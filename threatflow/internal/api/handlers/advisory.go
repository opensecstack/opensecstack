package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/csaf"
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/webhook"
)

// Advisory handles CSAF 2.0 advisory ingestion (POST /api/v1/advisories,
// pushed by OpenCSIRT's PushAdvisory — see
// opencsirt/internal/integrations/threatflow.go) and the read-side
// advisories/vulnerabilities endpoints backed by migration 009's tables.
type Advisory struct {
	logger     zerolog.Logger
	store      *store.AdvisoryStore
	importer   *csaf.Importer
	citadel    *citadel.Client
	dispatcher *webhook.Dispatcher
}

// NewAdvisory creates a new Advisory handler. Pass nil store/importer to
// keep scaffold responses for environments without a database connection.
// citadelC and dispatcher may be nil — related features are then disabled.
func NewAdvisory(logger zerolog.Logger, advisoryStore *store.AdvisoryStore, importer *csaf.Importer, citadelC *citadel.Client, dispatcher *webhook.Dispatcher) *Advisory {
	return &Advisory{
		logger:     logger.With().Str("handler", "advisory").Logger(),
		store:      advisoryStore,
		importer:   importer,
		citadel:    citadelC,
		dispatcher: dispatcher,
	}
}

// List returns advisories ordered by current_release_date DESC (?limit, ?offset).
func (h *Advisory) List(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "total": 0})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	items, total, err := h.store.List(r.Context(), limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("list advisories")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// Get returns a single advisory with its vulnerabilities/remediations/products.
func (h *Advisory) Get(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "advisory not found"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	a, err := h.store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "advisory not found"})
			return
		}
		h.logger.Error().Err(err).Msg("get advisory")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// Ingest parses, validates, and persists a CSAF 2.0 advisory document. The
// request body is the CSAF document JSON verbatim, matching exactly what
// opencsirt/internal/integrations/threatflow.go's PushAdvisory sends
// (`json.Marshal(csafDoc)` of the full document, no envelope). ?source is
// optional and defaults to "opencsirt" — the only producer of this payload
// today.
func (h *Advisory) Ingest(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(r.Body, 32<<20)) // 32 MiB cap, matches STIX.IngestBundle
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return
	}
	if !json.Valid(payload) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if h.importer == nil {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted (persistence disabled)"})
		return
	}

	source := r.URL.Query().Get("source")
	if source == "" {
		source = "opencsirt"
	}

	// MARSHAL gate — advisory ingest is a privileged mutation, mirroring
	// STIX.IngestBundle's ActionBundleImport gate.
	if h.citadel != nil && h.citadel.Enabled() {
		actorUserID, actorRole, actorToken := actorFromRequest(r)
		decision, err := h.citadel.Evaluate(r.Context(), citadel.ActionAdvisoryIngest,
			"CSAF advisory ingest from "+source, actorUserID, "", actorRole, actorToken)
		if err != nil {
			h.logger.Error().Err(err).Msg("marshal evaluate")
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "governance check failed"})
			return
		}
		if !decision.Allowed() {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":   "refused by citadel",
				"outcome": decision.Outcome,
				"reasons": decision.Reasons,
			})
			return
		}
	}

	res, err := h.importer.Ingest(r.Context(), payload, source)
	if err != nil {
		if errors.Is(err, csaf.ErrInvalidCSAF) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h.logger.Error().Err(err).Msg("ingest advisory")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ingest failed"})
		return
	}

	status := http.StatusOK
	switch res.Action {
	case store.AdvisoryCreated:
		status = http.StatusCreated
	case store.AdvisoryStale:
		// The request was valid CSAF but describes a revision older than
		// what ThreatFlow already has for this tracking.id — logged for
		// audit (see AdvisoryStore.UpsertRevision), current state
		// untouched. 409 tells the caller their write did not apply.
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":       "stale revision: a newer revision is already stored",
			"tracking_id": res.TrackingID,
			"revision":    res.Revision,
		})
		return
	}

	// WORM audit trail — fire-and-forget, never blocks the response. Skipped
	// for duplicate/stale outcomes: nothing changed, so there is nothing new
	// to attest (the original ingest that created the current state already
	// emitted its own WORM entry).
	if h.citadel != nil && (res.Action == store.AdvisoryCreated || res.Action == store.AdvisoryUpdated) {
		h.citadel.EmitAsync("threatflow", citadel.ActionAdvisoryIngest, map[string]any{
			"advisory_id":            res.AdvisoryID,
			"tracking_id":            res.TrackingID,
			"revision":               res.Revision,
			"action":                 res.Action,
			"vulnerabilities_mapped": res.VulnerabilitiesMapped,
			"products_mapped":        res.ProductsMapped,
			"source":                 source,
		})
	}

	// Webhook fan-out — same skip rule as WORM above.
	if h.dispatcher != nil {
		eventType := webhook.EventAdvisoryIngested
		if res.Action == store.AdvisoryUpdated {
			eventType = webhook.EventAdvisoryUpdated
		}
		if res.Action == store.AdvisoryCreated || res.Action == store.AdvisoryUpdated {
			h.dispatcher.Emit(r.Context(), eventType, "threatflow", 100, map[string]any{
				"advisory_id":            res.AdvisoryID,
				"tracking_id":            res.TrackingID,
				"revision":               res.Revision,
				"vulnerabilities_mapped": res.VulnerabilitiesMapped,
				"products_mapped":        res.ProductsMapped,
				"source":                 source,
			})
		}
	}

	writeJSON(w, status, res)
}
