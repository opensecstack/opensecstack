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
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/stix"
	"github.com/opensecstack/threatflow/internal/webhook"
)

// STIX handles STIX 2.1 bundle endpoints backed by the stix_bundles /
// stix_objects tables and the internal/stix importer.
type STIX struct {
	logger     zerolog.Logger
	stix       *store.StixStore
	importer   *stix.Importer
	citadel    *citadel.Client
	dispatcher *webhook.Dispatcher
}

// NewSTIX creates a new STIX handler. Pass nil stores to keep scaffold
// responses for environments without a database connection. citadelC and
// dispatcher may be nil — related features are then disabled.
func NewSTIX(logger zerolog.Logger, stixStore *store.StixStore, importer *stix.Importer, citadelC *citadel.Client, dispatcher *webhook.Dispatcher) *STIX {
	return &STIX{
		logger:     logger.With().Str("handler", "stix").Logger(),
		stix:       stixStore,
		importer:   importer,
		citadel:    citadelC,
		dispatcher: dispatcher,
	}
}

// ListBundles returns persisted STIX bundles (?direction=import|export, ?limit, ?offset).
func (h *STIX) ListBundles(w http.ResponseWriter, r *http.Request) {
	if h.stix == nil {
		writeJSON(w, http.StatusOK, map[string]any{"bundles": []any{}, "total": 0})
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))

	bundles, total, err := h.stix.ListBundles(r.Context(), q.Get("direction"), limit, offset)
	if err != nil {
		h.logger.Error().Err(err).Msg("list bundles")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": bundles, "total": total})
}

// IngestBundle parses, validates, and persists a STIX 2.1 bundle. The request
// body is the bundle JSON verbatim; ?source and ?feed_id are optional.
func (h *STIX) IngestBundle(w http.ResponseWriter, r *http.Request) {
	payload, err := io.ReadAll(io.LimitReader(r.Body, 32<<20)) // 32 MiB cap
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

	q := r.URL.Query()
	source := q.Get("source")
	if source == "" {
		source = "api"
	}
	var feedID *uuid.UUID
	if v := q.Get("feed_id"); v != "" {
		parsed, perr := uuid.Parse(v)
		if perr != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid feed_id"})
			return
		}
		feedID = &parsed
	}

	// MARSHAL gate — bundle import is a privileged mutation.
	if h.citadel != nil && h.citadel.Enabled() {
		decision, err := h.citadel.Evaluate(r.Context(), citadel.ActionBundleImport,
			"stix bundle import from "+source, "", "operator")
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

	res, err := h.importer.Import(r.Context(), payload, source, feedID)
	if err != nil {
		if errors.Is(err, stix.ErrInvalidBundle) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		h.logger.Error().Err(err).Msg("import bundle")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "import failed"})
		return
	}

	if h.citadel != nil {
		h.citadel.EmitAsync("threatflow", citadel.ActionBundleImport, map[string]any{
			"bundle_id":       res.BundleID,
			"objects_stored":  res.ObjectsStored,
			"iocs_upserted":   res.IOCsUpserted,
			"ttps_tagged":     res.TTPsTagged,
			"source":          source,
		})
	}

	// Fan out a bundle.imported event so subscribers can pull the new IOCs.
	// Confidence = 100 so the event is never filtered by min_confidence.
	if h.dispatcher != nil {
		h.dispatcher.Emit(r.Context(), webhook.EventBundleImported, "threatflow", 100, map[string]any{
			"bundle_id":      res.BundleID,
			"iocs_upserted":  res.IOCsUpserted,
			"objects_stored": res.ObjectsStored,
			"ttps_tagged":    res.TTPsTagged,
			"correlations":   res.Correlations,
			"source":         source,
		})
	}

	writeJSON(w, http.StatusCreated, res)
}

// GetBundle returns a bundle envelope plus all objects it contains.
func (h *STIX) GetBundle(w http.ResponseWriter, r *http.Request) {
	if h.stix == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "bundle not found"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	b, err := h.stix.GetBundle(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "bundle not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	objs, err := h.stix.ObjectsForBundle(r.Context(), b.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "objects fetch failed"})
		return
	}
	rawObjs := make([]json.RawMessage, 0, len(objs))
	for _, o := range objs {
		rawObjs = append(rawObjs, o.Content)
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundle": b, "objects": rawObjs})
}
