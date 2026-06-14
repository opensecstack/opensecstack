package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/correlate"
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/webhook"
)

// IOC handles threat intelligence indicator endpoints backed by the iocs table.
type IOC struct {
	logger     zerolog.Logger
	store      *store.IOCStore
	citadel    *citadel.Client
	correlator *correlate.Engine
	dispatcher *webhook.Dispatcher
	cache      *cache.Cache
}

// NewIOC creates a new IOC handler. Any optional dependency may be nil —
// the related feature is then disabled.
func NewIOC(logger zerolog.Logger, s *store.IOCStore, citadelC *citadel.Client, correlator *correlate.Engine, dispatcher *webhook.Dispatcher, c *cache.Cache) *IOC {
	return &IOC{
		logger:     logger.With().Str("handler", "ioc").Logger(),
		store:      s,
		citadel:    citadelC,
		correlator: correlator,
		dispatcher: dispatcher,
		cache:      c,
	}
}

type ingestRequest struct {
	StixID      string   `json:"stix_id"`
	Type        string   `json:"type"`
	Value       string   `json:"value"`
	Pattern     string   `json:"pattern"`
	Source      string   `json:"source"`
	Confidence  int      `json:"confidence"`
	Description string   `json:"description"`
	Tags        []string `json:"tags"`
	CVE         string   `json:"cve"`
}

// List returns IOCs with optional filters (?type, ?value, ?tag, ?min_confidence, ?limit, ?offset).
func (h *IOC) List(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"items": []any{}, "total": 0})
		return
	}
	q := r.URL.Query()
	filter := store.IOCFilter{
		Type:   q.Get("type"),
		Value:  q.Get("value"),
		Tag:    q.Get("tag"),
		Search: q.Get("q"),
	}
	if v := q.Get("min_confidence"); v != "" {
		filter.MinConf, _ = strconv.Atoi(v)
	}
	if v := q.Get("limit"); v != "" {
		filter.Limit, _ = strconv.Atoi(v)
	}
	if v := q.Get("offset"); v != "" {
		filter.Offset, _ = strconv.Atoi(v)
	}

	items, total, err := h.store.List(r.Context(), filter)
	if err != nil {
		h.logger.Error().Err(err).Msg("list iocs")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// Ingest upserts an IOC by pattern_hash. Returns 201 on create.
func (h *IOC) Ingest(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if h.store == nil {
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		return
	}
	if req.Type == "" || req.Value == "" || req.Pattern == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type, value, and pattern are required"})
		return
	}

	// MARSHAL gate — governance check before mutation.
	if h.citadel != nil && h.citadel.Enabled() {
		desc := "direct IOC ingest: " + req.Type + "=" + req.Value
		decision, err := h.citadel.Evaluate(r.Context(), citadel.ActionIOCIngest, desc, "", "operator")
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

	ioc := &store.IOC{
		StixID:      req.StixID,
		Type:        req.Type,
		Value:       req.Value,
		Pattern:     req.Pattern,
		Source:      req.Source,
		Confidence:  req.Confidence,
		Description: req.Description,
		Tags:        req.Tags,
		CVE:         req.CVE,
	}
	if err := h.store.Upsert(r.Context(), ioc); err != nil {
		h.logger.Error().Err(err).Msg("upsert ioc")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "ingest failed"})
		return
	}

	// Invalidate the match cache so subsequent /match reads see the new row.
	if h.cache != nil {
		h.cache.Invalidate(r.Context(), cache.IOCMatchKey(ioc.Type, ioc.Value))
	}

	// Correlation — enrich with cross-IOC relationships.
	if h.correlator != nil {
		if _, err := h.correlator.CorrelateIOC(r.Context(), ioc); err != nil {
			h.logger.Warn().Err(err).Msg("correlate")
		}
	}

	// WORM audit trail — fire-and-forget, never blocks the response.
	if h.citadel != nil {
		h.citadel.EmitAsync("threatflow", citadel.ActionIOCIngest, map[string]any{
			"ioc_id":     ioc.ID,
			"type":       ioc.Type,
			"value":      ioc.Value,
			"confidence": ioc.Confidence,
			"source":     ioc.Source,
		})
	}

	// Webhook fan-out to ecosystem subscribers.
	if h.dispatcher != nil {
		h.dispatcher.Emit(r.Context(), webhook.EventIOCCreated, "threatflow", ioc.Confidence, map[string]any{
			"ioc_id":     ioc.ID,
			"type":       ioc.Type,
			"value":      ioc.Value,
			"pattern":    ioc.Pattern,
			"confidence": ioc.Confidence,
			"tags":       ioc.Tags,
			"source":     ioc.Source,
		})
	}

	writeJSON(w, http.StatusCreated, ioc)
}

// Get returns a single IOC by ID.
func (h *IOC) Get(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "ioc not found"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	ioc, err := h.store.Get(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "ioc not found"})
			return
		}
		h.logger.Error().Err(err).Msg("get ioc")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, ioc)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
