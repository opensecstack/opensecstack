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
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/webhook"
)

// Sighting serves ingress endpoints for ecosystem platforms reporting that
// they observed an IOC, and egress lookup endpoints they use to check if an
// indicator they see is known.
type Sighting struct {
	logger     zerolog.Logger
	sightings  *store.SightingStore
	iocs       *store.IOCStore
	dispatcher *webhook.Dispatcher
	cache      *cache.Cache
}

// NewSighting creates a Sighting handler.
func NewSighting(logger zerolog.Logger, sightings *store.SightingStore, iocs *store.IOCStore, dispatcher *webhook.Dispatcher, c *cache.Cache) *Sighting {
	return &Sighting{
		logger:     logger.With().Str("handler", "sighting").Logger(),
		sightings:  sightings,
		iocs:       iocs,
		dispatcher: dispatcher,
		cache:      c,
	}
}

type sightingRequest struct {
	IOCID        string          `json:"ioc_id"`
	IOCType      string          `json:"type"`
	IOCValue     string          `json:"value"`
	Platform     string          `json:"platform"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Metadata     json.RawMessage `json:"metadata"`
}

// Record ingests a sighting. The caller either supplies an explicit ioc_id
// or a (type, value) pair — in the latter case we look up the canonical row
// so ecosystem clients can report "I saw evil.example on request /api/users"
// without needing to know the internal UUID.
func (h *Sighting) Record(w http.ResponseWriter, r *http.Request) {
	if h.sightings == nil || h.iocs == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	var req sightingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Platform == "" || req.ResourceType == "" || req.ResourceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "platform, resource_type, resource_id required"})
		return
	}
	if !validSightingPlatform(req.Platform) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "platform must be apiguard, irflow, or manual"})
		return
	}

	var iocID uuid.UUID
	var resolvedIOC *store.IOC
	if req.IOCID != "" {
		parsed, err := uuid.Parse(req.IOCID)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid ioc_id"})
			return
		}
		resolvedIOC, err = h.iocs.Get(r.Context(), parsed)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "ioc not found"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch ioc failed"})
			return
		}
		iocID = parsed
	} else {
		if req.IOCType == "" || req.IOCValue == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "either ioc_id or (type + value) required"})
			return
		}
		ioc, err := h.iocs.IOCByValue(r.Context(), req.IOCType, req.IOCValue)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "ioc not known to threatflow"})
				return
			}
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch ioc failed"})
			return
		}
		iocID = ioc.ID
		resolvedIOC = ioc
	}

	sight := &store.Sighting{
		IOCID:        iocID,
		Platform:     req.Platform,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		Metadata:     req.Metadata,
	}
	if err := h.sightings.Create(r.Context(), sight); err != nil {
		h.logger.Error().Err(err).Msg("create sighting")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "record failed"})
		return
	}

	// Fan out to subscribers so IRFlow can trigger a planbook the moment
	// APIGuard reports an IOC hit.
	if h.dispatcher != nil && resolvedIOC != nil {
		h.dispatcher.Emit(r.Context(), webhook.EventSightingReported, "threatflow", resolvedIOC.Confidence,
			map[string]any{
				"sighting_id":   sight.ID,
				"ioc_id":        resolvedIOC.ID,
				"ioc_type":      resolvedIOC.Type,
				"ioc_value":     resolvedIOC.Value,
				"ioc_confidence": resolvedIOC.Confidence,
				"platform":      sight.Platform,
				"resource_type": sight.ResourceType,
				"resource_id":   sight.ResourceID,
				"observed_at":   sight.ObservedAt,
			})
	}

	writeJSON(w, http.StatusCreated, sight)
}

// ForIOC returns every sighting attached to a given IOC.
func (h *Sighting) ForIOC(w http.ResponseWriter, r *http.Request) {
	if h.sightings == nil {
		writeJSON(w, http.StatusOK, map[string]any{"sightings": []any{}})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := h.sightings.ForIOC(r.Context(), id, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("list sightings")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sightings": items, "total": len(items)})
}

// Match is a cheap lookup for ecosystem services: "do you know about this
// indicator?" Returns 200 + IOC data if known, 404 otherwise. Reads are
// cached for 10 minutes in Redis (when configured) — APIGuard typically
// hammers this endpoint before every request.
// Query params: ?type=...&value=...
func (h *Sighting) Match(w http.ResponseWriter, r *http.Request) {
	if h.iocs == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown"})
		return
	}
	q := r.URL.Query()
	iocType := q.Get("type")
	value := q.Get("value")
	if iocType == "" || value == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type and value required"})
		return
	}

	cacheKey := cache.IOCMatchKey(iocType, value)
	if h.cache != nil {
		var cached store.IOC
		if err := h.cache.Get(r.Context(), cacheKey, &cached); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"match": true, "ioc": &cached, "cached": true})
			return
		}
	}

	ioc, err := h.iocs.IOCByValue(r.Context(), iocType, value)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]any{"match": false})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return
	}
	if h.cache != nil {
		h.cache.Set(r.Context(), cacheKey, ioc)
	}
	writeJSON(w, http.StatusOK, map[string]any{"match": true, "ioc": ioc, "cached": false})
}

func validSightingPlatform(p string) bool {
	switch p {
	case "apiguard", "irflow", "manual":
		return true
	}
	return false
}
