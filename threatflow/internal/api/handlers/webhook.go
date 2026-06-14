package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

// Webhook serves subscriber CRUD and delivery history endpoints.
type Webhook struct {
	logger zerolog.Logger
	store  *store.WebhookStore
}

// NewWebhook creates a Webhook handler.
func NewWebhook(logger zerolog.Logger, s *store.WebhookStore) *Webhook {
	return &Webhook{
		logger: logger.With().Str("handler", "webhook").Logger(),
		store:  s,
	}
}

type subscriberRequest struct {
	Name          string   `json:"name"`
	Platform      string   `json:"platform"`
	URL           string   `json:"url"`
	Secret        string   `json:"secret"`
	EventTypes    []string `json:"event_types"`
	MinConfidence int      `json:"min_confidence"`
	Enabled       *bool    `json:"enabled"`
}

// List returns every subscriber.
func (h *Webhook) List(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"subscribers": []any{}})
		return
	}
	enabledOnly := r.URL.Query().Get("enabled") == "true"
	subs, err := h.store.ListSubscribers(r.Context(), enabledOnly)
	if err != nil {
		h.logger.Error().Err(err).Msg("list subscribers")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscribers": subs})
}

// Create registers a new webhook subscriber. If the request does not supply a
// secret, a fresh 32-byte hex secret is generated and returned once in the
// response — callers must capture it; the GET endpoints never echo it back.
func (h *Webhook) Create(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	var req subscriberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" || req.URL == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and url are required"})
		return
	}
	if !validPlatform(req.Platform) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "platform must be one of apiguard, irflow, nis2compass, external"})
		return
	}

	secret := req.Secret
	generated := false
	if secret == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret generation failed"})
			return
		}
		secret = hex.EncodeToString(buf)
		generated = true
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	sub := &store.WebhookSubscriber{
		Name:          req.Name,
		Platform:      req.Platform,
		URL:           req.URL,
		Secret:        secret,
		EventTypes:    req.EventTypes,
		MinConfidence: req.MinConfidence,
		Enabled:       enabled,
	}
	if err := h.store.CreateSubscriber(r.Context(), sub); err != nil {
		h.logger.Error().Err(err).Msg("create subscriber")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}

	resp := map[string]any{
		"subscriber": sub,
	}
	if generated {
		resp["secret"] = secret
		resp["warning"] = "secret is shown once and cannot be retrieved later"
	}
	writeJSON(w, http.StatusCreated, resp)
}

// Get fetches a subscriber by ID (secret is NOT returned).
func (h *Webhook) Get(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	sub, err := h.store.GetSubscriber(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscriber not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, sub)
}

// Patch toggles the enabled flag.
func (h *Webhook) Patch(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must contain enabled boolean"})
		return
	}
	if err := h.store.SetEnabled(r.Context(), id, *body.Enabled); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscriber not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "update failed"})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// Delete removes a subscriber.
func (h *Webhook) Delete(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := h.store.DeleteSubscriber(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "subscriber not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// Deliveries returns the recent delivery attempts for a subscriber.
func (h *Webhook) Deliveries(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"deliveries": []any{}})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	deliveries, err := h.store.RecentDeliveries(r.Context(), id, limit)
	if err != nil {
		h.logger.Error().Err(err).Msg("recent deliveries")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "fetch failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deliveries": deliveries})
}

// Stats returns aggregate delivery status counts.
func (h *Webhook) Stats(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		writeJSON(w, http.StatusOK, map[string]any{"stats": map[string]int{}})
		return
	}
	stats, err := h.store.DeliveryStats(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("delivery stats")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "stats failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"stats": stats})
}

func validPlatform(p string) bool {
	switch p {
	case "apiguard", "irflow", "nis2compass", "external":
		return true
	}
	return false
}
