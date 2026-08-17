package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/opensecstack/vertguard/internal/threatfeed/webhook"
	vgwebhook "github.com/opensecstack/vertguard/internal/webhook"
)

// WebhookAdminHandler manages ThreatFlow subscriber registration.
type WebhookAdminHandler struct {
	Pub *webhook.Publisher
}

// NewWebhookAdminHandler is a convenience constructor.
func NewWebhookAdminHandler(p *webhook.Publisher) *WebhookAdminHandler {
	return &WebhookAdminHandler{Pub: p}
}

type subscriberRequest struct {
	URL        string   `json:"url"`
	HMACSecret string   `json:"hmac_secret"`
	Active     *bool    `json:"active"`
	Filters    []string `json:"filters"`
}

// Create handles POST /api/v1/webhooks/subscribers.
func (h *WebhookAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req subscriberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.URL == "" || req.HMACSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "url and hmac_secret are required")
		return
	}
	active := true
	if req.Active != nil {
		active = *req.Active
	}
	s := h.Pub.Add(webhook.Subscriber{
		URL:        req.URL,
		HMACSecret: req.HMACSecret,
		Active:     active,
		Filters:    req.Filters,
	})
	s.HMACSecret = ""
	writeJSON(w, http.StatusCreated, s)
}

// List handles GET /api/v1/webhooks/subscribers.
func (h *WebhookAdminHandler) List(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, h.Pub.List())
}

// Delete handles DELETE /api/v1/webhooks/subscribers/{id}.
func (h *WebhookAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_id", "id is required")
		return
	}
	if !h.Pub.Remove(id) {
		writeJSONError(w, http.StatusNotFound, "not_found", "subscriber not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ─── VG-015: persistent outbound webhook subscribers ──────────────────

// WebhookSubscribersHandler is the VG-015 admin surface for the
// 3-slot-rotating, DB-backed subscriber registry. Distinct from the
// legacy in-memory WebhookAdminHandler above — both can coexist on
// the router (different paths: /webhooks vs /webhook).
type WebhookSubscribersHandler struct {
	Store      *vgwebhook.Store
	Dispatcher *vgwebhook.Dispatcher
}

// NewWebhookSubscribersHandler is a convenience constructor.
func NewWebhookSubscribersHandler(s *vgwebhook.Store, d *vgwebhook.Dispatcher) *WebhookSubscribersHandler {
	return &WebhookSubscribersHandler{Store: s, Dispatcher: d}
}

type webhookSubscriberCreateRequest struct {
	URL        string   `json:"url"`
	EventTypes []string `json:"event_types"`
	HMACSecret string   `json:"hmac_secret"` // lands in primary slot
	KeyID      string   `json:"key_id"`
	Tenant     string   `json:"tenant"`
	Enabled    *bool    `json:"enabled"`
}

type webhookSubscriberRotateRequest struct {
	NewSecret string `json:"new_secret"`
	NewKeyID  string `json:"new_key_id"`
}

// CreateV2 handles POST /api/v1/webhook/subscribers.
func (h *WebhookSubscribersHandler) CreateV2(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "webhook subscribers store not configured")
		return
	}
	var req webhookSubscriberCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.URL == "" || req.HMACSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "url and hmac_secret are required")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	sub := &vgwebhook.Subscriber{
		Tenant:      req.Tenant,
		URL:         req.URL,
		EventTypes:  req.EventTypes,
		HMACSecrets: []string{req.HMACSecret, "", ""},
		KeyIDs:      []string{req.KeyID, "", ""},
		Enabled:     enabled,
	}
	if err := h.Store.Upsert(r.Context(), sub); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, sub.ToPublic())
}

// ListV2 handles GET /api/v1/webhook/subscribers.
func (h *WebhookSubscribersHandler) ListV2(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "webhook subscribers store not configured")
		return
	}
	subs, err := h.Store.List(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	out := make([]vgwebhook.PublicView, 0, len(subs))
	for i := range subs {
		out = append(out, subs[i].ToPublic())
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscribers": out, "count": len(out)})
}

// DeleteV2 handles DELETE /api/v1/webhook/subscribers/{id}.
func (h *WebhookSubscribersHandler) DeleteV2(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "webhook subscribers store not configured")
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "id must be a UUID")
		return
	}
	if err := h.Store.Delete(r.Context(), id); err != nil {
		if errors.Is(err, vgwebhook.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "subscriber not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Rotate handles POST /api/v1/webhook/subscribers/{id}/rotate.
func (h *WebhookSubscribersHandler) Rotate(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "webhook subscribers store not configured")
		return
	}
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "id must be a UUID")
		return
	}
	var req webhookSubscriberRotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if req.NewSecret == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "new_secret is required")
		return
	}
	sub, err := h.Store.Rotate(r.Context(), id, req.NewSecret, req.NewKeyID)
	if err != nil {
		if errors.Is(err, vgwebhook.ErrNotFound) {
			writeJSONError(w, http.StatusNotFound, "not_found", "subscriber not found")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "rotate_failed", err.Error())
		return
	}
	if h.Dispatcher != nil {
		h.Dispatcher.RecordRotation()
	}
	writeJSON(w, http.StatusOK, sub.ToPublic())
}
