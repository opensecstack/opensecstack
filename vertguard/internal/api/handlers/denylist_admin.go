package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/auth/denylist"
)

// DenylistAdminHandler exposes operator-facing CRUD on the JWT denylist.
// Mutations refresh the in-memory cache so revocations take effect
// within milliseconds rather than waiting for the next ticker.
type DenylistAdminHandler struct {
	Store     denylist.Store
	Cache     *denylist.Cache
	AuditSink audit.Sink
	Logger    *zerolog.Logger
}

// NewDenylistAdminHandler is a convenience constructor.
func NewDenylistAdminHandler(s denylist.Store, c *denylist.Cache, sink audit.Sink, logger *zerolog.Logger) *DenylistAdminHandler {
	return &DenylistAdminHandler{Store: s, Cache: c, AuditSink: sink, Logger: logger}
}

type denylistRequest struct {
	Kind      string  `json:"kind"`
	Value     string  `json:"value"`
	Reason    string  `json:"reason,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
}

// Create handles POST /api/v1/admin/denylist.
func (h *DenylistAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "denylist store not configured")
		return
	}
	var req denylistRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if err := validateReason(req.Reason); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_reason", "reason exceeds 256 chars or contains control characters")
		return
	}
	if req.Kind != denylist.KindJTI && req.Kind != denylist.KindSub {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind", "kind must be 'jti' or 'sub'")
		return
	}
	if req.Value == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "value is required")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be RFC3339")
			return
		}
		expiresAt = &t
	}

	revokedBy := "unknown"
	role := ""
	if c, ok := auth.ClaimsFromContext(r.Context()); ok && c != nil {
		revokedBy = c.Sub
		role = c.Role
	}

	entry := denylist.Entry{
		ID:        uuid.New(),
		Kind:      req.Kind,
		Value:     req.Value,
		Reason:    req.Reason,
		RevokedBy: revokedBy,
		RevokedAt: time.Now().UTC(),
		ExpiresAt: expiresAt,
	}
	if err := h.Store.Add(r.Context(), entry); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}

	h.refreshCache(r.Context())
	h.emitAudit(r, "REVOKE_TOKEN", revokedBy, role, http.StatusCreated, entry)
	writeJSON(w, http.StatusCreated, entry)
}

// List handles GET /api/v1/admin/denylist.
func (h *DenylistAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "denylist store not configured")
		return
	}
	entries, err := h.Store.List(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

// Delete handles DELETE /api/v1/admin/denylist/{kind}/{value}.
func (h *DenylistAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "denylist store not configured")
		return
	}
	kind := chi.URLParam(r, "kind")
	value := chi.URLParam(r, "value")
	if kind != denylist.KindJTI && kind != denylist.KindSub {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind", "kind must be 'jti' or 'sub'")
		return
	}
	if value == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_value", "value is required")
		return
	}

	if err := h.Store.Remove(r.Context(), kind, value); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}

	revokedBy := "unknown"
	role := ""
	if c, ok := auth.ClaimsFromContext(r.Context()); ok && c != nil {
		revokedBy = c.Sub
		role = c.Role
	}
	h.refreshCache(r.Context())
	h.emitAudit(r, "UNREVOKE_TOKEN", revokedBy, role, http.StatusNoContent, denylist.Entry{
		Kind: kind, Value: value, RevokedBy: revokedBy,
	})
	w.WriteHeader(http.StatusNoContent)
}

// refreshCache best-effort triggers a snapshot reload. Failure here
// is logged but doesn't fail the request — the row is already in the
// store and the periodic ticker will pick it up within 30s.
func (h *DenylistAdminHandler) refreshCache(ctx context.Context) {
	if h.Cache == nil {
		return
	}
	if err := h.Cache.Refresh(ctx); err != nil && h.Logger != nil {
		h.Logger.Warn().Err(err).Msg("denylist cache refresh failed after admin mutation")
	}
}

func (h *DenylistAdminHandler) emitAudit(r *http.Request, action, actor, role string, status int, entry denylist.Entry) {
	if h.AuditSink == nil {
		return
	}
	meta, _ := json.Marshal(entry)
	ev := audit.Event{
		ID:         uuid.New(),
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Role:       role,
		Action:     action,
		TargetType: "token_denylist",
		TargetID:   entry.Kind + ":" + entry.Value,
		Outcome:    audit.OutcomeSuccess,
		StatusCode: status,
		RequestID:  chimw.GetReqID(r.Context()),
		RemoteIP:   audit.ParseRemoteIP(r.RemoteAddr),
		Metadata:   meta,
	}
	if err := h.AuditSink.Record(r.Context(), ev); err != nil && h.Logger != nil {
		h.Logger.Warn().Err(err).Str("event_id", ev.ID.String()).Msg("denylist audit record failed")
	}
}
