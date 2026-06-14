package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/ratelimit"
)

// RateLimitAdminHandler exposes CRUD over the per-key override table.
// Composes the same way as WebhookAdminHandler so the routing wiring
// is mechanical.
type RateLimitAdminHandler struct {
	Store   ratelimit.OverrideStore
	Limiter *ratelimit.Limiter
	Sink    audit.Sink
	Logger  *zerolog.Logger
}

// NewRateLimitAdminHandler is a convenience constructor.
func NewRateLimitAdminHandler(s ratelimit.OverrideStore, l *ratelimit.Limiter, sink audit.Sink, logger *zerolog.Logger) *RateLimitAdminHandler {
	return &RateLimitAdminHandler{Store: s, Limiter: l, Sink: sink, Logger: logger}
}

type rateLimitOverrideRequest struct {
	Kind      string  `json:"kind"`
	Value     string  `json:"value"`
	RPS       float64 `json:"rps"`
	Burst     int     `json:"burst"`
	Reason    string  `json:"reason"`
	ExpiresAt *string `json:"expires_at"`
}

// Create handles POST /api/v1/admin/ratelimit/overrides.
func (h *RateLimitAdminHandler) Create(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil || h.Limiter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "rate-limit admin not configured")
		return
	}
	var req rateLimitOverrideRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "input_malformed", "invalid JSON body")
		return
	}
	if err := validateReason(req.Reason); err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_reason", "reason exceeds 256 chars or contains control characters")
		return
	}
	if req.Kind != ratelimit.KindSub && req.Kind != ratelimit.KindIP {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind", "kind must be 'sub' or 'ip'")
		return
	}
	if req.Value == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "value is required")
		return
	}
	// Negative RPS / burst is meaningless for a token bucket; zero is
	// allowed (block-on-burst-exhaustion / hard-stop semantics).
	if req.RPS < 0 || req.Burst < 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_quota", "rps and burst must be non-negative")
		return
	}

	o := ratelimit.Override{
		Kind:      req.Kind,
		Value:     req.Value,
		RPS:       req.RPS,
		Burst:     req.Burst,
		Reason:    req.Reason,
		CreatedAt: time.Now().UTC(),
	}
	if claims, ok := auth.ClaimsFromContext(r.Context()); ok && claims != nil {
		o.CreatedBy = claims.Sub
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		exp, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be RFC3339")
			return
		}
		o.ExpiresAt = &exp
	}

	if err := h.Store.Add(r.Context(), o); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if err := h.Limiter.Refresh(r.Context(), h.Store); err != nil && h.Logger != nil {
		h.Logger.Warn().Err(err).Msg("ratelimit refresh after add failed")
	}

	h.audit(r, "RATELIMIT_OVERRIDE_ADD", o, http.StatusCreated)
	writeJSON(w, http.StatusCreated, o)
}

// List handles GET /api/v1/admin/ratelimit/overrides.
func (h *RateLimitAdminHandler) List(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "rate-limit admin not configured")
		return
	}
	list, err := h.Store.List(r.Context())
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "list_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"overrides": list, "count": len(list)})
}

// Delete handles DELETE /api/v1/admin/ratelimit/overrides/{kind}/{value}.
func (h *RateLimitAdminHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.Store == nil || h.Limiter == nil {
		writeJSONError(w, http.StatusServiceUnavailable, "unavailable", "rate-limit admin not configured")
		return
	}
	kind := chi.URLParam(r, "kind")
	value := chi.URLParam(r, "value")
	if kind == "" || value == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_field", "kind and value are required")
		return
	}
	if kind != ratelimit.KindSub && kind != ratelimit.KindIP {
		writeJSONError(w, http.StatusBadRequest, "invalid_kind", "kind must be 'sub' or 'ip'")
		return
	}
	if err := h.Store.Remove(r.Context(), kind, value); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	if err := h.Limiter.Refresh(r.Context(), h.Store); err != nil && h.Logger != nil {
		h.Logger.Warn().Err(err).Msg("ratelimit refresh after delete failed")
	}

	h.audit(r, "RATELIMIT_OVERRIDE_REMOVE",
		ratelimit.Override{Kind: kind, Value: value},
		http.StatusNoContent)
	w.WriteHeader(http.StatusNoContent)
}

// audit emits an explicit event with the action verb the runbook can
// grep for. The HTTP-level audit middleware also records the request,
// but that one carries only the route pattern — operators want the
// override payload preserved verbatim.
func (h *RateLimitAdminHandler) audit(r *http.Request, action string, o ratelimit.Override, status int) {
	if h == nil || h.Sink == nil {
		return
	}
	actor, role := "anonymous", ""
	if c, ok := auth.ClaimsFromContext(r.Context()); ok && c != nil {
		actor = c.Sub
		role = c.Role
	}
	meta, _ := json.Marshal(o)
	ev := audit.Event{
		ID:         uuid.New(),
		Timestamp:  time.Now().UTC(),
		Actor:      actor,
		Role:       role,
		Action:     action,
		TargetType: "rate_limit_override",
		TargetID:   o.Kind + ":" + o.Value,
		Outcome:    audit.OutcomeSuccess,
		StatusCode: status,
		RequestID:  chimw.GetReqID(r.Context()),
		RemoteIP:   audit.ParseRemoteIP(r.RemoteAddr),
		Metadata:   meta,
	}
	if err := h.Sink.Record(r.Context(), ev); err != nil && h.Logger != nil {
		h.Logger.Warn().Err(err).Msg("ratelimit admin audit record failed")
	}
}
