package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/citadel"
	"github.com/opensecstack/apiguard/internal/db"
)

// APIKeys handles API key management endpoints.
type APIKeys struct {
	logger  zerolog.Logger
	db      *db.DB
	citadel *citadel.Client
}

// NewAPIKeys creates a new APIKeys handler.
func NewAPIKeys(logger zerolog.Logger, database *db.DB, citadelClient *citadel.Client) *APIKeys {
	return &APIKeys{
		logger:  logger.With().Str("handler", "apikeys").Logger(),
		db:      database,
		citadel: citadelClient,
	}
}

// auditLog appends an audit entry and forwards it to CITADEL (fire-and-forget).
func (h *APIKeys) auditLog(ctx context.Context, action db.AuditAction, resourceType string, resourceID *uuid.UUID, ip, ua, actor string) {
	entry := &db.AuditLog{
		ActorID:      actor,
		ActorType:    "user",
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
	}
	if ip != "" {
		entry.IPAddress = sql.NullString{String: ip, Valid: true}
	}
	if ua != "" {
		entry.UserAgent = sql.NullString{String: ua, Valid: true}
	}
	if err := h.db.AppendAuditLog(ctx, entry, h.citadel); err != nil {
		h.logger.Warn().Err(err).Str("action", string(action)).Msg("audit log write failed")
	}
}

// actorFromContext extracts the subject claim from the JWT in context,
// falling back to "api-client" if claims are absent (e.g. during tests).
func actorFromContext(ctx context.Context) string {
	if claims, ok := middleware.ClaimsFromContext(ctx); ok && claims.Sub != "" {
		return claims.Sub
	}
	return "api-client"
}

// List handles GET /api/v1/api-keys.
// Returns a JSON array of all active API keys (key_hash is never returned).
func (h *APIKeys) List(w http.ResponseWriter, r *http.Request) {
	keys, err := h.db.ListAPIKeys(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("listing api keys")
		writeError(w, http.StatusInternalServerError, "failed to list api keys")
		return
	}

	writeJSON(w, http.StatusOK, keys)
}

// createAPIKeyRequest is the expected body for POST /api/v1/api-keys.
type createAPIKeyRequest struct {
	Label string `json:"label"`
}

// createAPIKeyResponse wraps the newly created key with the one-time plaintext.
type createAPIKeyResponse struct {
	*db.APIKey
	Key     string `json:"key"`
	Warning string `json:"warning"`
}

// Create handles POST /api/v1/api-keys.
// Body: {"label": "..."}
// Returns 201 with the APIKey object, the plaintext key, and a warning.
func (h *APIKeys) Create(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	createdBy := actorFromContext(r.Context())

	key, plaintext, err := h.db.CreateAPIKey(r.Context(), req.Label, createdBy)
	if err != nil {
		h.logger.Error().Err(err).Msg("creating api key")
		writeError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}

	h.auditLog(r.Context(), db.AuditActionAPIKeyCreated, "api_keys", &key.ID,
		r.RemoteAddr, r.UserAgent(), createdBy)

	writeJSON(w, http.StatusCreated, createAPIKeyResponse{
		APIKey:  key,
		Key:     plaintext,
		Warning: "Store this key securely — it will not be shown again.",
	})
}

// Revoke handles DELETE /api/v1/api-keys/{id}.
// Returns 204 No Content on success.
func (h *APIKeys) Revoke(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid api key id")
		return
	}

	revokedBy := actorFromContext(r.Context())

	if err := h.db.RevokeAPIKey(r.Context(), id, revokedBy); err != nil {
		h.logger.Error().Err(err).Str("id", idStr).Msg("revoking api key")
		writeError(w, http.StatusNotFound, "api key not found or already revoked")
		return
	}

	h.auditLog(r.Context(), db.AuditActionAPIKeyRevoked, "api_keys", &id,
		r.RemoteAddr, r.UserAgent(), revokedBy)

	w.WriteHeader(http.StatusNoContent)
}
