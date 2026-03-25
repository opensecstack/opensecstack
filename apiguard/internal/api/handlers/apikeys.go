package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/db"
)

// APIKeys handles API key management endpoints.
type APIKeys struct {
	logger zerolog.Logger
	db     *db.DB
}

// NewAPIKeys creates a new APIKeys handler.
func NewAPIKeys(logger zerolog.Logger, database *db.DB) *APIKeys {
	return &APIKeys{
		logger: logger.With().Str("handler", "apikeys").Logger(),
		db:     database,
	}
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

	// Use a fixed actor identifier; in a multi-user system this would come
	// from the JWT claims in the request context.
	createdBy := "api-client"

	key, plaintext, err := h.db.CreateAPIKey(r.Context(), req.Label, createdBy)
	if err != nil {
		h.logger.Error().Err(err).Msg("creating api key")
		writeError(w, http.StatusInternalServerError, "failed to create api key")
		return
	}

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

	// Use a fixed actor identifier; in a multi-user system this would come
	// from the JWT claims in the request context.
	revokedBy := "api-client"

	if err := h.db.RevokeAPIKey(r.Context(), id, revokedBy); err != nil {
		h.logger.Error().Err(err).Str("id", idStr).Msg("revoking api key")
		writeError(w, http.StatusNotFound, "api key not found or already revoked")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
