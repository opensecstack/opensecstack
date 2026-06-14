package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/api/middleware"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/db/store"
)

// Auth handles the token-exchange endpoint and API key administration.
type Auth struct {
	logger  zerolog.Logger
	service *auth.Service
	keys    *store.APIKeyStore
}

// NewAuth creates an Auth handler.
func NewAuth(logger zerolog.Logger, service *auth.Service, keys *store.APIKeyStore) *Auth {
	return &Auth{
		logger:  logger.With().Str("handler", "auth").Logger(),
		service: service,
		keys:    keys,
	}
}

type tokenRequest struct {
	APIKey string `json:"api_key"`
}

// Token exchanges an API key for a short-lived JWT.
func (h *Auth) Token(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "auth disabled"})
		return
	}
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	id, err := h.service.AuthenticateAPIKey(r.Context(), req.APIKey)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid api key"})
		return
	}
	token, exp, err := h.service.IssueToken(id)
	if err != nil {
		h.logger.Error().Err(err).Msg("issue token")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token issue failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_at":   exp,
		"role":         id.Role,
	})
}

type apiKeyRequest struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	ExpiresIn int    `json:"expires_in_days"`
}

// CreateKey mints a new API key, returns the plaintext exactly once.
func (h *Auth) CreateKey(w http.ResponseWriter, r *http.Request) {
	if h.keys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	var req apiKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if req.Name == "" || req.Role == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and role are required"})
		return
	}
	if !validRole(req.Role) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role must be one of viewer, analyst, operator, admin"})
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key generation failed"})
		return
	}
	plaintext := "tf_" + hex.EncodeToString(buf)

	key := &store.APIKey{
		Name:    req.Name,
		KeyHash: store.HashAPIKey(plaintext),
		Role:    req.Role,
		Enabled: true,
	}
	if err := h.keys.Create(r.Context(), key); err != nil {
		h.logger.Error().Err(err).Msg("create api key")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "create failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"api_key": key,
		"secret":  plaintext,
		"warning": "secret is shown once and cannot be retrieved later",
	})
}

// List returns every API key row (hashes only, not the plaintext).
func (h *Auth) ListKeys(w http.ResponseWriter, r *http.Request) {
	if h.keys == nil {
		writeJSON(w, http.StatusOK, map[string]any{"keys": []any{}})
		return
	}
	list, err := h.keys.List(r.Context())
	if err != nil {
		h.logger.Error().Err(err).Msg("list api keys")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"keys": list})
}

// RevokeKey disables (soft-delete) an API key.
func (h *Auth) RevokeKey(w http.ResponseWriter, r *http.Request) {
	if h.keys == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "persistence disabled"})
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return
	}
	if err := h.keys.Revoke(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "api key not found"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "revoke failed"})
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// Me returns the identity inferred from the caller's Bearer token.
func (h *Auth) Me(w http.ResponseWriter, r *http.Request) {
	id := middleware.Identity(r)
	if id == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"subject": id.Subject,
		"role":    id.Role,
		"source":  id.Source,
	})
}

func validRole(r string) bool {
	switch auth.Role(r) {
	case auth.RoleViewer, auth.RoleAnalyst, auth.RoleOperator, auth.RoleAdmin:
		return true
	}
	return false
}
