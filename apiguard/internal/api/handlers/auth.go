package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/config"
)

// Auth handles authentication endpoints.
type Auth struct {
	logger zerolog.Logger
	cfg    *config.Config
}

// NewAuth creates a new Auth handler.
func NewAuth(logger zerolog.Logger, cfg *config.Config) *Auth {
	return &Auth{
		logger: logger.With().Str("handler", "auth").Logger(),
		cfg:    cfg,
	}
}

type tokenRequest struct {
	APIKey string `json:"api_key"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresIn int64  `json:"expires_in"` // seconds
	TokenType string `json:"token_type"`
}

// Token handles POST /api/v1/auth/token.
// It accepts an API key and returns a signed JWT for use on protected endpoints.
func (a *Auth) Token(w http.ResponseWriter, r *http.Request) {
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}

	if req.APIKey == "" {
		writeError(w, http.StatusUnprocessableEntity, "api_key is required")
		return
	}

	// Validate the API key against the configured set.
	if !a.validAPIKey(req.APIKey) {
		a.logger.Warn().Str("remote_addr", r.RemoteAddr).Msg("invalid API key presented")
		writeError(w, http.StatusUnauthorized, "invalid api_key")
		return
	}

	expiry := a.cfg.Auth.TokenExpiry
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}

	token, err := issueJWT(a.cfg.Auth.JWTSecret, "api-client", expiry)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to issue JWT")
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, tokenResponse{
		Token:     token,
		ExpiresIn: int64(expiry.Seconds()),
		TokenType: "Bearer",
	})
}

// validAPIKey returns true when key matches one of the configured API keys.
func (a *Auth) validAPIKey(key string) bool {
	for _, k := range a.cfg.Auth.APIKeys {
		if hmac.Equal([]byte(k), []byte(key)) {
			return true
		}
	}
	return false
}

// issueJWT creates a signed HS256 JWT with sub, iat, and exp claims.
func issueJWT(secret, subject string, expiry time.Duration) (string, error) {
	header := jwtBase64([]byte(`{"alg":"HS256","typ":"JWT"}`))

	now := time.Now()
	payload, err := json.Marshal(map[string]interface{}{
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := header + "." + jwtBase64(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := jwtBase64(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

func jwtBase64(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// TokenFromEnv handles GET /api/v1/auth/token — returns a dev token when the
// server is started with a single configured API key (for quick local testing).
// This endpoint is only reachable if EnableAPIKeys is true.
func (a *Auth) Ping(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"auth":       "ok",
		"api_keys":   len(a.cfg.Auth.APIKeys),
		"hint":       "POST /api/v1/auth/token with {\"api_key\":\"...\"} to obtain a Bearer token",
		"token_type": "HS256 JWT",
		"algorithms": []string{"HS256"},
	})
}

// stripPort removes the port suffix from an address like "1.2.3.4:5678".
func stripPort(addr string) string {
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}
