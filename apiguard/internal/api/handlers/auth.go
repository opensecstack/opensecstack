package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
)

// Auth handles authentication endpoints.
type Auth struct {
	logger         zerolog.Logger
	cfg            *config.Config
	db             *db.DB
	trustedProxies []*net.IPNet // parsed from cfg.RateLimit.TrustedProxies
}

// NewAuth creates a new Auth handler.
func NewAuth(logger zerolog.Logger, cfg *config.Config) *Auth {
	return &Auth{
		logger:         logger.With().Str("handler", "auth").Logger(),
		cfg:            cfg,
		trustedProxies: parseTrustedProxies(cfg),
	}
}

// NewAuthWithDB creates a new Auth handler that can also validate keys stored
// in the database, falling back to the static config keys when DB is unavailable.
func NewAuthWithDB(logger zerolog.Logger, cfg *config.Config, database *db.DB) *Auth {
	return &Auth{
		logger:         logger.With().Str("handler", "auth").Logger(),
		cfg:            cfg,
		db:             database,
		trustedProxies: parseTrustedProxies(cfg),
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
	// Fail fast if the server isn't fully configured for auth.
	if a.cfg.Auth.JWTSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "authentication not configured: jwt_secret is missing")
		return
	}
	// Allow DB-managed keys to substitute for static config keys, so only
	// fail when both sources are absent.
	if len(a.cfg.Auth.APIKeys) == 0 && a.db == nil {
		writeError(w, http.StatusServiceUnavailable, "authentication not configured: no api_keys defined — set auth.api_keys in config or APIGUARD_AUTH_API_KEYS env var")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1 MB
	var req tokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.APIKey == "" {
		writeError(w, http.StatusUnprocessableEntity, "api_key is required")
		return
	}

	// Validate the API key against the configured set.
	if !a.validAPIKey(req.APIKey) {
		a.logger.Warn().Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("invalid API key presented")
		writeError(w, http.StatusUnauthorized, "invalid api_key")
		return
	}

	expiry := a.cfg.Auth.TokenExpiry
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}

	// H2: embed the SHA-256 hash of the API key in the subject for traceability
	// and to support key-revocation checks on token refresh (H3).
	keyHashBytes := sha256.Sum256([]byte(req.APIKey))
	subject := "api-client:" + hex.EncodeToString(keyHashBytes[:])

	token, err := issueJWT(a.cfg.Auth.JWTSecret, subject, "apiguard", "apiguard", "access", expiry)
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

// validAPIKey returns true when key matches either an active DB-managed key or
// one of the statically configured API keys.
//
// DB lookup is attempted first. If the DB is unavailable the error is logged
// and validation falls through to the static config keys so the system remains
// operational (same graceful-degradation pattern used elsewhere).
func (a *Auth) validAPIKey(key string) bool {
	// --- DB-backed key check ---
	if a.db != nil {
		sum := sha256.Sum256([]byte(key))
		keyHash := hex.EncodeToString(sum[:])
		found, err := a.db.LookupAPIKeyByHash(context.Background(), keyHash)
		if err != nil {
			a.logger.Warn().Err(err).Msg("db api key lookup failed, falling back to config keys")
		} else if found {
			return true
		}
	}

	// --- Static config key fallback ---
	for _, k := range a.cfg.Auth.APIKeys {
		if hmac.Equal([]byte(k), []byte(key)) {
			return true
		}
	}
	return false
}

// issueJWT creates a signed HS256 JWT with sub, iat, exp, iss, aud, and typ claims.
// tokenType should be "access" for access tokens and "refresh" for refresh tokens.
func issueJWT(secret, subject, issuer, audience, tokenType string, expiry time.Duration) (string, error) {
	header := jwtBase64([]byte(`{"alg":"HS256","typ":"JWT"}`))

	now := time.Now()
	payload, err := json.Marshal(map[string]interface{}{
		"sub": subject,
		"iat": now.Unix(),
		"exp": now.Add(expiry).Unix(),
		"iss": issuer,
		"aud": audience,
		"typ": tokenType,
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

// Ping handles GET /api/v1/auth/token.
// Returns usage instructions for the token endpoint.
func (a *Auth) Ping(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"hint":       "POST /api/v1/auth/token with {\"api_key\":\"<your-key>\"} to obtain a Bearer token",
		"token_type": "HS256 JWT",
		"algorithms": []string{"HS256"},
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type refreshResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RefreshToken handles POST /api/v1/auth/refresh.
// It accepts a valid refresh token and returns a new access token and refresh token.
func (a *Auth) RefreshToken(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Auth.JWTSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "authentication not configured: jwt_secret is missing")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024) // 1 MB
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusUnauthorized, "refresh_token is required")
		return
	}

	claims, err := validateRefreshToken(req.RefreshToken, a.cfg.Auth.JWTSecret)
	if err != nil {
		a.logger.Warn().Err(err).Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("invalid refresh token presented")
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	// H3: verify the API key referenced in the refresh token is still active.
	if a.db != nil && strings.HasPrefix(claims.Sub, "api-client:") {
		keyHash := strings.TrimPrefix(claims.Sub, "api-client:")
		found, err := a.db.LookupAPIKeyByHash(r.Context(), keyHash)
		if err != nil {
			a.logger.Warn().Err(err).Msg("db api key lookup failed during token refresh")
			// Do not fall through — refuse the refresh when we cannot verify.
			writeError(w, http.StatusInternalServerError, "unable to verify API key status")
			return
		}
		if !found {
			a.logger.Warn().Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("refresh rejected: API key no longer active")
			writeError(w, http.StatusUnauthorized, "API key has been revoked")
			return
		}
	}

	expiry := a.cfg.Auth.TokenExpiry
	if expiry <= 0 {
		expiry = 24 * time.Hour
	}

	accessToken, err := issueJWT(a.cfg.Auth.JWTSecret, claims.Sub, "apiguard", "apiguard", "access", expiry)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to issue access token")
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	// A-H5: refresh tokens have no server-side invalidation mechanism; limit
	// the exposure window to 24 hours so a leaked token cannot be misused
	// indefinitely. TODO: implement a refresh-token allowlist/revocation store
	// to fully invalidate issued refresh tokens.
	newRefreshToken, err := issueJWT(a.cfg.Auth.JWTSecret, claims.Sub, "apiguard", "apiguard", "refresh", 24*time.Hour)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to issue refresh token")
		writeError(w, http.StatusInternalServerError, "failed to issue token")
		return
	}

	writeJSON(w, http.StatusOK, refreshResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(expiry.Seconds()),
	})
}

// validateRefreshToken verifies the HS256 signature and expiry of a refresh
// token. On success it returns the parsed claims so the caller can inspect Sub.
func validateRefreshToken(token, secret string) (*jwtClaims, error) {
	segments := strings.SplitN(token, ".", 3)
	if len(segments) != 3 {
		return nil, fmt.Errorf("token must have 3 parts, got %d", len(segments))
	}

	headerB64, payloadB64, signatureB64 := segments[0], segments[1], segments[2]

	// Verify HMAC-SHA256 signature.
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	expectedSig := mac.Sum(nil)

	actualSig, err := jwtBase64Decode(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	if !hmac.Equal(expectedSig, actualSig) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Decode and parse payload claims.
	payloadBytes, err := jwtBase64Decode(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("invalid payload JSON: %w", err)
	}

	if claims.Exp == 0 {
		return nil, fmt.Errorf("missing exp claim")
	}
	if time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token has expired")
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	if claims.Iss != "apiguard" {
		return nil, fmt.Errorf("invalid iss claim: %q", claims.Iss)
	}
	if claims.Aud != "apiguard" {
		return nil, fmt.Errorf("invalid aud claim: %q", claims.Aud)
	}
	if claims.Typ != "refresh" {
		return nil, fmt.Errorf("invalid token type %q: expected \"refresh\"", claims.Typ)
	}

	return &claims, nil
}

// jwtClaims holds the standard JWT payload fields used internally.
type jwtClaims struct {
	Sub string `json:"sub"`
	Exp int64  `json:"exp"`
	Iat int64  `json:"iat"`
	Iss string `json:"iss"`
	Aud string `json:"aud"`
	Typ string `json:"typ"`
}

// jwtBase64Decode decodes a base64url-encoded string (without padding).
func jwtBase64Decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
