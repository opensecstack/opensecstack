package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/citadel"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
)

// revokedRefreshTokens stores SHA-256 hashes (hex-encoded) of refresh tokens
// that have been explicitly revoked via DELETE /api/v1/auth/refresh.
var revokedRefreshTokens sync.Map

// Auth handles authentication endpoints.
type Auth struct {
	logger         zerolog.Logger
	cfg            *config.Config
	db             *db.DB
	citadel        *citadel.Client
	sp             *middleware.SecretProvider
	denylist       *middleware.TokenDenylist // access-token denylist for logout
	trustedProxies []*net.IPNet              // parsed from cfg.RateLimit.TrustedProxies
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
// Pass a non-nil denylist to enable access-token logout via POST /auth/logout.
func NewAuthWithDB(logger zerolog.Logger, cfg *config.Config, database *db.DB, citadelClient *citadel.Client, sp *middleware.SecretProvider, denylist *middleware.TokenDenylist) *Auth {
	return &Auth{
		logger:         logger.With().Str("handler", "auth").Logger(),
		cfg:            cfg,
		db:             database,
		citadel:        citadelClient,
		sp:             sp,
		denylist:       denylist,
		trustedProxies: parseTrustedProxies(cfg),
	}
}

func (a *Auth) auditLog(ctx context.Context, action db.AuditAction, resourceType string, resourceID *uuid.UUID, ip, ua, actor, actorType string) {
	if a.db == nil {
		return
	}
	entry := &db.AuditLog{
		ActorID:      actor,
		ActorType:    actorType,
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
	if err := a.db.AppendAuditLog(ctx, entry, a.citadel); err != nil {
		a.logger.Warn().Err(err).Str("action", string(action)).Msg("audit log write failed")
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
	a.auditLog(r.Context(), db.AuditActionUserLogin, "auth", nil,
		middleware.ClientIPFromRequest(r, a.trustedProxies), r.UserAgent(), subject, "api_key")
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
			// Log api_key_used — best-effort, fire-and-forget
			a.auditLog(context.Background(), db.AuditActionAPIKeyUsed, "api_keys", nil, "", "", keyHash, "api_key")
			return true
		}
	}

	// NOTE: Static API keys configured in auth.api_keys remain valid regardless of
	// DB key state. Operators who have migrated to DB-managed keys should remove
	// static keys from config to ensure revocation is enforced. Static keys are
	// intended for bootstrapping only.
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
	writeJSON(w, http.StatusOK, map[string]interface{}{ //nolint:gosec // "hint" is a usage-instructions string, not a hardcoded credential
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

	// Check whether this refresh token has been explicitly revoked.
	// Cache layer: check in-memory map first to avoid a DB round-trip for
	// tokens that were revoked in the current process lifetime.
	tokenHash := refreshTokenHash(req.RefreshToken)
	if _, revoked := revokedRefreshTokens.Load(tokenHash); revoked {
		a.logger.Warn().Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("revoked refresh token presented (cache hit)")
		writeError(w, http.StatusUnauthorized, "token has been revoked")
		return
	}
	// DB layer: check persistent revocation store (survives restarts).
	if a.db != nil {
		revoked, err := db.IsRefreshTokenRevoked(r.Context(), a.db.Pool, tokenHash)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to check refresh token revocation in DB")
			writeError(w, http.StatusInternalServerError, "unable to verify token status")
			return
		}
		if revoked {
			// Populate the in-memory cache so subsequent requests are fast.
			revokedRefreshTokens.Store(tokenHash, struct{}{})
			a.logger.Warn().Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("revoked refresh token presented (db hit)")
			writeError(w, http.StatusUnauthorized, "token has been revoked")
			return
		}
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

	// Limit the refresh-token lifetime to 24 hours so a leaked token cannot be
	// misused indefinitely. Explicit revocation is handled via RevokeRefreshToken.
	refreshExpiry := 24 * time.Hour
	if refreshExpiry > expiry {
		refreshExpiry = expiry
	}
	newRefreshToken, err := issueJWT(a.cfg.Auth.JWTSecret, claims.Sub, "apiguard", "apiguard", "refresh", refreshExpiry)
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

// RevokeRefreshToken handles DELETE /api/v1/auth/refresh.
// It extracts a refresh token from the Authorization header and adds its
// SHA-256 hash to the revocation set (in-memory + DB) so that subsequent
// uses are rejected by the RefreshToken handler.
//
// Status codes:
//   - 401 — missing/malformed Authorization header or invalid token signature
//   - 200 — token was already revoked (idempotent; no action taken)
//   - 204 — token successfully revoked now
func (a *Auth) RevokeRefreshToken(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Auth.JWTSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "authentication not configured: jwt_secret is missing")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "Bearer token required in Authorization header")
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	if _, err := validateRefreshToken(tokenStr, a.cfg.Auth.JWTSecret); err != nil {
		a.logger.Warn().Err(err).Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("invalid token presented for revocation")
		writeError(w, http.StatusUnauthorized, "invalid or expired refresh token")
		return
	}

	tokenHash := refreshTokenHash(tokenStr)

	// Fast path: check in-memory cache before hitting the DB.
	if _, alreadyRevoked := revokedRefreshTokens.Load(tokenHash); alreadyRevoked {
		w.WriteHeader(http.StatusOK)
		return
	}

	// DB path: check persistent store (covers tokens revoked by another instance
	// or before the current process started).
	if a.db != nil {
		revoked, err := db.IsRefreshTokenRevoked(r.Context(), a.db.Pool, tokenHash)
		if err != nil {
			a.logger.Error().Err(err).Msg("failed to check refresh token revocation status in DB")
			writeError(w, http.StatusInternalServerError, "failed to revoke token")
			return
		}
		if revoked {
			// Populate in-memory cache so the next check is fast.
			revokedRefreshTokens.Store(tokenHash, struct{}{})
			w.WriteHeader(http.StatusOK)
			return
		}
	}

	// Not yet revoked — persist now.
	if a.db != nil {
		if err := db.RevokeRefreshToken(r.Context(), a.db.Pool, tokenHash); err != nil {
			a.logger.Error().Err(err).Msg("failed to persist refresh token revocation to DB")
			writeError(w, http.StatusInternalServerError, "failed to revoke token")
			return
		}
	}

	// Also store in the in-memory cache for fast subsequent checks.
	revokedRefreshTokens.Store(tokenHash, struct{}{})
	a.auditLog(r.Context(), db.AuditActionUserLogout, "auth", nil,
		middleware.ClientIPFromRequest(r, a.trustedProxies), r.UserAgent(), tokenHash, "api_key")
	w.WriteHeader(http.StatusNoContent)
}

// Logout handles POST /api/v1/auth/logout.
// It adds the caller's access token to the in-memory denylist so that
// subsequent requests bearing the same token are rejected by JWTAuth middleware
// before they reach any protected handler.
//
// No database persistence is needed: the denylist entry TTL is capped to the
// token's remaining lifetime, so the entry is irrelevant (and reaped) once the
// token would have expired anyway.
//
// Status codes:
//   - 401 — missing/malformed Authorization header or invalid access token
//   - 200 — token successfully added to denylist (or denylist not configured)
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	if a.cfg.Auth.JWTSecret == "" {
		writeError(w, http.StatusServiceUnavailable, "authentication not configured: jwt_secret is missing")
		return
	}

	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "Bearer token required in Authorization header")
		return
	}
	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate the access token to confirm the caller owns it and to extract
	// the expiry so we can set the correct denylist TTL.
	claims, err := validateAccessToken(tokenStr, a.cfg.Auth.JWTSecret, a.sp)
	if err != nil {
		a.logger.Warn().Err(err).Str("remote_addr", middleware.ClientIPFromRequest(r, a.trustedProxies)).Msg("invalid access token presented for logout")
		writeError(w, http.StatusUnauthorized, "invalid or expired access token")
		return
	}

	if a.denylist != nil {
		expiresAt := time.Unix(claims.Exp, 0)
		a.denylist.Add(middleware.HashToken(tokenStr), expiresAt)
	}

	a.auditLog(r.Context(), db.AuditActionUserLogout, "auth", nil,
		middleware.ClientIPFromRequest(r, a.trustedProxies), r.UserAgent(), claims.Sub, "user")
	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// validateAccessToken verifies an access token against the primary secret and,
// when a SecretProvider is available, all grace-period secrets too.
func validateAccessToken(tokenStr, primarySecret string, sp *middleware.SecretProvider) (*middleware.Claims, error) {
	secrets := []string{primarySecret}
	if sp != nil {
		for _, b := range sp.All() {
			s := string(b)
			if s != primarySecret {
				secrets = append(secrets, s)
			}
		}
	}
	var (
		claims *middleware.Claims
		err    error
	)
	for _, secret := range secrets {
		claims, err = middleware.ValidateAccessToken(tokenStr, secret)
		if err == nil {
			return claims, nil
		}
	}
	return nil, err
}

// ListRefreshTokens handles GET /api/v1/auth/refresh.
// Returns recently revoked refresh tokens (token_hash truncated to 8 chars,
// revoked_at timestamp). Since only revoked tokens are persisted, this list
// represents the revocation log rather than all issued tokens.
func (a *Auth) ListRefreshTokens(w http.ResponseWriter, r *http.Request) {
	if a.db == nil {
		writeError(w, http.StatusServiceUnavailable, "database not available")
		return
	}

	page := 1
	perPage := 50
	tokens, err := db.ListRevokedRefreshTokens(r.Context(), a.db.Pool, perPage, (page-1)*perPage)
	if err != nil {
		a.logger.Error().Err(err).Msg("failed to list revoked refresh tokens")
		writeError(w, http.StatusInternalServerError, "failed to list revoked tokens")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"revoked_tokens": tokens,
		"count":          len(tokens),
	})
}

// refreshTokenHash returns the hex-encoded SHA-256 hash of a raw refresh token
// string, used as the key in the revokedRefreshTokens map.
func refreshTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
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

func actorFromJWT(r *http.Request) string {
	if claims, ok := middleware.ClaimsFromContext(r.Context()); ok && claims.Sub != "" {
		return claims.Sub
	}
	return "unknown"
}

type rotateSecretRequest struct {
	NewSecret string `json:"new_secret"`
}

// RotateSecret handles POST /api/v1/admin/auth/rotate.
// It prepends newSecret as the active signing key, demoting existing secrets to
// grace-period verification-only keys (up to 3 total). Tokens signed with any
// retained secret remain valid until they expire naturally.
// Requires: new_secret >= 32 bytes. Never echoes the secret back.
func (a *Auth) RotateSecret(w http.ResponseWriter, r *http.Request) {
	if a.sp == nil {
		writeError(w, http.StatusServiceUnavailable, "secret rotation not available")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1*1024*1024)
	var req rotateSecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewSecret) < 32 {
		writeError(w, http.StatusUnprocessableEntity, "new_secret must be at least 32 characters")
		return
	}
	actor := actorFromJWT(r)
	a.sp.Rotate([]byte(req.NewSecret))
	a.auditLog(r.Context(), db.AuditActionJWTSecretRotated, "auth", nil,
		middleware.ClientIPFromRequest(r, a.trustedProxies), r.UserAgent(), actor, "user")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"rotated":        true,
		"active_secrets": a.sp.Len(),
	})
}
