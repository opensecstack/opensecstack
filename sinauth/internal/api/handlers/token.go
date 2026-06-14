package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/opensecstack/sinauth/internal/oidc"
	"github.com/opensecstack/sinauth/internal/rbac"
)

// effectiveAccessRoles returns the user's effective RBAC roles for the client,
// falling back to the configured default role when the user has no explicit
// per-client assignment. This ensures issued access tokens always carry a
// "role" claim so downstream platforms' RBAC can authorise the request.
func effectiveAccessRoles(ctx context.Context, d Deps, userID, clientID string) []string {
	roles, err := rbac.NewStore(d.Pool).GetEffectiveRoles(ctx, userID, clientID)
	if err != nil || len(roles) == 0 {
		if d.Cfg.DefaultRole != "" {
			return []string{d.Cfg.DefaultRole}
		}
		return nil
	}
	return roles
}

// Token handles POST /oauth/token
// Supports: authorization_code, refresh_token grant types.
func Token(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
			return
		}
		grantType := r.FormValue("grant_type")
		switch grantType {
		case "authorization_code":
			handleAuthCodeGrant(w, r, d)
		case "refresh_token":
			handleRefreshGrant(w, r, d)
		default:
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_grant_type"})
		}
	}
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, d Deps) {
	code        := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID    := r.FormValue("client_id")
	verifier    := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Consume auth code (atomic SELECT + DELETE)
	var userID, storedClientID, challenge, challengeMethod, nonce string
	var scopes []string
	err := d.Pool.QueryRow(r.Context(),
		`DELETE FROM authorization_codes
         WHERE code=$1 AND expires_at > now() AND used=false
         RETURNING user_id, client_id, scopes, code_challenge, code_challenge_method, nonce`,
		code,
	).Scan(&userID, &storedClientID, &scopes, &challenge, &challengeMethod, &nonce)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	if storedClientID != clientID {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}

	// Verify PKCE
	if challenge != "" {
		if verifier == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
		if err := oidc.VerifyS256(verifier, challenge); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
			return
		}
	}

	// Load user claims
	u, err := d.UserSvc.GetByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Issue tokens
	accessToken, err := d.Issuer.IssueAccessTokenWithRoles(u.Username, clientID, scopes, effectiveAccessRoles(r.Context(), d, userID, clientID), d.Cfg.AccessTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	idToken, err := d.Issuer.IssueIDToken(u.Username, clientID, nonce, u.Email, u.DisplayName, u.AvatarURL, u.EmailVerified, d.Cfg.IDTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	// Issue refresh token if scope includes offline_access
	var refreshToken string
	for _, s := range scopes {
		if s == "offline_access" {
			b := make([]byte, 32)
			rand.Read(b)
			refreshToken = hex.EncodeToString(b)
			d.TokenStore.SaveRefreshToken(r.Context(), refreshToken, clientID, userID, scopes, time.Now().Add(d.Cfg.RefreshTokenTTL))
			break
		}
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(d.Cfg.AccessTokenTTL.Seconds()),
		"id_token":     idToken,
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleRefreshGrant(w http.ResponseWriter, r *http.Request, d Deps) {
	raw := r.FormValue("refresh_token")
	if raw == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	clientID, userID, scopes, err := d.TokenStore.ConsumeRefreshToken(r.Context(), raw)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	u, err := d.UserSvc.GetByID(r.Context(), userID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	accessToken, err := d.Issuer.IssueAccessTokenWithRoles(u.Username, clientID, scopes, effectiveAccessRoles(r.Context(), d, userID, clientID), d.Cfg.AccessTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Issue new refresh token
	b := make([]byte, 32)
	rand.Read(b)
	newRefresh := hex.EncodeToString(b)
	d.TokenStore.SaveRefreshToken(r.Context(), newRefresh, clientID, userID, scopes, time.Now().Add(d.Cfg.RefreshTokenTTL))

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(d.Cfg.AccessTokenTTL.Seconds()),
		"refresh_token": newRefresh,
	})
}

// Ensure strings is used (scopes scanning uses it indirectly; explicit reference avoids import pruning).
var _ = strings.Join
