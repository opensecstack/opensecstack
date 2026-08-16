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
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	verifier := r.FormValue("code_verifier")

	if code == "" || redirectURI == "" || clientID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	// Consume auth code (atomic SELECT + DELETE)
	var userID, storedClientID, challenge, challengeMethod, nonce string
	var scopes []string
	var orgIDCol *string
	err := d.Pool.QueryRow(r.Context(),
		`DELETE FROM authorization_codes
         WHERE code=$1 AND expires_at > now() AND used=false
         RETURNING user_id, client_id, scopes, code_challenge, code_challenge_method, nonce, organization_id::text`,
		code,
	).Scan(&userID, &storedClientID, &scopes, &challenge, &challengeMethod, &nonce, &orgIDCol)
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

	// Resolve organization claims (ADR 005 v1.1) from the org context that was
	// validated and stored on the authorization code at /oauth/authorize time.
	// A code with no organization_id yields empty org claims, which the
	// omitempty tags on both token structs drop from the JWT entirely.
	orgID, orgRole, orgType := resolveOrgClaims(r.Context(), d, userID, orgIDCol)

	roles := effectiveAccessRoles(r.Context(), d, userID, clientID)

	// Policy enforcement (rbac.Store.Evaluate): the require_mfa/
	// require_email_verified/deny_role rows in the `policies` table were,
	// until this call site, never evaluated anywhere in sinauth — see
	// evaluator.go. This is the first of the two grant-handler call sites
	// that make them take effect.
	//
	// MFAVerified is conservatively always false here: sinauth does not yet
	// track step-up MFA completion as part of this OAuth flow (WebAuthn/SMS
	// OTP are standalone credential-management endpoints today, not wired as
	// a login/authorize step), so a require_mfa policy correctly denies
	// issuance until that session-level tracking is added — fail closed on
	// an explicit "require MFA" policy rather than silently treat it as
	// satisfied.
	if d.RBAC != nil {
		tc := rbac.TokenContext{
			UserID:        userID,
			Username:      u.Username,
			ClientID:      clientID,
			Roles:         roles,
			MFAVerified:   false,
			EmailVerified: u.EmailVerified,
			OrgID:         orgID,
			OrgRole:       orgRole,
		}
		if err := d.RBAC.Evaluate(r.Context(), tc); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "error_description": err.Error()})
			return
		}
	}

	// Issue tokens
	accessToken, err := d.Issuer.IssueAccessTokenWithRoles(u.Username, clientID, scopes, roles, orgID, orgRole, orgType, d.Cfg.AccessTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	idToken, err := d.Issuer.IssueIDToken(u.Username, clientID, nonce, u.Email, u.DisplayName, u.AvatarURL, u.EmailVerified, orgID, orgRole, orgType, d.Cfg.IDTokenTTL)
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
			// A failed save must not hand the client a refresh_token that
			// was never persisted — every future refresh attempt with it
			// would then fail with a confusing "invalid refresh token".
			if err := d.TokenStore.SaveRefreshToken(r.Context(), refreshToken, clientID, userID, scopes, time.Now().Add(d.Cfg.RefreshTokenTTL)); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
				return
			}
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
	// Refresh tokens do not currently carry organization context (out of
	// scope for ADR 005 v1.1 — org-scoped refresh is a follow-up), so
	// refreshed access tokens carry no org claims either.
	roles := effectiveAccessRoles(r.Context(), d, userID, clientID)

	// Policy enforcement — see the matching comment in handleAuthCodeGrant.
	// A refresh exchange re-evaluates policies against current state (e.g. a
	// deny_role policy added after the original login now applies), not just
	// the original grant.
	if d.RBAC != nil {
		tc := rbac.TokenContext{
			UserID:        userID,
			Username:      u.Username,
			ClientID:      clientID,
			Roles:         roles,
			MFAVerified:   false,
			EmailVerified: u.EmailVerified,
		}
		if err := d.RBAC.Evaluate(r.Context(), tc); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "error_description": err.Error()})
			return
		}
	}

	accessToken, err := d.Issuer.IssueAccessTokenWithRoles(u.Username, clientID, scopes, roles, "", "", "", d.Cfg.AccessTokenTTL)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	// Issue new refresh token
	b := make([]byte, 32)
	rand.Read(b)
	newRefresh := hex.EncodeToString(b)
	// ConsumeRefreshToken above already invalidated the old token (rotation
	// is single-use) — a failed save here would strand the client with no
	// working refresh token at all once the access token expires.
	if err := d.TokenStore.SaveRefreshToken(r.Context(), newRefresh, clientID, userID, scopes, time.Now().Add(d.Cfg.RefreshTokenTTL)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(d.Cfg.AccessTokenTTL.Seconds()),
		"refresh_token": newRefresh,
	})
}

// Ensure strings is used (scopes scanning uses it indirectly; explicit reference avoids import pruning).
var _ = strings.Join

// resolveOrgClaims turns the (possibly-NULL) organization_id read off a
// consumed authorization code into the org_id/org_role/org_type claim
// values to embed in the issued tokens (ADR 005 v1.1). It re-derives
// org_role/org_type from the organization package rather than trusting
// anything client-supplied — the code's organization_id was already
// validated for membership at /oauth/authorize time, but the role/type are
// looked up fresh here so they reflect current membership state at token
// issuance time.
//
// Returns three empty strings when orgIDCol is nil (no org context on this
// code) or when OrgSvc isn't wired — in both cases the caller ends up with
// individual-only tokens, matching pre-ADR-005 behaviour.
func resolveOrgClaims(ctx context.Context, d Deps, userID string, orgIDCol *string) (orgID, orgRole, orgType string) {
	if orgIDCol == nil || *orgIDCol == "" || d.OrgSvc == nil {
		return "", "", ""
	}

	org, err := d.OrgSvc.Get(ctx, *orgIDCol)
	if err != nil {
		return "", "", ""
	}

	memberships, err := d.OrgSvc.MembershipsForUser(ctx, userID)
	if err != nil {
		return "", "", ""
	}
	for _, m := range memberships {
		if m.OrganizationID == org.ID {
			return org.ID, m.OrgRole, org.OrgType
		}
	}
	// Membership was revoked between /oauth/authorize and /oauth/token: fail
	// closed on org claims rather than issuing an org_id with no org_role.
	return "", "", ""
}
