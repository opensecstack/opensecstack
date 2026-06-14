package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/auth"
)

// AuthDeps wires the login endpoint. When Creds is empty, /auth/login
// responds 503 (issuer disabled) — operators are then expected to mint
// JWTs out-of-band against OPENSCRUB_JWT_SECRET.
type AuthDeps struct {
	Creds  *auth.CredentialStore
	Issuer *auth.Issuer
	Logger zerolog.Logger
}

// Auth bundles the login handler. Method receiver kept as *Auth so
// future endpoints (refresh, whoami) can hang off the same struct.
type Auth struct {
	deps AuthDeps
}

// NewAuth builds an Auth handler.
func NewAuth(d AuthDeps) *Auth { return &Auth{deps: d} }

// Enabled reports whether the issuer is wired (creds + issuer + secret).
// The router uses this to decide whether to register the route — when
// disabled we still register a stub that returns 503 so the dashboard
// gets a meaningful error instead of a 404.
func (a *Auth) Enabled() bool {
	return a != nil && a.deps.Issuer != nil && a.deps.Creds != nil && !a.deps.Creds.Empty()
}

// Login handles POST /api/v1/auth/login.
//
// Request:  {"username": "...", "password": "..."}
// Response: {"access_token": "...", "token_type": "Bearer",
//            "expires_at": "RFC3339", "role": "...", "sub": "..."}
//
// `sub` echoes the verified username so the frontend can render
// "logged in as …" without re-decoding the JWT body.
//
// Failure modes:
//   400 bad_json         malformed request body
//   401 invalid_creds    username/password wrong (constant-time compare)
//   503 issuer_disabled  no credentials seeded → operator must mint OOB
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if !a.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "issuer_disabled",
			"login endpoint disabled; mint a JWT out-of-band against OPENSCRUB_JWT_SECRET")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "missing_field", "username and password required")
		return
	}
	cred, err := a.deps.Creds.Verify(req.Username, req.Password)
	if err != nil {
		// Don't distinguish "no such user" from "wrong password" in the
		// response — the timing-safe check in CredentialStore.Verify
		// already does the same on the wire.
		a.deps.Logger.Warn().Str("username", req.Username).Msg("login failed")
		writeError(w, http.StatusUnauthorized, "invalid_creds", "invalid credentials")
		return
	}
	tok, exp, err := a.deps.Issuer.Mint(cred.Username, cred.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "mint_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tok,
		"token_type":   "Bearer",
		"expires_at":   exp.UTC().Format(time.RFC3339),
		"role":         cred.Role,
		"sub":          cred.Username,
	})
}

// Whoami handles GET /api/v1/auth/whoami. The dashboard calls this on
// page load to confirm the JWT in sessionStorage is still accepted by
// the server — required because the client-side jwt.ts only checks
// `exp`, not the signature, and would happily accept a token signed by
// a now-rotated secret. The auth.Middleware in front of this route
// rejects unverifiable tokens with 401 (which the axios interceptor
// converts into a logout), so reaching this handler implies the claim
// is currently valid.
func (a *Auth) Whoami(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.FromContext(r.Context())
	if !ok || c == nil {
		// Dev mode without claims — middleware would normally inject a
		// synthetic admin, so this branch is only reachable when the
		// route is somehow mounted outside the auth chain.
		writeError(w, http.StatusUnauthorized, "no_claims", "no claims in context")
		return
	}
	resp := map[string]any{
		"sub":  c.Sub,
		"role": c.Role,
	}
	if len(c.Roles) > 0 {
		resp["roles"] = c.Roles
	}
	if c.Iss != "" {
		resp["iss"] = c.Iss
	}
	if c.Exp > 0 {
		resp["exp"] = c.Exp
	}
	writeJSON(w, http.StatusOK, resp)
}
