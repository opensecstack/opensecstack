package handlers

import (
	"net/http"

	"github.com/opensecstack/vertguard/internal/auth"
)

// AuthHandler exposes auth-introspection endpoints. Today only Whoami;
// scaffolded as a struct so future endpoints (refresh, etc.) hang off
// the same wiring without re-plumbing main.go.
type AuthHandler struct{}

// NewAuthHandler is the conventional constructor.
func NewAuthHandler() *AuthHandler { return &AuthHandler{} }

// Whoami handles GET /api/v1/auth/whoami. Mirrors openscrub's contract:
// returns the verified claim set so the dashboard can confirm the JWT
// in sessionStorage is still accepted by the server (the client-side
// token check only validates `exp`, not the signature, so a token
// signed by a now-rotated secret would otherwise look valid until the
// next privileged call).
//
// The auth.Middleware in front of this route normally rejects
// unverifiable tokens with 401. The no-claims branch below stays as a
// belt-and-suspenders guard for the case where the route is somehow
// mounted outside the auth chain (e.g. dev mode misconfiguration).
func (h *AuthHandler) Whoami(w http.ResponseWriter, r *http.Request) {
	c, ok := auth.ClaimsFromContext(r.Context())
	if !ok || c == nil {
		writeJSONError(w, http.StatusUnauthorized, "no_claims", "no claims in context")
		return
	}
	resp := map[string]any{
		"sub":  c.Sub,
		"role": c.Role,
	}
	if c.Iss != "" {
		resp["iss"] = c.Iss
	}
	if c.Exp > 0 {
		resp["exp"] = c.Exp
	}
	if c.Iat > 0 {
		resp["iat"] = c.Iat
	}
	writeJSON(w, http.StatusOK, resp)
}
