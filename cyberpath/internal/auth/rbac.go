// Package auth — RBAC middleware + helpers.
//
// The JWT middleware (see jwt.go) authenticates the caller and stashes
// *Claims in the request context. RBAC sits one layer above: given an
// already-authenticated request, decide whether the caller's role is
// allowed to hit this route.
//
// Role model: schema (migration 0002) ties users to a single role via
// `users.role_id` FK, so the canonical claim is `Claims.Role` (single
// string). For forward-compatibility with token issuers that emit a
// `roles` array, HasRole also consults `Claims.Roles` when present.
package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// Role identifiers — kept in sync with the seeded `roles` table.
const (
	RoleAdmin      = "admin"
	RoleInstructor = "instructor"
	RoleLearner    = "learner"
	RoleAuditor    = "auditor"
)

// ClaimsFromContext returns the claims previously stashed by the JWT
// middleware. Aliased to FromContext — exported under both names so
// call sites can pick whichever reads better at the use point.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	return FromContext(ctx)
}

// HasRole reports whether the supplied claims grant the given role.
// Checks the single-string Role field first (canonical, matches the
// schema's users.role_id FK), then falls back to the optional Roles
// slice for tokens issued with multi-role payloads.
func HasRole(claims *Claims, role string) bool {
	if claims == nil || role == "" {
		return false
	}
	if claims.Role == role {
		return true
	}
	for _, r := range claims.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// hasAnyRole reports whether the claims hold at least one of the
// supplied roles. Empty `roles` means "no requirement" → true.
func hasAnyRole(claims *Claims, roles []string) bool {
	if len(roles) == 0 {
		return true
	}
	for _, r := range roles {
		if HasRole(claims, r) {
			return true
		}
	}
	return false
}

// RequireRole returns a middleware that admits the request only when
// the caller's claims include at least one of the supplied roles.
//
//   - No claims in context  → 401 unauthenticated (JWT middleware
//     should have caught this; defence in depth).
//   - Claims present, role not in set → 403 forbidden.
//   - Claims present, role in set → next handler.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				writeRBACErr(w, http.StatusUnauthorized,
					"unauthenticated", "authentication required")
				return
			}
			if !hasAnyRole(claims, roles) {
				writeRBACErr(w, http.StatusForbidden,
					"forbidden", "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAnyRole is an alias for RequireRole that reads more naturally
// at call sites enforcing "any of these roles".
func RequireAnyRole(roles ...string) func(http.Handler) http.Handler {
	return RequireRole(roles...)
}

func writeRBACErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
