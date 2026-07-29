package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/opensecstack/sinauth/internal/token"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// BearerAuth validates access tokens for protected endpoints.
func BearerAuth(v *token.Verifier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			raw := strings.TrimPrefix(header, "Bearer ")
			claims, err := v.Verify(raw)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims)))
		})
	}
}

// ClaimsFrom extracts access token claims from the request context.
func ClaimsFrom(ctx context.Context) *token.AccessTokenClaims {
	c, _ := ctx.Value(ClaimsKey).(*token.AccessTokenClaims)
	return c
}

// AdminChecker resolves whether an authenticated user has platform-admin
// standing. Implemented by *user.Service (internal/user/service.go); kept
// as a narrow interface here so this package doesn't need to import user.
type AdminChecker interface {
	IsPlatformAdmin(ctx context.Context, userID string) (bool, error)
}

// RequireAdmin composes BearerAuth with a platform-admin authorization
// check. sinauth's /admin/* routes originally relied on BearerAuth alone,
// which only proves a token is validly-signed and unexpired — it does NOT
// establish that the caller has any administrative standing. That gap let
// any authenticated user create/delete organizations and RBAC groups, and
// grant themselves membership (including org_role=owner) in organizations
// or groups they had no legitimate connection to.
//
// RequireAdmin fixes that: it first runs BearerAuth to authenticate the
// caller, then resolves the caller's user id against AdminChecker and
// rejects the request with 403 unless the user is flagged as a platform
// admin (users.is_platform_admin — see migrations/019_platform_admin.sql).
// See SECURITY.md for how the first platform admin is bootstrapped.
func RequireAdmin(v *token.Verifier, admins AdminChecker) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		checkAdmin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFrom(r.Context())
			if claims == nil || claims.Sub == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			isAdmin, err := admins.IsPlatformAdmin(r.Context(), claims.Sub)
			if err != nil || !isAdmin {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
		return BearerAuth(v)(checkAdmin)
	}
}
