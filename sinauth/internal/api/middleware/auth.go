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
