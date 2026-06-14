package sinauth

import (
	"context"
	"net/http"
	"strings"
)

type contextKey string

// ClaimsContextKey is the key used to store verified Claims in a request context.
const ClaimsContextKey contextKey = "sinauth_claims"

// BearerAuth returns an http.Handler middleware that verifies the sinauth
// Bearer token on each request. On success it stores *Claims in the request
// context under ClaimsContextKey and calls the next handler. On failure it
// writes a 401 JSON response.
func (c *Client) BearerAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"missing bearer token"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		claims, err := c.VerifyToken(r.Context(), token)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), ClaimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClaimsFromContext extracts verified Claims stored in ctx by the BearerAuth
// middleware. Returns (nil, false) if no claims are present.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ClaimsContextKey).(*Claims)
	return c, ok
}
