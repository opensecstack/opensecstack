// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensecstack/sdk/go/sinauth"
)

// contextKey is the unexported key type for values stored in request contexts.
type contextKey string

const (
	contextKeySubject contextKey = "subject"
	contextKeyRole    contextKey = "role"
)

// roleRank maps role names to their integer rank. Higher is more privileged.
var roleRank = map[string]int{
	"viewer":   1,
	"analyst":  2,
	"operator": 3,
	"admin":    4,
}

// isRS256Token returns true when the JWT header contains "alg":"RS256".
// It does not verify the token; it only inspects the (unauthenticated) header.
func isRS256Token(tokenStr string) bool {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) != 3 {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return header.Alg == "RS256"
}

// Authenticate is a chi middleware that validates the Bearer JWT in the
// Authorization header. On success it stores the "sub" and "role" claims in
// the request context. On failure it writes 401 Unauthorized.
//
// When sinauthURL is non-empty a sinauth client is created once at middleware
// construction time. Tokens whose header declares alg=RS256 are verified via
// the sinauth SDK (RS256 SSO path); all other tokens fall back to the existing
// HMAC-SHA256 (HS256) path.
func Authenticate(secret, sinauthURL string) func(http.Handler) http.Handler {
	// Build sinauth client once, log failure but do not crash.
	var sc *sinauth.Client
	if sinauthURL != "" {
		var err error
		sc, err = sinauth.New(sinauthURL)
		if err != nil {
			// Non-fatal: RS256 tokens will be rejected, HS256 still works.
			// A real deployment would wire a logger here; use stderr-level panic
			// avoidance by just leaving sc nil.
			_ = err
		}
	}

	keyFunc := func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := r.Header.Get("Authorization")
			if !strings.HasPrefix(raw, "Bearer ") {
				http.Error(w, "missing or malformed Authorization header", http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(raw, "Bearer ")

			// RS256 path: delegate to sinauth SDK.
			if sc != nil && isRS256Token(tokenStr) {
				saClaims, err := sc.VerifyToken(r.Context(), tokenStr)
				if err != nil {
					http.Error(w, "invalid or expired token", http.StatusUnauthorized)
					return
				}
				sub := saClaims.Sub
				role := saClaims.Role
				if sub == "" {
					http.Error(w, "token missing required claims", http.StatusUnauthorized)
					return
				}
				// role may be empty for service-account tokens; downstream
				// RequireRole will gate access as needed.
				ctx := context.WithValue(r.Context(), contextKeySubject, sub)
				ctx = context.WithValue(ctx, contextKeyRole, role)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// HS256 path: existing golang-jwt/HMAC validation.
			token, err := jwt.Parse(tokenStr, keyFunc,
				jwt.WithValidMethods([]string{"HS256"}),
				jwt.WithExpirationRequired(),
			)
			if err != nil || !token.Valid {
				http.Error(w, "invalid or expired token", http.StatusUnauthorized)
				return
			}

			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				http.Error(w, "malformed token claims", http.StatusUnauthorized)
				return
			}

			sub, _ := claims["sub"].(string)
			role, _ := claims["role"].(string)

			if sub == "" || role == "" {
				http.Error(w, "token missing required claims", http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextKeySubject, sub)
			ctx = context.WithValue(ctx, contextKeyRole, role)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns a middleware that allows only requests whose role claim
// meets or exceeds the privilege rank of minRole. Requests with an
// insufficient role receive 403 Forbidden. Authenticate must run before this
// middleware.
func RequireRole(minRole string) func(http.Handler) http.Handler {
	required, ok := roleRank[minRole]
	if !ok {
		// Fail-safe: if the role name is unrecognised, block everyone.
		required = 999
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role, _ := r.Context().Value(contextKeyRole).(string)
			rank, ok := roleRank[role]
			if !ok || rank < required {
				http.Error(w, "insufficient privileges", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SubjectFromContext extracts the "sub" claim stored by Authenticate.
func SubjectFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeySubject).(string)
	return v
}

// RoleFromContext extracts the "role" claim stored by Authenticate.
func RoleFromContext(ctx context.Context) string {
	v, _ := ctx.Value(contextKeyRole).(string)
	return v
}
