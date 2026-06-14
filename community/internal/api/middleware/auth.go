package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/auth"
)

type contextKey string

const ClaimsKey contextKey = "claims"

// Auth validates the JWT and enforces session revocation.
// It accepts an optional *pgxpool.Pool: when non-nil it checks the user_sessions
// table so that revoked tokens are rejected even if the JWT signature is still valid.
func Auth(secret string, pool ...*pgxpool.Pool) func(http.Handler) http.Handler {
	var db *pgxpool.Pool
	if len(pool) > 0 {
		db = pool[0]
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rawToken, claims, err := extractClaimsRaw(r, secret)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// When a DB pool is available, enforce session revocation and update last_seen.
			if db != nil {
				hash := tokenHashStr(rawToken)

				// Revocation check — fail CLOSED: any DB error is treated as a rejection.
				// Only allow the request through if the query succeeds and the session exists.
				var exists bool
				err := db.QueryRow(r.Context(),
					`SELECT EXISTS(SELECT 1 FROM user_sessions WHERE token_hash = $1 AND expires_at > NOW())`,
					hash,
				).Scan(&exists)
				if err != nil || !exists {
					http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
					return
				}

				// Deactivated-account check — reject if user is deactivated or DB is unavailable.
				var deactivatedAt *time.Time
				err = db.QueryRow(r.Context(),
					`SELECT deactivated_at FROM users WHERE username = $1`,
					claims.Sub,
				).Scan(&deactivatedAt)
				if err != nil || deactivatedAt != nil {
					http.Error(w, `{"error":"account deactivated"}`, http.StatusForbidden)
					return
				}

				// Update last_seen_at in the background — don't block the request.
				go func() {
					ctx := context.Background()
					db.Exec(ctx, `UPDATE user_sessions SET last_seen_at = NOW() WHERE token_hash = $1`, hash)
				}()
			}

			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims)))
		})
	}
}

// OptionalAuth attaches claims to the context when a valid JWT is present.
// It does NOT enforce session revocation (used on public endpoints).
func OptionalAuth(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, claims, err := extractClaimsRaw(r, secret); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), ClaimsKey, claims))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func ClaimsFrom(ctx context.Context) *auth.Claims {
	c, _ := ctx.Value(ClaimsKey).(*auth.Claims)
	return c
}

// extractClaimsRaw returns both the raw token string and the validated claims.
func extractClaimsRaw(r *http.Request, secret string) (string, *auth.Claims, error) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		return "", nil, auth.ErrInvalidToken
	}
	raw := strings.TrimPrefix(header, "Bearer ")
	claims, err := auth.Verify(raw, secret)
	if err != nil {
		return "", nil, err
	}
	return raw, claims, nil
}

// tokenHashStr returns the SHA-256 hex digest of a token string.
func tokenHashStr(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
