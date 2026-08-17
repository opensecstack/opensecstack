package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/opensecstack/sdk/go/sinauth"
	"github.com/rs/zerolog"
)

type ctxKey int

const (
	claimsCtxKey ctxKey = iota
)

// Revoker is the (optional) hook the auth middleware uses to consult
// a JWT denylist. The denylist subsystem provides a concrete impl; pass
// nil to keep the legacy behaviour.
type Revoker interface {
	IsRevoked(claims *Claims) (bool, string)
}

// jwtAlg parses the JWT header (without signature verification) and returns
// the alg field. Returns "" on any error.
func jwtAlg(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(b, &hdr); err != nil {
		return ""
	}
	return hdr.Alg
}

// sinHolder wraps a lazily-initialised sinauth.Client. Lazy init means
// startup succeeds even when the sinauth issuer is temporarily down.
type sinHolder struct {
	url     string
	once    sync.Once
	client  *sinauth.Client
	initErr error
}

func newSinHolder(url string) *sinHolder { return &sinHolder{url: url} }

func (h *sinHolder) get() (*sinauth.Client, error) {
	h.once.Do(func() {
		h.client, h.initErr = sinauth.New(h.url)
	})
	return h.client, h.initErr
}

// Middleware returns a chi-compatible middleware that verifies the
// JWT from the Authorization header and stores the Claims in context.
//
// devMode: when true, a synthetic admin identity is injected and
// verification is bypassed. WARN at startup ensures operators notice.
//
// revoker: optional. When non-nil, verified-but-revoked tokens are
// rejected with 401 + code "token_revoked".
//
// The middleware uses dual-mode verification: RS256 tokens are routed to
// a lazily-initialised sinauth client (default issuer http://localhost:8100);
// all other tokens fall through to the HS256 Verifier v.
// Use MiddlewareWithSinauth to supply a custom issuer URL.
func Middleware(v *Verifier, devMode bool, logger *zerolog.Logger, revoker ...Revoker) func(http.Handler) http.Handler {
	return MiddlewareWithSinauth(v, devMode, "http://localhost:8100", logger, revoker...)
}

// MiddlewareWithSinauth is like Middleware but uses sinauthURL for RS256
// token verification instead of the default http://localhost:8100.
func MiddlewareWithSinauth(v *Verifier, devMode bool, sinauthURL string, logger *zerolog.Logger, revoker ...Revoker) func(http.Handler) http.Handler {
	var rev Revoker
	for _, r := range revoker {
		if r != nil {
			rev = r
			break
		}
	}
	sin := newSinHolder(sinauthURL)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if devMode {
				ctx := context.WithValue(r.Context(), claimsCtxKey, &Claims{
					Sub: "dev", Role: RoleAdmin, Iss: "vertguard",
				})
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			hdr := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(hdr, prefix) {
				writeUnauthorized(w, "missing or malformed Authorization header")
				return
			}
			token := strings.TrimSpace(hdr[len(prefix):])

			var claims *Claims
			if jwtAlg(token) == "RS256" {
				client, err := sin.get()
				if err != nil {
					if logger != nil {
						logger.Warn().Err(err).Str("path", r.URL.Path).Msg("sinauth client init failed")
					}
					writeUnauthorized(w, "sinauth unavailable")
					return
				}
				sc, err := client.VerifyToken(r.Context(), token)
				if err != nil {
					if logger != nil {
						logger.Warn().Err(err).Str("path", r.URL.Path).Msg("sinauth verify failed")
					}
					writeUnauthorized(w, "invalid token")
					return
				}
				role := sc.Role
				if role == "" && len(sc.ClientRoles) > 0 {
					role = sc.ClientRoles[0]
				}
				claims = &Claims{
					Sub:  sc.Sub,
					Role: role,
					Iss:  sc.Issuer,
				}
			} else {
				var err error
				claims, err = v.Verify(token)
				if err != nil {
					if logger != nil {
						logger.Warn().
							Err(err).
							Str("path", r.URL.Path).
							Msg("jwt verify failed")
					}
					writeUnauthorized(w, "invalid token")
					return
				}
			}

			if rev != nil {
				if revoked, reason := rev.IsRevoked(claims); revoked {
					if logger != nil {
						logger.Warn().
							Str("sub", claims.Sub).
							Str("jti", claims.Jti).
							Str("reason", reason).
							Str("path", r.URL.Path).
							Msg("revoked token rejected")
					}
					writeTokenRevoked(w, reason)
					return
				}
			}

			ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext returns the verified claims, if any.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(claimsCtxKey).(*Claims)
	return c, ok
}

// InjectClaimsForTest is a test-only helper that mounts a Claims value
// into ctx using the same key the production Middleware uses. Lets
// handler-level unit tests exercise the post-auth branch without
// minting a real JWT. NOT intended for production code paths.
func InjectClaimsForTest(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey, c)
}

// RequireWrite is a handler wrapper enforcing write-level authorisation.
func RequireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			writeForbidden(w, "authentication required")
			return
		}
		if !canWrite(claims.Role) {
			writeForbidden(w, "role lacks write permission")
			return
		}
		next(w, r)
	}
}

// RequireAdmin enforces admin role.
func RequireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || !canAdmin(claims.Role) {
			writeForbidden(w, "admin role required")
			return
		}
		next(w, r)
	}
}

// RequireRead enforces read (any known role).
func RequireRead(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || !canRead(claims.Role) {
			writeForbidden(w, "authentication required")
			return
		}
		next(w, r)
	}
}

func writeUnauthorized(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"unauthorized"}`))
}

// writeTokenRevoked emits the 401 used when the JWT is structurally
// valid but has been added to the denylist. Distinct code so clients
// can distinguish from generic auth failures and trigger a re-login.
func writeTokenRevoked(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	body := `token revoked`
	if reason != "" {
		body = `token revoked: ` + jsonEscape(reason)
	}
	_, _ = w.Write([]byte(`{"error":"` + body + `","code":"token_revoked"}`))
}

// jsonEscape minimally escapes characters that would break the inline
// JSON we hand-build above. Full json.Marshal is overkill for a short
// human reason string.
func jsonEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				continue
			}
			b.WriteRune(r)
		}
	}
	return b.String()
}

func writeForbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write([]byte(`{"error":"` + msg + `","code":"forbidden"}`))
}
