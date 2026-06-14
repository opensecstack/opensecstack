package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"go.uber.org/zap"

	"github.com/opensecstack/sdk/go/sinauth"
)

// Config controls the auth middleware's behaviour.
type Config struct {
	// Secret is the HMAC-SHA256 signing key. Required unless Disabled is true.
	Secret string

	// Disabled short-circuits the middleware: every request passes through
	// unauthenticated. Intended for integration tests and local development.
	// Must never be true in production.
	Disabled bool

	// Pepper is the server-side secret fed into Argon2id via NewHasher
	// when hashing API keys or other long-lived credentials. Must be
	// >= 16 bytes of high-entropy material. Empty disables password
	// hashing helpers at startup.
	Pepper string

	// SinauthURL is the sinauth issuer URL used for RS256 token verification.
	// When a bearer token carries alg=RS256 it is verified against this endpoint.
	// Defaults to http://localhost:8100 when empty.
	SinauthURL string

	// Logger records decisions. A nop logger is used when nil.
	Logger *zap.Logger
}

// sinauthState holds the lazily-initialised sinauth client per middleware
// instance (one per Config). Using sync.Once avoids a startup hard dependency
// on sinauth being reachable.
type sinauthState struct {
	once    sync.Once
	client  *sinauth.Client
	initErr error
}

// jwtHeaderAlg parses only the JWT header segment (no signature check) and
// returns the "alg" field. Returns "" on any parse error.
func jwtHeaderAlg(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return ""
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return ""
	}
	return hdr.Alg
}

// Middleware returns a chi-compatible middleware that validates a Bearer
// JWT on every request, attaches the claims to the request context, and
// rejects requests without a valid token with 401.
//
// Dual-mode: tokens with alg=RS256 are verified via the sinauth SDK
// (OIDC/JWKS); all other algorithms fall through to the existing HS256 path.
func Middleware(cfg Config) func(http.Handler) http.Handler {
	log := cfg.Logger
	if log == nil {
		log = zap.NewNop()
	}
	sinauthURL := cfg.SinauthURL
	if sinauthURL == "" {
		sinauthURL = "http://localhost:8100"
	}
	sas := &sinauthState{}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if cfg.Disabled {
				// Inject synthetic dev claims so downstream RequireWrite /
				// RequireDelete / RequireRole guards also pass. Dev-mode
				// requests surface as role=admin in audit logs (honest,
				// since they have unrestricted access).
				dev := &Claims{Subject: "dev", Role: RoleAdmin}
				next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), dev)))
				return
			}

			token := bearerToken(r)
			if token == "" {
				writeAuthError(w, http.StatusUnauthorized, "missing bearer token")
				return
			}

			// Dual-mode: RS256 → sinauth, everything else → HS256.
			if jwtHeaderAlg(token) == "RS256" {
				sas.once.Do(func() {
					sas.client, sas.initErr = sinauth.New(sinauthURL)
				})
				if sas.initErr != nil {
					log.Info("auth: sinauth client unavailable",
						zap.String("path", r.URL.Path),
						zap.Error(sas.initErr),
					)
					writeAuthError(w, http.StatusUnauthorized, "sinauth unavailable: "+sas.initErr.Error())
					return
				}
				sc, err := sas.client.VerifyToken(context.Background(), token)
				if err != nil {
					log.Info("auth: reject RS256 token",
						zap.String("path", r.URL.Path),
						zap.String("remote", r.RemoteAddr),
						zap.Error(err),
					)
					writeAuthError(w, http.StatusUnauthorized, err.Error())
					return
				}
				claims := &Claims{Subject: sc.Sub, Role: sc.Role}
				next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
				return
			}

			// HS256 path (existing logic unchanged).
			claims, err := Verify(cfg.Secret, token)
			if err != nil {
				log.Info("auth: reject token",
					zap.String("path", r.URL.Path),
					zap.String("remote", r.RemoteAddr),
					zap.Error(err),
				)
				writeAuthError(w, http.StatusUnauthorized, err.Error())
				return
			}
			if !IsKnownRole(claims.Role) {
				writeAuthError(w, http.StatusForbidden, "unknown role on token")
				return
			}

			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
		})
	}
}


// RequireRole returns middleware that enforces the authenticated caller has
// one of the given roles. Use for endpoints with role-specific access.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := ClaimsFromContext(r.Context())
			if c == nil {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if _, ok := allowed[c.Role]; !ok {
				writeAuthError(w, http.StatusForbidden, "insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireWrite allows any role that may mutate state (admin, operator, service).
func RequireWrite() func(http.Handler) http.Handler {
	return requireCheck(canWrite, "write access required")
}

// RequireDelete allows only admins.
func RequireDelete() func(http.Handler) http.Handler {
	return requireCheck(canDelete, "delete access required")
}

func requireCheck(check func(role string) bool, msg string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c := ClaimsFromContext(r.Context())
			if c == nil {
				writeAuthError(w, http.StatusUnauthorized, "authentication required")
				return
			}
			if !check(c.Role) {
				writeAuthError(w, http.StatusForbidden, msg)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerToken extracts the token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func writeAuthError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `Bearer realm="irflow"`)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
