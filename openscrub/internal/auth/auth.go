// Package auth — JWT (HS256 + RS256) verification + RBAC for the OpenScrub
// HTTP API. Mirrors the cyberpath/irflow pattern: 3-slot rotation
// (primary/next/previous), middleware sets *Claims in the request
// context, RBAC.RequireRole sits one layer above.
//
// Dual-mode: tokens with alg=RS256 are verified via the sinauth SDK;
// all other tokens fall through to the existing HS256 path so existing
// sessions are never broken.
package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/opensecstack/sdk/go/sinauth"
	"github.com/rs/zerolog"
)

// Canonical role identifiers (5-role model from the prompt).
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
	RoleAnalyst  = "analyst"
	RoleReadOnly = "readonly"
)

// AllRoles returns the full canonical set; useful for tests + docs.
func AllRoles() []string {
	return []string{RoleAdmin, RoleOperator, RoleAuditor, RoleAnalyst, RoleReadOnly}
}

// Claims is the minimal claim set OpenScrub verifies.
type Claims struct {
	Sub   string   `json:"sub"`
	Role  string   `json:"role"`
	Roles []string `json:"roles,omitempty"`
	Iss   string   `json:"iss,omitempty"`
	Exp   int64    `json:"exp,omitempty"`
}

// Verifier verifies a token string.
type Verifier interface {
	Verify(token string) (*Claims, error)
}

// HS256Verifier accepts a list of secrets in priority order
// (primary, next, previous). Empty entries are filtered.
type HS256Verifier struct {
	secrets [][]byte
	issuer  string
}

// NewHS256Verifier builds a verifier from a slice of secret strings.
func NewHS256Verifier(secrets []string, issuer string) *HS256Verifier {
	v := &HS256Verifier{issuer: issuer}
	for _, s := range secrets {
		if s != "" {
			v.secrets = append(v.secrets, []byte(s))
		}
	}
	return v
}

// HasSecrets reports whether at least one secret was configured.
func (v *HS256Verifier) HasSecrets() bool { return len(v.secrets) > 0 }

// Verify parses and validates a token, returning the first secret-match.
func (v *HS256Verifier) Verify(token string) (*Claims, error) {
	if token == "" {
		return nil, errors.New("auth: token empty")
	}
	if len(v.secrets) == 0 {
		return nil, errors.New("auth: no secrets configured")
	}
	var lastErr error
	for _, secret := range v.secrets {
		parsed, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("auth: only HS256 supported")
			}
			return secret, nil
		})
		if err != nil {
			lastErr = err
			continue
		}
		mc, ok := parsed.Claims.(jwt.MapClaims)
		if !ok || !parsed.Valid {
			lastErr = errors.New("auth: invalid claims")
			continue
		}
		c, err := mapToClaims(mc)
		if err != nil {
			lastErr = err
			continue
		}
		if v.issuer != "" && c.Iss != "" && c.Iss != v.issuer {
			lastErr = errors.New("auth: issuer mismatch")
			continue
		}
		return c, nil
	}
	return nil, lastErr
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

// DualVerifier implements Verifier. RS256 tokens are routed to the sinauth
// SDK; everything else falls through to the wrapped HS256Verifier.
// The sinauth.Client is initialised lazily (sync.Once) so startup never
// fails if the sinauth issuer is temporarily unreachable.
type DualVerifier struct {
	hs256      *HS256Verifier
	sinauthURL string

	once   sync.Once
	client *sinauth.Client
	initErr error
}

// NewDualVerifier wraps an existing HS256Verifier with RS256/sinauth support.
func NewDualVerifier(hs *HS256Verifier, sinauthURL string) *DualVerifier {
	return &DualVerifier{hs256: hs, sinauthURL: sinauthURL}
}

func (d *DualVerifier) sinClient() (*sinauth.Client, error) {
	d.once.Do(func() {
		d.client, d.initErr = sinauth.New(d.sinauthURL)
	})
	return d.client, d.initErr
}

// Verify implements Verifier. RS256 → sinauth; otherwise → HS256.
func (d *DualVerifier) Verify(token string) (*Claims, error) {
	if jwtAlg(token) == "RS256" {
		client, err := d.sinClient()
		if err != nil {
			return nil, errors.New("auth: sinauth client unavailable: " + err.Error())
		}
		sc, err := client.VerifyToken(context.Background(), token)
		if err != nil {
			return nil, err
		}
		role := sc.Role
		if role == "" && len(sc.ClientRoles) > 0 {
			role = sc.ClientRoles[0]
		}
		return &Claims{
			Sub:  sc.Sub,
			Role: role,
			Iss:  sc.Issuer,
		}, nil
	}
	return d.hs256.Verify(token)
}

func mapToClaims(m jwt.MapClaims) (*Claims, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var c Claims
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

type ctxKey struct{}

// WithClaims stashes claims in ctx. Used by tests.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// FromContext returns claims previously stashed by Middleware (or WithClaims).
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// devClaims is the synthetic identity Middleware injects in dev mode
// so RequireRole-protected routes work without a real JWT. Centralised
// here so the dev bypass is greppable and policy-uniform.
func devClaims() *Claims {
	return &Claims{Sub: "dev-anonymous", Role: RoleAdmin}
}

// HasRole — single-string Role first, then optional Roles slice.
func HasRole(c *Claims, role string) bool {
	if c == nil || role == "" {
		return false
	}
	if c.Role == role {
		return true
	}
	for _, r := range c.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Middleware verifies bearer tokens. In dev mode (or when no secrets
// configured), missing/invalid tokens are tolerated with a warning.
func Middleware(v Verifier, devMode bool, log *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := bearer(r)
			if tok == "" {
				if devMode {
					if log != nil {
						log.Warn().Str("path", r.URL.Path).Msg("auth: missing token (dev mode — injecting synthetic admin claim)")
					}
					ctx := context.WithValue(r.Context(), ctxKey{}, devClaims())
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeAuthErr(w, http.StatusUnauthorized, "missing_token", "authorization required")
				return
			}
			claims, err := v.Verify(tok)
			if err != nil {
				if devMode {
					if log != nil {
						log.Warn().Err(err).Msg("auth: token invalid (dev mode — injecting synthetic admin claim)")
					}
					ctx := context.WithValue(r.Context(), ctxKey{}, devClaims())
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				writeAuthErr(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole admits the request only when the caller holds at least
// one of the supplied roles.
//
// No claims in context → 401. The previous implementation auto-admitted
// in this case to keep unit tests easy, but that is a privilege-
// escalation footgun: any path that fails to wire the auth middleware
// silently grants admin. Dev-mode is the responsibility of
// auth.Middleware (which can inject anonymous claims with a wide
// role); RequireRole always fails closed.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, ok := FromContext(r.Context())
			if !ok || c == nil {
				writeAuthErr(w, http.StatusUnauthorized, "unauthenticated", "authentication required")
				return
			}
			for _, role := range roles {
				if HasRole(c, role) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeAuthErr(w, http.StatusForbidden, "forbidden", "insufficient role")
		})
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	// Strict scheme matching: anything other than "Bearer <token>" is
	// rejected. The previous fallback (return the raw header when no
	// scheme prefix matched) silently accepted Basic / API-key
	// schemes — Verify() then failed with a misleading "invalid
	// claims" error instead of "wrong scheme".
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

func writeAuthErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
