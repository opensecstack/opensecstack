// Package auth provides JWT verification + middleware for CyberPath.
//
// Mirrors VertGuard's 3-slot rotation pattern (primary/next/previous).
// In v0.0.1 verification is a stub: in dev mode the middleware accepts
// any (or no) token and logs a warning; in prod mode it fails closed
// when no secrets are configured. Full HS256 verification will land in
// v1.0.0 alongside the auth/login + refresh endpoints.
//
// Dual-mode RS256+HS256: when a bearer token carries alg=RS256 it is
// routed to the sinauth SDK (OIDC/JWKS); all other tokens fall through
// to the HS256 path. Existing sessions are not affected.
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

// Claims is the minimal JWT claim set CyberPath verifies.
type Claims struct {
	Sub      string   `json:"sub"`
	Role     string   `json:"role"`
	TenantID string   `json:"tenant_id,omitempty"`
	Roles    []string `json:"roles,omitempty"`
	Iss      string   `json:"iss,omitempty"`
	Exp      int64    `json:"exp,omitempty"`
}

// Verifier is the interface satisfied by anything that can verify a token.
type Verifier interface {
	Verify(token string) (*Claims, error)
}

// HS256Verifier validates HS256 JWTs against one or more shared secrets,
// trying each in priority order. Empty secrets are filtered out.
type HS256Verifier struct {
	secrets [][]byte
	issuer  string
}

// NewHS256Verifier accepts secrets in priority order: primary, next, previous.
func NewHS256Verifier(secrets []string, issuer string) *HS256Verifier {
	v := &HS256Verifier{issuer: issuer}
	for _, s := range secrets {
		if s != "" {
			v.secrets = append(v.secrets, []byte(s))
		}
	}
	return v
}

// HasSecrets reports whether any secret is configured.
func (v *HS256Verifier) HasSecrets() bool { return len(v.secrets) > 0 }

// Verify parses + validates a token, returning claims on the first
// secret that produces a valid signature.
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

// DualVerifier routes RS256 tokens to sinauth and everything else to HS256.
// The sinauth client is initialised lazily (sync.Once) so startup does not
// require sinauth to be reachable; if sinauth is down the first RS256
// verification will fail with a descriptive error.
type DualVerifier struct {
	hs256      Verifier // existing HS256 path
	sinauthURL string   // e.g. "http://localhost:8100"

	once   sync.Once
	rs256  *sinauth.Client
	initErr error
}

// NewDualVerifier wraps an HS256 verifier with sinauth RS256 support.
// sinauthURL should be the sinauth issuer URL (SINAUTH_URL env default
// http://localhost:8100). If sinauthURL is empty, RS256 tokens are
// rejected immediately rather than falling through to HS256.
func NewDualVerifier(hs256 Verifier, sinauthURL string) *DualVerifier {
	return &DualVerifier{hs256: hs256, sinauthURL: sinauthURL}
}

// Verify implements Verifier. RS256 tokens are handled by sinauth;
// all other algorithms are delegated to the HS256 verifier.
func (d *DualVerifier) Verify(token string) (*Claims, error) {
	if jwtHeaderAlg(token) == "RS256" {
		return d.verifyRS256(token)
	}
	return d.hs256.Verify(token)
}

func (d *DualVerifier) verifyRS256(token string) (*Claims, error) {
	if d.sinauthURL == "" {
		return nil, errors.New("auth: sinauth URL not configured for RS256 tokens")
	}
	d.once.Do(func() {
		d.rs256, d.initErr = sinauth.New(d.sinauthURL)
	})
	if d.initErr != nil {
		return nil, errors.New("auth: sinauth client unavailable: " + d.initErr.Error())
	}
	sc, err := d.rs256.VerifyToken(context.Background(), token)
	if err != nil {
		return nil, err
	}
	return &Claims{
		Sub:  sc.Sub,
		Role: sc.Role,
	}, nil
}

type ctxKey struct{}

// FromContext returns the claims previously stashed by Middleware, if any.
func FromContext(ctx context.Context) (*Claims, bool) {
	c, ok := ctx.Value(ctxKey{}).(*Claims)
	return c, ok
}

// WithClaims stashes claims in ctx. Used by tests to inject auth context
// without going through the full JWT middleware stack.
func WithClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, ctxKey{}, c)
}

// Middleware reads the bearer token, verifies it, and stashes claims in
// the request context. In devMode (or when no secrets are configured)
// missing/invalid tokens are tolerated with a warning so local dev does
// not require a secret. In production with secrets configured, missing
// or bad tokens fail closed with 401.
func Middleware(v Verifier, devMode bool, log *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tok := bearer(r)
			if tok == "" {
				if devMode {
					if log != nil {
						log.Warn().Str("path", r.URL.Path).Msg("auth: missing token (dev mode — allowing)")
					}
					next.ServeHTTP(w, r)
					return
				}
				writeAuthErr(w, "missing_token", "authorization required")
				return
			}
			claims, err := v.Verify(tok)
			if err != nil {
				if devMode {
					if log != nil {
						log.Warn().Err(err).Msg("auth: token invalid (dev mode — allowing)")
					}
					next.ServeHTTP(w, r)
					return
				}
				writeAuthErr(w, "invalid_token", err.Error())
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return strings.TrimSpace(h)
}

func writeAuthErr(w http.ResponseWriter, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
