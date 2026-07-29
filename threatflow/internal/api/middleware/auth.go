// Package middleware hosts ThreatFlow's HTTP middleware: JWT auth, role
// enforcement, and per-IP rate limiting.
package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/opensecstack/sdk/go/sinauth"
	"github.com/opensecstack/threatflow/internal/auth"
)

type ctxKey int

const identityKey ctxKey = 1

// Identity extracts the authenticated identity from the request context. The
// returned pointer is nil when the request is unauthenticated (public route).
func Identity(r *http.Request) *auth.Identity {
	v, _ := r.Context().Value(identityKey).(*auth.Identity)
	return v
}

// ContextWithIdentity stashes id in ctx the same way RequireAuth/RequireRole
// do after a successful verification. Exported for handler-level tests that
// need to exercise CITADEL Kerkese construction under a specific identity
// without standing up a full auth middleware chain.
func ContextWithIdentity(ctx context.Context, id *auth.Identity) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

// sinauthHolder wraps lazy sinauth client initialisation. The client is
// created the first time an RS256 token is seen so startup never fails
// if the issuer is temporarily unreachable.
type sinauthHolder struct {
	url     string
	once    sync.Once
	client  *sinauth.Client
	initErr error
}

func (h *sinauthHolder) get() (*sinauth.Client, error) {
	h.once.Do(func() {
		h.client, h.initErr = sinauth.New(h.url)
	})
	return h.client, h.initErr
}

// RequireAuth wraps the next handler so it only fires when the request
// carries a valid Bearer JWT. On failure it writes a 401 JSON response.
func RequireAuth(svc *auth.Service) func(http.Handler) http.Handler {
	return RequireAuthWithSinauth(svc, "http://localhost:8100")
}

// RequireAuthWithSinauth is RequireAuth with a configurable sinauth issuer URL.
// RS256 Bearer tokens are verified via sinauth; HS256 tokens fall back to svc.
func RequireAuthWithSinauth(svc *auth.Service, sinauthURL string) func(http.Handler) http.Handler {
	sin := &sinauthHolder{url: sinauthURL}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := identityFromRequestDual(svc, sin, r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			ctx := context.WithValue(r.Context(), identityKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole combines authentication with role enforcement.
func RequireRole(svc *auth.Service, required auth.Role) func(http.Handler) http.Handler {
	return RequireRoleWithSinauth(svc, required, "http://localhost:8100")
}

// RequireRoleWithSinauth is RequireRole with a configurable sinauth issuer URL.
func RequireRoleWithSinauth(svc *auth.Service, required auth.Role, sinauthURL string) func(http.Handler) http.Handler {
	sin := &sinauthHolder{url: sinauthURL}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id, err := identityFromRequestDual(svc, sin, r)
			if err != nil {
				writeJSONError(w, http.StatusUnauthorized, "unauthorized")
				return
			}
			if !auth.AtLeast(id.Role, required) {
				writeJSONError(w, http.StatusForbidden, "forbidden: requires "+string(required))
				return
			}
			ctx := context.WithValue(r.Context(), identityKey, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// jwtAlg returns the alg field from the JWT header without verifying the
// signature. Returns "" on any parse error.
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

// identityFromRequestDual pulls a Bearer token out of Authorization and
// verifies it. RS256 tokens are routed to sinauth; everything else uses svc.
func identityFromRequestDual(svc *auth.Service, sin *sinauthHolder, r *http.Request) (*auth.Identity, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, auth.ErrUnauthorized
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return nil, auth.ErrUnauthorized
	}
	token := strings.TrimSpace(parts[1])

	if jwtAlg(token) == "RS256" {
		client, err := sin.get()
		if err != nil {
			return nil, errors.New("sinauth unavailable: " + err.Error())
		}
		sc, err := client.VerifyToken(r.Context(), token)
		if err != nil {
			return nil, auth.ErrUnauthorized
		}
		role := auth.Role(sc.Role)
		if role == "" && len(sc.ClientRoles) > 0 {
			role = auth.Role(sc.ClientRoles[0])
		}
		return &auth.Identity{
			Subject: sc.Sub,
			Role:    role,
			Source:  "sinauth",
		}, nil
	}

	return svc.VerifyToken(token)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
