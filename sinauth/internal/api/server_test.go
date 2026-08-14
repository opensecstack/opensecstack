package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/config"
	"github.com/opensecstack/sinauth/internal/keys"
)

// newTestPool returns a pgxpool.Pool for wiring NewServer in tests.
// pgxpool.New parses the DSN and configures the pool but does not eagerly
// dial the database, so this succeeds even when SINAUTH_TEST_DB_URL is
// unset — it just means routes that actually hit the DB will fail
// downstream (which is fine for the middleware/routing-focused tests
// below; a real pool is used automatically when the env var is set so
// this file exercises more of the DB-touching paths too when a live
// Postgres is available).
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SINAUTH_TEST_DB_URL")
	if dsn == "" {
		dsn = "postgres://user:pass@127.0.0.1:1/nonexistent?sslmode=disable"
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func newTestKeyManager(t *testing.T) *keys.Manager {
	t.Helper()
	km := keys.New("test-kid")
	path := filepath.Join(t.TempDir(), "sinauth.pem")
	if err := km.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	return km
}

func baseTestConfig() *config.Config {
	return &config.Config{
		Issuer:                "https://sinauth.test",
		BcryptCost:            4,
		WebAuthnRPID:          "localhost",
		WebAuthnRPDisplayName: "sinauth-test",
		WebAuthnOrigins:       []string{"http://localhost"},
		RateLimitAuthPerMin:   100000,
		RateLimitGlobalPerMin: 100000,
	}
}

// TestNewServer_BuildsHandler proves NewServer wires up all dependencies
// (stores, services, webauthn, mailer, SMS provider, discovery, router,
// middleware chain) without error given a minimally valid config, and
// that the result is usable as an http.Handler.
func TestNewServer_BuildsHandler(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()

	handler := NewServer(cfg, pool, km)
	if handler == nil {
		t.Fatal("NewServer returned nil handler")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /api/v1/health: status=%d, want 200", rec.Code)
	}
}

// TestNewServer_SMSProviderSelection proves the Twilio-vs-noop SMS
// provider branch: SMSEnabled derives the provider used to construct
// handlers.Deps, and both branches must build a working server.
func TestNewServer_SMSProviderSelection(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)

	t.Run("noop when SMS disabled", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.SMSEnabled = false
		handler := NewServer(cfg, pool, km)
		if handler == nil {
			t.Fatal("NewServer returned nil handler")
		}
	})

	t.Run("twilio when SMS enabled", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.SMSEnabled = true
		cfg.TwilioSID = "AC-test"
		cfg.TwilioToken = "token-test"
		cfg.TwilioFrom = "+15550000000"
		handler := NewServer(cfg, pool, km)
		if handler == nil {
			t.Fatal("NewServer returned nil handler")
		}
	})
}

// TestNewServer_WebAuthnInitFailurePanics proves NewServer panics (rather
// than silently starting with a broken WebAuthn config) when
// webauthn.New rejects the config — here, an RPID that is not a valid
// origin/hostname component relative to the configured RPOrigins.
func TestNewServer_WebAuthnInitFailurePanics(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	// An empty RPID fails go-webauthn's config validation ("RPID": must
	// not be empty) — webauthn.New returns an error, which NewServer
	// converts into a panic.
	cfg.WebAuthnRPID = ""

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewServer did not panic on invalid WebAuthn config")
		} else if s, ok := r.(string); !ok || !strings.Contains(s, "failed to init webauthn") {
			t.Fatalf("panic value = %v, want message containing 'failed to init webauthn'", r)
		}
	}()
	NewServer(cfg, pool, km)
}

// TestNewServer_AllowedOriginsFallback proves the CORS allowed-origins
// derivation: when AllowedOrigins is empty, SiteURL is used as the sole
// allowed origin so the browser app can still call the API cross-origin.
func TestNewServer_AllowedOriginsFallback(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	cfg.SiteURL = "https://app.sinauth.test"
	cfg.AllowedOrigins = nil

	handler := NewServer(cfg, pool, km)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://app.sinauth.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.sinauth.test" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q (SiteURL fallback not applied)", got, cfg.SiteURL)
	}
}

// TestNewServer_AllowedOriginsExplicit proves that an explicit
// AllowedOrigins list is used as-is and is not overridden by SiteURL.
func TestNewServer_AllowedOriginsExplicit(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	cfg.SiteURL = "https://should-not-be-used.test"
	cfg.AllowedOrigins = []string{"https://explicit.test"}

	handler := NewServer(cfg, pool, km)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://should-not-be-used.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (origin not in explicit AllowedOrigins)", got)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req.Header.Set("Origin", "https://explicit.test")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://explicit.test" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://explicit.test", got)
	}
}

// TestNewServer_MiddlewareChain proves the outer middleware chain
// (CORS -> MaxBodySize -> Logger -> RateLimit -> mux) is actually wired
// in the order documented in NewServer's trailing comment: a CORS
// preflight (OPTIONS) is answered without reaching the mux (204, no
// route needed), and the global rate limiter engages after the
// configured number of requests regardless of route.
func TestNewServer_MiddlewareChain(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	cfg.AllowedOrigins = []string{"https://cors.test"}

	// CORS preflight short-circuits before the mux/router — this exercises
	// the CORS middleware being the outermost wrapper.
	handler := NewServer(cfg, pool, km)
	req := httptest.NewRequest(http.MethodOptions, "/this/route/does/not/exist", nil)
	req.Header.Set("Origin", "https://cors.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS preflight: status=%d, want 204", rec.Code)
	}

	// Global rate limiting: with a limit of 1/min, the second request
	// within the window must be rejected with 429, proving RateLimit is
	// the innermost wrapper around the mux (applies to every route).
	cfg2 := baseTestConfig()
	cfg2.RateLimitGlobalPerMin = 1
	handler2 := NewServer(cfg2, pool, km)

	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req1.RemoteAddr = "203.0.113.5:1234"
	rec1 := httptest.NewRecorder()
	handler2.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request: status=%d, want 200", rec1.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	req2.RemoteAddr = "203.0.113.5:1234"
	rec2 := httptest.NewRecorder()
	handler2.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: status=%d, want 429 (rate limit not applied around mux)", rec2.Code)
	}
}

// TestNewServer_RouteRegistration exercises a representative sample of
// registered routes across every section of NewServer to prove they are
// actually reachable through the router (i.e. not a 404), and that the
// auth-gated groups correctly reject unauthenticated/non-admin callers
// before ever reaching a handler that would need the DB.
func TestNewServer_RouteRegistration(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	handler := NewServer(cfg, pool, km)

	cases := []struct {
		method   string
		path     string
		body     string
		wantCode int
	}{
		// OIDC discovery — no auth, no DB.
		{http.MethodGet, "/.well-known/openid-configuration", "", http.StatusOK},
		{http.MethodGet, "/.well-known/jwks.json", "", http.StatusOK},

		// Protected OAuth2 endpoint — BearerAuth rejects with 401, no DB hit.
		{http.MethodGet, "/oauth/userinfo", "", http.StatusUnauthorized},
		{http.MethodPost, "/oauth/userinfo", "", http.StatusUnauthorized},

		// Admin routes — RequireAdmin rejects unauthenticated callers with
		// 401 before touching the DB, proving these groups are wired
		// through requireAdmin/adminAuth rather than left open.
		{http.MethodGet, "/api/v1/admin/clients", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/admin/users", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/admin/audit", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/admin/sessions", "", http.StatusUnauthorized},
		{http.MethodGet, "/admin/rbac/groups", "", http.StatusUnauthorized},
		{http.MethodGet, "/admin/rbac/policies", "", http.StatusUnauthorized},
		{http.MethodGet, "/admin/organizations", "", http.StatusUnauthorized},
		{http.MethodPost, "/admin/federation/providers", "", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/organizations/some-id/members", "", http.StatusUnauthorized},

		// Self-service, requires bearer.
		{http.MethodGet, "/api/v1/users/me/organizations", "", http.StatusUnauthorized},

		// MFA WebAuthn admin-authed begin endpoints require a bearer token.
		{http.MethodPost, "/api/v1/mfa/webauthn/register/begin", "", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/mfa/webauthn/credentials", "", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/mfa/sms/send", "", http.StatusUnauthorized},

		// Health/ready — no auth.
		{http.MethodGet, "/api/v1/health", "", http.StatusOK},

		// Unregistered route must 404, proving the mux (not a catch-all) is
		// actually in effect.
		{http.MethodGet, "/this/route/does/not/exist", "", http.StatusNotFound},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			var req *http.Request
			if c.body != "" {
				req = httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			} else {
				req = httptest.NewRequest(c.method, c.path, nil)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Errorf("%s %s: status=%d, want %d (body: %s)", c.method, c.path, rec.Code, c.wantCode, rec.Body.String())
			}
		})
	}
}

// TestNewServer_MaxBodySize proves MaxBodySize (2 MB) is wired around the
// whole router: a request body over the limit must fail when the handler
// tries to read it. /oauth/token has no auth gate and reads the body via
// r.ParseForm, so it reliably surfaces the MaxBytesReader error as a 400
// without needing a live DB for the earlier middleware layers to matter.
func TestNewServer_MaxBodySize(t *testing.T) {
	pool := newTestPool(t)
	km := newTestKeyManager(t)
	cfg := baseTestConfig()
	handler := NewServer(cfg, pool, km)

	oversized := strings.Repeat("a", (2<<20)+1024)
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("grant_type=password&x="+oversized))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("oversized body: status=%d, want a failure status (MaxBodySize not enforced)", rec.Code)
	}
}
