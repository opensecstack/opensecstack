package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
)

// newTestPool returns a pgxpool.Pool for wiring NewServer in tests.
// pgxpool.New parses the DSN and configures the pool but does not eagerly
// dial the database, so this succeeds even without a live Postgres — routes
// that actually hit the DB (e.g. /api/v1/health, which pings it) simply see
// a connection failure downstream, which is fine for the routing/middleware
// tests below that only care about auth gating and mux wiring.
func newTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://user:pass@127.0.0.1:1/nonexistent?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// baseTestConfig returns a minimally valid Config for constructing NewServer
// in tests. MeilisearchURL points at a closed local port so search.New's
// synchronous CreateIndex call fails fast (connection refused) instead of
// hanging on a DNS lookup for an empty host.
func baseTestConfig() *config.Config {
	return &config.Config{
		JWTSecret:         "test-secret",
		MeilisearchURL:    "http://127.0.0.1:1",
		NativeAuthEnabled: true,
		SiteURL:           "https://community.test",
	}
}

// TestNewServer_BuildsHandler proves NewServer wires up all dependencies
// (citadel, governance, search, mailer, channel hub, mux, middleware chain)
// without error/panic given a minimally valid config, and that the result is
// usable as an http.Handler.
func TestNewServer_BuildsHandler(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()

	handler := NewServer(cfg, pool, "test-version")
	if handler == nil {
		t.Fatal("NewServer returned nil handler")
	}

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET /robots.txt: status=%d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "User-agent") {
		t.Errorf("GET /robots.txt body = %q, want it to contain a robots directive", rec.Body.String())
	}
}

// TestNewServer_NativeAuthGate proves the nativeGate wrapper: native
// email/password endpoints are reachable when NativeAuthEnabled is true, and
// return 403 with the SSO-redirect error body when it's false — this drives
// whether sinauth SSO is the only way in, per server.go's nativeGate comment.
func TestNewServer_NativeAuthGate(t *testing.T) {
	pool := newTestPool(t)

	t.Run("enabled: reaches the login handler", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.NativeAuthEnabled = true
		handler := NewServer(cfg, pool, "v")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		req.RemoteAddr = "203.0.113.10:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		// The login handler itself will fail validation/DB lookup, but it must
		// not be the nativeGate's 403 — proves the gate lets the request through.
		if rec.Code == http.StatusForbidden {
			t.Errorf("POST /api/v1/auth/login: status=403 with NativeAuthEnabled=true, want the request to reach the handler")
		}
	})

	t.Run("disabled: 403 with SSO message", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.NativeAuthEnabled = false
		handler := NewServer(cfg, pool, "v")

		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(`{}`))
		req.RemoteAddr = "203.0.113.11:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("POST /api/v1/auth/login: status=%d, want 403 (native auth disabled)", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "sinauth") && !strings.Contains(rec.Body.String(), "SIN") {
			t.Errorf("body = %q, want it to mention SSO/SIN sign-in", rec.Body.String())
		}
	})

	t.Run("disabled: register/forgot-password/reset-password also gated", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.NativeAuthEnabled = false
		handler := NewServer(cfg, pool, "v")

		for _, path := range []string{"/api/v1/auth/register", "/api/v1/auth/forgot-password", "/api/v1/auth/reset-password"} {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`))
			req.RemoteAddr = "203.0.113.12:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("POST %s: status=%d, want 403 (native auth disabled)", path, rec.Code)
			}
		}
	})

	t.Run("disabled: OAuth endpoints stay reachable (not native)", func(t *testing.T) {
		cfg := baseTestConfig()
		cfg.NativeAuthEnabled = false
		handler := NewServer(cfg, pool, "v")

		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/github", nil)
		req.RemoteAddr = "203.0.113.13:1234"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden {
			t.Errorf("GET /api/v1/auth/github: status=403, want OAuth start to bypass the native-auth gate")
		}
	})
}

// TestNewServer_RouteRegistration exercises a representative sample of
// registered routes across every section of NewServer to prove they are
// actually reachable through the router, and that the auth-gated groups
// correctly reject unauthenticated callers before ever reaching a handler
// that would need a live DB connection.
func TestNewServer_RouteRegistration(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	handler := NewServer(cfg, pool, "v")

	cases := []struct {
		method   string
		path     string
		wantCode int
	}{
		// Auth-gated admin routes — Auth middleware rejects unauthenticated
		// callers with 401 before touching the DB.
		{http.MethodGet, "/api/v1/admin/users", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/admin/invites", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/admin/audit-log", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/admin/stats", http.StatusUnauthorized},

		// Auth-gated self-service routes.
		{http.MethodGet, "/api/v1/me/sessions", http.StatusUnauthorized},
		{http.MethodGet, "/api/v1/me/api-keys", http.StatusUnauthorized},
		{http.MethodPut, "/api/v1/users/me", http.StatusUnauthorized},
		{http.MethodPost, "/api/v1/posts", http.StatusUnauthorized},

		// Public, no-DB routes.
		{http.MethodGet, "/robots.txt", http.StatusOK},

		// Auth methods discovery is intentionally public.
		{http.MethodGet, "/api/v1/auth/methods", http.StatusOK},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, nil)
			req.RemoteAddr = "198.51.100.1:1234"
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != c.wantCode {
				t.Errorf("%s %s: status=%d, want %d (body: %s)", c.method, c.path, rec.Code, c.wantCode, rec.Body.String())
			}
		})
	}
}

// TestNewServer_UploadsStaticFileRoute proves the /uploads/ prefix is wired
// to a file server rooted at cfg.UploadDir: a request for a nonexistent file
// under that root must 404 (not panic, not fall through to the SPA
// catch-all), proving StripPrefix + FileServer are actually mounted there.
func TestNewServer_UploadsStaticFileRoute(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	cfg.UploadDir = t.TempDir()
	handler := NewServer(cfg, pool, "v")

	req := httptest.NewRequest(http.MethodGet, "/uploads/does-not-exist.png", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /uploads/does-not-exist.png: status=%d, want 404 from the file server", rec.Code)
	}
}

// TestNewServer_SPACatchAll proves an unregistered path falls through to the
// SPA catch-all ("/") instead of 404ing, since the app is a single-page app
// served from index.html for client-side routing.
func TestNewServer_SPACatchAll(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	handler := NewServer(cfg, pool, "v")

	req := httptest.NewRequest(http.MethodGet, "/this/route/does/not/exist/as/an/api/endpoint", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("GET unregistered path: status=%d, want 200 (SPA fallback)", rec.Code)
	}
}

// TestNewServer_MiddlewareChain proves the outer middleware chain
// (CORS -> MaxBodySize -> Logger -> RateLimit -> mux) is actually wired: a
// CORS preflight (OPTIONS) is answered without reaching the mux (204).
func TestNewServer_MiddlewareChain(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	cfg.AllowedOrigins = []string{"https://cors.test"}
	handler := NewServer(cfg, pool, "v")

	req := httptest.NewRequest(http.MethodOptions, "/this/route/does/not/exist", nil)
	req.Header.Set("Origin", "https://cors.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("OPTIONS preflight: status=%d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://cors.test" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://cors.test", got)
	}
}

// TestNewServer_AllowedOriginsFallback proves the CORS allowed-origins
// derivation: when AllowedOrigins is empty, SiteURL is used as the sole
// allowed origin so the browser app can still call the API cross-origin.
func TestNewServer_AllowedOriginsFallback(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	cfg.SiteURL = "https://app.community.test"
	cfg.AllowedOrigins = nil
	handler := NewServer(cfg, pool, "v")

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.Header.Set("Origin", "https://app.community.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.community.test" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q (SiteURL fallback not applied)", got, cfg.SiteURL)
	}
}

// TestNewServer_AllowedOriginsExplicit proves an explicit AllowedOrigins
// list is used as-is and is not overridden by SiteURL.
func TestNewServer_AllowedOriginsExplicit(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	cfg.SiteURL = "https://should-not-be-used.test"
	cfg.AllowedOrigins = []string{"https://explicit.test"}
	handler := NewServer(cfg, pool, "v")

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.Header.Set("Origin", "https://should-not-be-used.test")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("Access-Control-Allow-Origin = %q, want empty (origin not in explicit AllowedOrigins)", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req2.Header.Set("Origin", "https://explicit.test")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if got := rec2.Header().Get("Access-Control-Allow-Origin"); got != "https://explicit.test" {
		t.Errorf("Access-Control-Allow-Origin = %q, want https://explicit.test", got)
	}
}

// TestNewServer_MaxBodySize proves MaxBodySize is wired around the whole
// router: an oversized body on an endpoint that reads it must fail rather
// than being accepted whole. The login handler decodes JSON from the body,
// so it surfaces the MaxBytesReader error without needing a live DB for
// earlier layers to matter.
func TestNewServer_MaxBodySize(t *testing.T) {
	pool := newTestPool(t)
	cfg := baseTestConfig()
	handler := NewServer(cfg, pool, "v")

	oversized := `{"padding":"` + strings.Repeat("a", (4<<20)+1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(oversized))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "203.0.113.20:1234"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code == http.StatusOK {
		t.Errorf("oversized body: status=%d, want a failure status (MaxBodySize not enforced)", rec.Code)
	}
}
