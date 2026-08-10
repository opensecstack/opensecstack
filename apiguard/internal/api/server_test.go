package api

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
	"github.com/opensecstack/apiguard/internal/scanner"
)

// newTestServer builds a real *Server via NewServer using an unreachable
// Postgres pool (nil) and an in-memory rate limiter backend (empty Redis
// URL), so no network dependency is required to exercise NewServer,
// setupMiddleware, registerRoutes, and Router.
//
// The caller must call the returned cleanup function to stop the background
// audit worker goroutine and all rate limiters started by NewServer.
func newTestServer(t *testing.T) (*Server, func()) {
	t.Helper()

	cfg := &config.Config{
		Port: 0, // unused unless Start() is called
	}
	database := &db.DB{} // Pool is nil; fine as long as no query is executed
	sc := scanner.New(&cfg.Scanner, zerolog.Nop())

	s := NewServer(cfg, database, sc)

	cleanup := func() {
		if s.stopAuditWorker != nil {
			s.stopAuditWorker()
		}
		s.globalLimiter.Stop()
		s.authLimiter.Stop()
		s.scanLimiter.Stop()
		s.reportLimiter.Stop()
		s.refreshLimiter.Stop()
		s.apiKeyLimiter.Stop()
		if s.tokenDenylist != nil {
			s.tokenDenylist.Stop()
		}
	}

	return s, cleanup
}

// TestNewServer_ConstructsWithAllDependencies verifies that NewServer wires
// up a non-nil router, stores the configured port, and does not panic when
// given a DB handle with no live connection pool (the pool is never touched
// until a request actually executes a query).
func TestNewServer_ConstructsWithAllDependencies(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.router == nil {
		t.Fatal("NewServer did not initialise the router")
	}
	if s.metrics == nil {
		t.Fatal("NewServer did not initialise the metrics collector")
	}
	if s.secretProvider == nil {
		t.Fatal("NewServer did not initialise the secret provider")
	}
	if s.tokenDenylist == nil {
		t.Fatal("NewServer did not initialise the token denylist")
	}
	if s.citadel == nil {
		t.Fatal("NewServer did not initialise the citadel client")
	}
	if s.scansHandler == nil {
		t.Fatal("registerRoutes did not store the scans handler for WaitScans()")
	}
}

// TestNewServer_SinauthDisabledByDefault verifies that when
// cfg.Auth.SinauthURL is empty (the default), no sinauth client is created —
// only HS256 tokens are accepted.
func TestNewServer_SinauthDisabledByDefault(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	if s.sinauthClient != nil {
		t.Error("expected sinauthClient to be nil when SinauthURL is unset")
	}
}

// TestNewServer_SinauthInvalidURLIsNonFatal verifies that a malformed
// sinauth_url does not stop server construction — it logs a warning and
// continues without RS256 support.
func TestNewServer_SinauthInvalidURLIsNonFatal(t *testing.T) {
	cfg := &config.Config{}
	cfg.Auth.SinauthURL = "://not-a-valid-url"
	database := &db.DB{}
	sc := scanner.New(&cfg.Scanner, zerolog.Nop())

	s := NewServer(cfg, database, sc)
	defer func() {
		if s.stopAuditWorker != nil {
			s.stopAuditWorker()
		}
		s.globalLimiter.Stop()
		s.authLimiter.Stop()
		s.scanLimiter.Stop()
		s.reportLimiter.Stop()
		s.refreshLimiter.Stop()
		s.apiKeyLimiter.Stop()
		s.tokenDenylist.Stop()
	}()

	if s == nil {
		t.Fatal("NewServer returned nil for an invalid sinauth_url")
	}
}

// TestServer_Router returns the same router that requests are actually
// served on, and it must be reachable end-to-end (through the full
// middleware chain registered by setupMiddleware and the routes registered
// by registerRoutes).
func TestServer_Router(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	r := s.Router()
	if r == nil {
		t.Fatal("Router() returned nil")
	}
	if r != s.router {
		t.Fatal("Router() did not return the server's internal router")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GET /api/v1/health through Router(): got status %d, want %d", rr.Code, http.StatusOK)
	}
}

// TestServer_SetupMiddleware_SecurityHeaders verifies that the middleware
// chain wired by setupMiddleware actually runs on every request — using the
// presence of a security header set by middleware.SecurityHeaders as the
// probe, since that middleware has no other externally visible effect.
func TestServer_SetupMiddleware_SecurityHeaders(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if rr.Header().Get("X-Content-Type-Options") == "" {
		t.Error("expected SecurityHeaders middleware to set X-Content-Type-Options")
	}
	// chimw.RequestID / correlation ID middleware should stamp a request id
	// header via the logger chain; at minimum the request must not fail.
	if rr.Code == http.StatusInternalServerError {
		t.Errorf("unexpected 500 from middleware chain: %s", rr.Body.String())
	}
}

// TestServer_SetupMiddleware_GlobalRateLimiterDefault verifies that when
// cfg.Scanner.RateLimit is unset (<= 0), setupMiddleware falls back to the
// documented default of 120 requests/minute rather than leaving the limiter
// unconfigured (rate 0, which would reject everything).
func TestServer_SetupMiddleware_GlobalRateLimiterDefault(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	if s.globalLimiter == nil {
		t.Fatal("globalLimiter was not initialised")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)

	if rr.Code == http.StatusTooManyRequests {
		t.Error("first request was rate-limited; default rate limit must not be zero")
	}
}

// TestServer_RegisterRoutes_LimitersConfigured verifies that registerRoutes
// creates all five per-route limiters (auth/scan/report/refresh/apikey) so
// they can be stopped on shutdown, and that the underlying routes are
// actually reachable through the router registered by RegisterRoutes.
func TestServer_RegisterRoutes_LimitersConfigured(t *testing.T) {
	s, cleanup := newTestServer(t)
	defer cleanup()

	if s.authLimiter == nil || s.scanLimiter == nil || s.reportLimiter == nil ||
		s.refreshLimiter == nil || s.apiKeyLimiter == nil {
		t.Fatal("registerRoutes did not initialise all per-route limiters")
	}

	// Protected route must require auth (proves RegisterRoutes wired the JWT
	// middleware using the limiters/secret provider/denylist constructed by
	// registerRoutes).
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scans", nil)
	rr := httptest.NewRecorder()
	s.router.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("GET /api/v1/scans without auth: got %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

// TestServer_Start_ListenError verifies that Start() surfaces a listen error
// (e.g. the configured port is already bound) instead of blocking forever or
// panicking. This exercises the serveErr branch of Start()'s select without
// depending on OS signal delivery, which is not reliably testable across
// platforms.
func TestServer_Start_ListenError(t *testing.T) {
	// Reserve a wildcard-address TCP port — the same address form Start()
	// binds to (":<port>") — so the server's ListenAndServe fails immediately
	// with "address already in use" rather than racing on address scope.
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("failed to reserve a port: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)

	s, cleanup := newTestServer(t)
	defer cleanup()
	s.port = addr.Port

	err = s.Start()
	if err == nil {
		t.Fatal("expected Start() to return an error when the port is already in use")
	}
}
