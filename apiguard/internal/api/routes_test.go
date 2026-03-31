package api

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/handlers"
	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
)

// newTestRouter builds a chi router with all routes registered using minimal
// zero-value dependencies. The caller is responsible for stopping the rate
// limiters via the returned cleanup function.
func newTestRouter(t *testing.T) (http.Handler, func()) {
	t.Helper()

	logger := zerolog.Nop()
	cfg := &config.Config{}

	healthH := handlers.NewHealth(logger)
	authH := handlers.NewAuth(logger, cfg)
	scansH := handlers.NewScans(logger, nil, nil, context.Background())
	findingsH := handlers.NewFindings(logger, nil)
	specsH := handlers.NewSpecs(logger, "")
	auditH := handlers.NewAudit(logger, nil)
	apiKeysH := handlers.NewAPIKeys(logger, nil, nil, cfg)
	inventoryH := handlers.NewInventory(logger, nil)

	authLimiter := middleware.NewRateLimiter(100)
	scanLimiter := middleware.NewRateLimiter(100)
	reportLimiter := middleware.NewRateLimiter(100)
	refreshLimiter := middleware.NewRateLimiter(100)
	apiKeyLimiter := middleware.NewRateLimiter(100)

	metrics := middleware.NewMetricsCollector()

	r := chi.NewRouter()
	RegisterRoutes(
		r,
		healthH,
		authH,
		scansH,
		findingsH,
		specsH,
		auditH,
		apiKeysH,
		inventoryH,
		metrics,
		cfg,
		authLimiter,
		scanLimiter,
		reportLimiter,
		refreshLimiter,
		apiKeyLimiter,
		[]*net.IPNet{},
	)

	cleanup := func() {
		authLimiter.Stop()
		scanLimiter.Stop()
		reportLimiter.Stop()
		refreshLimiter.Stop()
		apiKeyLimiter.Stop()
	}

	return r, cleanup
}

// doRequest is a helper to make a test request against the router.
func doRequest(t *testing.T, r http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

// TestRegisteredRoutes_PublicEndpoints verifies that public endpoints are
// reachable (non-404) and return the expected successful status codes.
func TestRegisteredRoutes_PublicEndpoints(t *testing.T) {
	r, cleanup := newTestRouter(t)
	t.Cleanup(cleanup)

	tests := []struct {
		name     string
		method   string
		path     string
		wantCode int
	}{
		{"health endpoint returns 200", http.MethodGet, "/api/v1/health", http.StatusOK},
		{"version endpoint returns 200", http.MethodGet, "/api/v1/version", http.StatusOK},
		{"openapi spec returns 200", http.MethodGet, "/api/v1/openapi.json", http.StatusOK},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(t, r, tc.method, tc.path)
			if rr.Code != tc.wantCode {
				t.Errorf("%s %s: got status %d, want %d", tc.method, tc.path, rr.Code, tc.wantCode)
			}
		})
	}
}

// TestRegisteredRoutes_NotFound verifies that requests to unregistered paths
// return 404.
func TestRegisteredRoutes_NotFound(t *testing.T) {
	r, cleanup := newTestRouter(t)
	t.Cleanup(cleanup)

	rr := doRequest(t, r, http.MethodGet, "/api/v1/nonexistent")
	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /api/v1/nonexistent: got status %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// TestRegisteredRoutes_MethodNotAllowed verifies that using the wrong HTTP
// method on a registered route returns 405.
func TestRegisteredRoutes_MethodNotAllowed(t *testing.T) {
	r, cleanup := newTestRouter(t)
	t.Cleanup(cleanup)

	rr := doRequest(t, r, http.MethodPost, "/api/v1/health")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /api/v1/health: got status %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

// TestRegisteredRoutes_ProtectedEndpointsRequireAuth verifies that protected
// routes reject unauthenticated requests with 401.
func TestRegisteredRoutes_ProtectedEndpointsRequireAuth(t *testing.T) {
	r, cleanup := newTestRouter(t)
	t.Cleanup(cleanup)

	tests := []struct {
		name   string
		method string
		path   string
	}{
		{"scans list", http.MethodGet, "/api/v1/scans"},
		{"findings list", http.MethodGet, "/api/v1/findings"},
		{"audit log", http.MethodGet, "/api/v1/audit"},
		{"api-keys list", http.MethodGet, "/api/v1/api-keys/"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr := doRequest(t, r, tc.method, tc.path)
			if rr.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: got status %d, want %d (unauthenticated request should be rejected)",
					tc.method, tc.path, rr.Code, http.StatusUnauthorized)
			}
		})
	}
}

// TestRegisteredRoutes_CORSPreflightHandled verifies that OPTIONS requests to
// registered routes are handled by the router (not returning 404).
func TestRegisteredRoutes_CORSPreflightHandled(t *testing.T) {
	r, cleanup := newTestRouter(t)
	t.Cleanup(cleanup)

	rr := doRequest(t, r, http.MethodOptions, "/api/v1/health")
	if rr.Code == http.StatusNotFound {
		t.Errorf("OPTIONS /api/v1/health: got 404, expected the route to be handled (CORS preflight)")
	}
}
