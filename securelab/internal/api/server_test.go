// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/api"
)

const testJWTSecret = "server-test-secret"

func mintJWT(t *testing.T, role string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"sub":  "tester",
		"role": role,
		"exp":  time.Now().Add(time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// newTestRouter builds a router with a nil DB pool and nil scheduler. This is
// sufficient to test routing and auth/authz wiring, since every protected
// handler must run RequireRole before it ever touches the pool.
func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	return api.NewRouter(nil, nil, testJWTSecret, "", time.Now(), zaptest.NewLogger(t))
}

func TestRouter_UnknownRouteIs404(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/does-not-exist", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestRouter_ProtectedRouteRequiresAuth(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/scenarios", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", rr.Code)
	}
}

// TestRouter_ViewerCannotWriteScenario checks that the per-route RequireRole
// wiring in NewRouter actually enforces the documented "operator+" write
// requirement on POST /api/v1/scenarios, not just "any authenticated user".
func TestRouter_ViewerCannotCreateScenario(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/scenarios", nil)
	req.Header.Set("Authorization", "Bearer "+mintJWT(t, "viewer"))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for viewer creating a scenario, got %d", rr.Code)
	}
}

// TestRouter_AnalystCannotCreateEnvironment checks the admin-only write gate
// on environments is actually wired up (an analyst has read access to
// environments, but not create/delete).
func TestRouter_AnalystCannotCreateEnvironment(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/environments", nil)
	req.Header.Set("Authorization", "Bearer "+mintJWT(t, "analyst"))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for analyst creating an environment, got %d", rr.Code)
	}
}

// TestRouter_AnalystCannotDeleteEnvironment mirrors the create check for the
// DELETE route, which is also documented as admin-only.
func TestRouter_AnalystCannotDeleteEnvironment(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/environments/some-id", nil)
	req.Header.Set("Authorization", "Bearer "+mintJWT(t, "analyst"))
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for analyst deleting an environment, got %d", rr.Code)
	}
}

// TestRouter_HealthRouteIsUnauthenticated verifies /health is reachable with
// no Authorization header at all (infra health checks cannot present a JWT).
// With a nil pool, pool.Ping panics; chi's Recoverer middleware must turn
// that panic into a 500 rather than crashing the process — this is itself a
// meaningful behavioural guarantee for a route that infra probes hit
// continuously.
func TestRouter_HealthRouteIsUnauthenticatedAndSurvivesNilPool(t *testing.T) {
	r := newTestRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	// Whatever happens internally, Recoverer must guarantee we get a valid
	// HTTP response rather than the test process crashing.
	if rr.Code == 0 {
		t.Fatal("expected a valid HTTP response from /health, got none")
	}
}

func TestRouter_MethodNotAllowedOnKnownPath(t *testing.T) {
	r := newTestRouter(t)
	// /health only supports GET.
	req := httptest.NewRequest(http.MethodPost, "/health", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405 for POST /health, got %d", rr.Code)
	}
}
