package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/opencsirt/internal/api/handlers"
	"github.com/opensecstack/opencsirt/internal/auth"
)

func newTestAuthenticator(t *testing.T) *auth.Authenticator {
	t.Helper()
	a, err := auth.New([][]byte{[]byte("test-secret")}, "opencsirt-test", time.Hour, "", "")
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	return a
}

// TestRouter_PublicEndpointsBypassAuth proves /health and /auth/login are
// reachable without a bearer token, since Router registers them before the
// authenticated r.Group.
func TestRouter_PublicEndpointsBypassAuth(t *testing.T) {
	d := Deps{
		Auth:        newTestAuthenticator(t),
		AuthHandler: &handlers.Auth{Authenticator: newTestAuthenticator(t)},
		Health:      &handlers.Health{StartedAt: time.Now()},
	}
	r := Router(d)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /health without auth = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

// TestRouter_ProtectedEndpointsRequireAuth proves every route registered
// inside the authenticated r.Group actually sits behind d.Auth.Middleware —
// a route accidentally added outside that group would return something
// other than 401 here.
func TestRouter_ProtectedEndpointsRequireAuth(t *testing.T) {
	d := Deps{
		Auth:         newTestAuthenticator(t),
		AuthHandler:  &handlers.Auth{Authenticator: newTestAuthenticator(t)},
		Health:       &handlers.Health{StartedAt: time.Now()},
		Snapshot:     &handlers.Snapshot{},
		Constituency: &handlers.Constituency{},
		Incident:     &handlers.Incident{},
		Advisory:     &handlers.Advisory{},
		Peers:        &handlers.Peers{},
	}
	r := Router(d)

	protected := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/metrics/snapshot"},
		{http.MethodGet, "/api/v1/constituencies"},
		{http.MethodPost, "/api/v1/constituencies"},
		{http.MethodGet, "/api/v1/incidents"},
		{http.MethodPost, "/api/v1/incidents"},
		{http.MethodGet, "/api/v1/advisories"},
		{http.MethodPost, "/api/v1/advisories"},
		{http.MethodGet, "/api/v1/peers"},
	}
	for _, tc := range protected {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s %s without a bearer token = %d, want 401; body=%s", tc.method, tc.path, w.Code, w.Body.String())
			}
		})
	}
}

// TestRouter_PeersRoutesOmittedWhenPeersNil proves the `if d.Peers != nil`
// guard actually prevents route registration — the previously
// 0%-covered branch of Router. A request to /peers with no Peers handler
// wired must 404, not panic on a nil handler and not silently succeed.
func TestRouter_PeersRoutesOmittedWhenPeersNil(t *testing.T) {
	d := Deps{
		Auth:        newTestAuthenticator(t),
		AuthHandler: &handlers.Auth{Authenticator: newTestAuthenticator(t)},
		Health:      &handlers.Health{StartedAt: time.Now()},
		Peers:       nil,
	}
	r := Router(d)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/peers", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("GET /peers with Peers=nil = %d, want 404 (route should not be registered); body=%s", w.Code, w.Body.String())
	}
}

// TestRouter_WebhookRoutesOmittedWhenNil mirrors the Peers case for the
// two optional webhook handlers.
func TestRouter_WebhookRoutesOmittedWhenNil(t *testing.T) {
	d := Deps{
		Auth:        newTestAuthenticator(t),
		AuthHandler: &handlers.Auth{Authenticator: newTestAuthenticator(t)},
		Health:      &handlers.Health{StartedAt: time.Now()},
	}
	r := Router(d)

	for _, path := range []string{
		"/api/v1/integrations/irflow/incident",
		"/api/v1/integrations/taranis/osint",
	} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("POST %s with the webhook handler nil = %d, want 404", path, w.Code)
		}
	}
}

// TestRouter_WebhookRoutesRegisteredWhenSet proves a non-nil webhook
// handler is actually wired to its path and invoked (not just "not
// missing").
func TestRouter_WebhookRoutesRegisteredWhenSet(t *testing.T) {
	called := false
	webhook := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	d := Deps{
		Auth:          newTestAuthenticator(t),
		AuthHandler:   &handlers.Auth{Authenticator: newTestAuthenticator(t)},
		Health:        &handlers.Health{StartedAt: time.Now()},
		IRFlowWebhook: webhook,
	}
	r := Router(d)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/integrations/irflow/incident", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !called {
		t.Fatal("IRFlowWebhook handler was never invoked")
	}
	if w.Code != http.StatusTeapot {
		t.Fatalf("code = %d, want 418 (from the injected handler)", w.Code)
	}
}
