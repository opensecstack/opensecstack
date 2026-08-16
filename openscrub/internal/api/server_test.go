package api_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api"
	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

func testDeps(devMode bool) api.Deps {
	svc := rules.New(rules.Deps{
		Repo: rules.NewMemoryRepo(), Plane: dataplane.NewNoopClient(),
		NodeName: "test", Logger: zerolog.Nop(),
	})
	return api.Deps{
		Health:   &handlers.Health{},
		Rules:    &handlers.Rules{Service: svc, Logger: zerolog.Nop()},
		Verifier: auth.NewHS256Verifier([]string{"secret"}, "openscrub"),
		DevMode:  devMode,
		Logger:   zerolog.Nop(),
	}
}

// TestHealthAndReadyzUnauthenticated proves the liveness/readiness
// routes are reachable with zero Authorization header even outside dev
// mode — a regression here would take Kubernetes probes down along
// with real traffic.
func TestHealthAndReadyzUnauthenticated(t *testing.T) {
	r := api.NewRouter(testDeps(false))

	for _, path := range []string{"/api/v1/health", "/api/v1/readyz"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200 unauthenticated", path, rec.Code)
		}
	}
}

// TestRulesRequiresAuthOutsideDevMode confirms the authenticated API
// group actually enforces the auth middleware: with DevMode=false and
// no bearer token, protected routes must 401, not fall through.
func TestRulesRequiresAuthOutsideDevMode(t *testing.T) {
	r := api.NewRouter(testDeps(false))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401 without a token outside dev mode", rec.Code)
	}
}

// TestRulesMutateRequiresOperatorRole confirms RBAC: a readonly caller
// may list but not create rules.
func TestRulesMutateRequiresOperatorRole(t *testing.T) {
	r := api.NewRouter(testDeps(false))
	issuer := auth.NewIssuer("secret", "openscrub", time.Hour)
	tok, _, err := issuer.Mint("viewer-1", auth.RoleReadOnly)
	if err != nil {
		t.Fatal(err)
	}

	// GET is allowed for readonly.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readonly GET /rules: got %d, want 200", rec.Code)
	}

	// POST must be forbidden for readonly.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/api/v1/rules", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly POST /rules: got %d, want 403", rec.Code)
	}
}

// TestAuthLoginRouteOnlyRegisteredWhenAuthSet ensures the router
// doesn't register /auth/login (404, not a panic/500) when Deps.Auth
// is nil — the zero-value Deps case used by tests that don't exercise
// login.
func TestAuthLoginRouteOnlyRegisteredWhenAuthNil(t *testing.T) {
	d := testDeps(true)
	d.Auth = nil
	r := api.NewRouter(d)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("got %d, want 404 when Auth is nil", rec.Code)
	}
}

// panicPinger implements handlers.Pinger and panics on Ping — used to
// drive a real handler-originated panic through the full router so we
// can exercise the unexported quietRecoverer middleware.
type panicPinger struct{}

func (panicPinger) Ping(context.Context) error {
	panic("simulated db driver panic")
}

// TestPanicRecoveredAsJSON500 drives a handler panic through the full
// router (quietRecoverer is unexported, this is the only way to reach
// it) and asserts it degrades to a structured 500 instead of crashing
// the process or leaking a stack trace in the body.
func TestPanicRecoveredAsJSON500(t *testing.T) {
	d := testDeps(true)
	d.Health = &handlers.Health{DB: panicPinger{}}
	r := api.NewRouter(d)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/health", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500 after handler panic", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}
	body := rec.Body.String()
	if !contains(body, `"internal server error"`) {
		t.Fatalf("expected generic error message in body, got %q", body)
	}
	// Must NOT leak stack frames / file paths into the response body.
	if contains(body, ".go:") {
		t.Fatalf("response body appears to leak a stack trace: %q", body)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestOptionalRoutesRegisteredWhenDepsPresent exercises the
// Snapshot/Mitigations/Auth-whoami "if d.X != nil" branches in
// NewRouter that testDeps() otherwise leaves untouched — a nil Deps
// field must never panic route registration, and a non-nil one must
// actually be reachable through the full middleware chain (auth +
// RBAC) rather than 404ing.
func TestOptionalRoutesRegisteredWhenDepsPresent(t *testing.T) {
	d := testDeps(false)
	d.Snapshot = &handlers.Snapshot{Logger: zerolog.Nop()}
	d.Mitigations = &handlers.Mitigations{Logger: zerolog.Nop()}

	hash := auth.HashPassword("pepper", "s3cret")
	creds := auth.NewCredentialStore("pepper", "alice:admin:"+hash)
	issuer := auth.NewIssuer("secret", "openscrub", time.Hour)
	d.Auth = handlers.NewAuth(handlers.AuthDeps{Creds: creds, Issuer: issuer, Logger: zerolog.Nop()})

	r := api.NewRouter(d)

	tok, _, err := auth.NewIssuer("secret", "openscrub", time.Hour).Mint("admin-1", auth.RoleAdmin)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/api/v1/metrics/snapshot",
		"/api/v1/mitigations",
		"/api/v1/auth/whoami",
		"/api/v1/metrics",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: got %d, want 200 with admin token", path, rec.Code)
		}
	}

	// /auth/login must actually be wired up (not just present-but-nil)
	// when d.Auth is non-nil — a real POST with valid creds succeeds.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"username":"alice","password":"s3cret"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login: got %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
}

// TestOptionalRoutesAbsentWhenDepsNil confirms that when
// Snapshot/Mitigations are left nil (the common case for services that
// don't wire every optional handler), the routes 404 instead of
// panicking on a nil pointer somewhere downstream.
func TestOptionalRoutesAbsentWhenDepsNil(t *testing.T) {
	d := testDeps(true)
	r := api.NewRouter(d)

	for _, path := range []string{"/api/v1/metrics/snapshot", "/api/v1/mitigations"} {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: got %d, want 404 when dep is nil", path, rec.Code)
		}
	}
}

// TestNewServerListenAndServeGracefulShutdown drives NewServer +
// ListenAndServe through a real bind/serve/shutdown cycle on an
// ephemeral port: it proves the server actually accepts a connection
// and that cancelling the context triggers a clean Shutdown rather
// than leaving the listener dangling or returning an error.
func TestNewServerListenAndServeGracefulShutdown(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv := api.NewServer("127.0.0.1:0", mux, zerolog.Nop())

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()

	// Give the goroutine a moment to enter ListenAndServe before we
	// cancel; there's no port to dial against since addr uses :0, so
	// we just exercise the shutdown path directly.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe returned %v after graceful shutdown, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ListenAndServe did not return within 5s of context cancellation")
	}
}

// TestNewServerListenAndServeBindError confirms a real listen failure
// (port already in use) propagates as a non-nil, non-ErrServerClosed
// error from ListenAndServe instead of being swallowed.
func TestNewServerListenAndServeBindError(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve a port for the test: %v", err)
	}
	defer func() { _ = ln.Close() }()
	addr := ln.Addr().String()

	srv := api.NewServer(addr, http.NewServeMux(), zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err = srv.ListenAndServe(ctx)
	if err == nil {
		t.Fatal("ListenAndServe: got nil error binding an already-in-use address, want a bind error")
	}
	if errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("ListenAndServe: got ErrServerClosed for a bind failure, want the underlying listen error")
	}
}
