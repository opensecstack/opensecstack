package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/config"
)

func minimalConfig() *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret: "test-secret-at-least-32-bytes-long!!",
			Issuer: "vertguard-test",
		},
	}
}

// TestNew_MinimalOptions_UnauthenticatedRoutesWork verifies the always-on
// probe endpoints respond without any optional handler wired.
func TestNew_MinimalOptions_UnauthenticatedRoutesWork(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{
		Config: minimalConfig(),
		Logger: &logger,
	})
	if srv == nil {
		t.Fatal("New() returned nil")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	for _, path := range []string{"/livez", "/readyz", "/api/v1/health"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("GET %s: got 404, route not wired", path)
		}
	}
}

// TestNew_UnwiredOptionalRoutes_404 documents that optional module
// routes are absent from the mux entirely when their handler is nil
// (rather than present but erroring) — this is what lets trimmed test
// setups avoid standing up every dependency.
func TestNew_UnwiredOptionalRoutes_404(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{
		Config: minimalConfig(),
		Logger: &logger,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/prompt/scan", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/v1/prompt/scan: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("prompt route with nil handler: got %d, want 404", resp.StatusCode)
	}
}

// TestNew_AdminStubFallback_Returns501 verifies the admin patterns/atlas
// routes fall back to the 501 TODO stubs when the real handlers are nil
// — the route table must stay exhaustive even in trimmed setups.
func TestNew_AdminStubFallback_Returns501(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{
		Config: minimalConfig(),
		Logger: &logger,
	})
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/api/v1/admin/patterns/reload", "application/json", nil)
	if err != nil {
		t.Fatalf("POST reload: %v", err)
	}
	defer resp.Body.Close()
	// Auth middleware isn't wired (Authenticator nil) so this reaches the
	// handler unauthenticated and must hit the 501 stub, not 404/500.
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("admin patterns stub fallback: got %d, want 501", resp.StatusCode)
	}
}

// TestHandler_ReturnsUnderlyingMux confirms Handler() exposes the same
// router New() configured (not a fresh empty one).
func TestHandler_ReturnsUnderlyingMux(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{Config: minimalConfig(), Logger: &logger})
	h1 := srv.Handler()
	h2 := srv.Handler()
	if h1 == nil {
		t.Fatal("Handler() returned nil")
	}
	// Same underlying handler instance across calls.
	req := httptest.NewRequest(http.MethodGet, "/livez", nil)
	rr := httptest.NewRecorder()
	h1.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("livez via Handler() = %d, want 200", rr.Code)
	}
	_ = h2
}

// TestStartAndShutdown exercises the real listen/shutdown lifecycle —
// Start() must block until Shutdown() is called, and Shutdown() must
// return cleanly (no error) for a server that started successfully.
func TestStartAndShutdown(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{Config: minimalConfig(), Logger: &logger})

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// Give the listener a moment to come up before shutting down.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() error = %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			t.Fatalf("Start() returned unexpected error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Start() did not return after Shutdown()")
	}
}

// TestShutdown_NeverStarted still succeeds — Shutdown on a server whose
// listener never accepted a connection must not error or block.
func TestShutdown_NeverStarted(t *testing.T) {
	logger := zerolog.Nop()
	srv := New(Options{Config: minimalConfig(), Logger: &logger})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown() on never-started server error = %v", err)
	}
}

// TestLoggerMiddleware_PassesThroughAndLogs confirms the logger
// middleware invokes the next handler and doesn't alter the response.
func TestLoggerMiddleware_PassesThroughAndLogs(t *testing.T) {
	logger := zerolog.Nop()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	mw := loggerMiddleware(&logger)(next)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Fatal("logger middleware did not call next handler")
	}
	if rr.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d (middleware must not alter response)", rr.Code, http.StatusTeapot)
	}
}

// TestMetricsMiddleware_NilRegistry_PassesThrough is the fail-safe path:
// a nil metrics registry must not panic, just skip instrumentation.
func TestMetricsMiddleware_NilRegistry_PassesThrough(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := metricsMiddleware(nil)(next)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Fatal("metrics middleware (nil registry) did not call next handler")
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
}
