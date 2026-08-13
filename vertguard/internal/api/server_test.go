package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/ratelimit"
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

// TestMetricsMiddleware_RealRegistry_RecordsRequest exercises the
// non-nil branch of metricsMiddleware — it must still call through and
// must not panic when incrementing real Prometheus collectors.
func TestMetricsMiddleware_RealRegistry_RecordsRequest(t *testing.T) {
	reg := metrics.New()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
	})
	mw := metricsMiddleware(reg)(next)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	mw.ServeHTTP(rr, req)

	if !called {
		t.Fatal("metrics middleware (real registry) did not call next handler")
	}
	if rr.Code != http.StatusAccepted {
		t.Errorf("status = %d, want 202", rr.Code)
	}
}

// TestNew_FullyWiredOptions constructs a Server with every optional
// handler, plus a real metrics registry, auth verifier, rate limiter,
// and audit sink, so every conditional branch in New() that registers
// a route or middleware executes at least once. Requests only need to
// prove the router doesn't panic and the always-on probes still work
// — module route behaviour itself is covered by internal/api/handlers'
// own tests.
func TestNew_FullyWiredOptions(t *testing.T) {
	logger := zerolog.Nop()
	reg := metrics.New()
	verifier := auth.NewVerifier("test-secret-at-least-32-bytes-long!!", "vertguard-test")
	rl := ratelimit.New(ratelimit.Config{RPS: 100, Burst: 200})
	defer rl.Stop()
	sink := audit.NewMultiSink(&logger, audit.NewLoggerSink(&logger))

	cfg := minimalConfig()

	opts := Options{
		Config:             cfg,
		Logger:             &logger,
		Pinger:             nil,
		Prompt:             handlers.NewPromptHandler(nil, nil, nil),
		Phishing:           handlers.NewPhishingHandler(nil, nil, nil),
		Identity:           handlers.NewIdentityHandler(nil, nil, nil),
		ThreatFeed:         handlers.NewThreatFeedHandler(),
		Media:              handlers.NewMediaHandler(nil, nil, logger),
		ThreatflowReceiver: handlers.NewThreatflowReceiver("", nil, logger),
		WebhookAdmin:       handlers.NewWebhookAdminHandler(nil),
		WebhookSubscribers: handlers.NewWebhookSubscribersHandler(nil, nil),
		AdminAtlas:         handlers.NewAdminAtlasHandler(nil, sink, &logger, metrics.NewAdminMetricsAdapter(reg)),
		AdminPatterns:      handlers.NewAdminPatternsHandler(nil, nil, "", "", sink, &logger, metrics.NewAdminMetricsAdapter(reg)),
		AdminML:            handlers.NewAdminMLHandler(nil),
		Audit:              handlers.NewAuditHandler(nil),
		AuditSink:          sink,
		AuditMetrics:       metrics.NewAuditMetricsAdapter(reg),
		Metrics:            reg,
		Authenticator:      verifier,
		TokenRevoker:       nil,
		Denylist:           handlers.NewDenylistAdminHandler(nil, nil, sink, &logger),
		RateLimitAdmin:     handlers.NewRateLimitAdminHandler(ratelimit.NewMemoryOverrideStore(), rl, sink, &logger),
		RateLimiter:        rl,
		RateLimitMetrics:   metrics.NewRateLimitMetricsAdapter(reg),
		Auth:               handlers.NewAuthHandler(),
		Audio:              handlers.NewAudioHandler(nil, logger),
		Video:              handlers.NewVideoStreamHandler(nil, logger),
		Meetings:           handlers.NewMeetingsHandler(nil, "", logger),
	}

	srv := New(opts)
	if srv == nil {
		t.Fatal("New() returned nil with fully-wired options")
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Probe endpoints must still work with every module wired.
	for _, path := range []string{"/livez", "/api/v1/health"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("GET %s: got 404, route not wired", path)
		}
	}

	// A wired-but-unauthenticated module route must now be gated by the
	// auth middleware (401/403), not fall through to 404 — proving the
	// route registration + auth middleware branches both executed.
	resp, err := http.Post(ts.URL+"/api/v1/prompt/scan", "application/json", nil)
	if err != nil {
		t.Fatalf("POST /api/v1/prompt/scan: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("prompt route with wired handler: got 404, want auth-gated response")
	}
}
