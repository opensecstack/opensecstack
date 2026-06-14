package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/ratelimit"
)

// setupServerWithRateLimit builds a server wired with the rate limiter
// and the override admin handler so we can drive a real-world cycle:
// add override → next request 429.
func setupServerWithRateLimit(t *testing.T) (*testEnv, *ratelimit.Limiter, *ratelimit.MemoryOverrideStore) {
	t.Helper()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port: 0, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{Secret: testSecret, Issuer: testIssuer, DevMode: true},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30, BlockThreshold: 0.70, MaxInputSize: 1024 * 1024,
		},
	}
	mreg := metrics.New()
	scanner := prompt.NewScanner(prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold, cfg.Prompt.BlockThreshold, int(cfg.Prompt.MaxInputSize))
	promptH := handlers.NewPromptHandler(scanner, nil, metrics.NewPromptMetricsAdapter(mreg))
	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	rlMetrics := metrics.NewRateLimitMetricsAdapter(mreg)
	// Generous default so non-overridden traffic flows freely; the
	// override is what we exercise.
	lim := ratelimit.New(ratelimit.Config{RPS: 1000, Burst: 1000})
	lim.SetOverrideHook(rlMetrics)
	t.Cleanup(lim.Stop)

	store := ratelimit.NewMemoryOverrideStore()
	auditSink := audit.NewLoggerSink(&logger)
	rlAdmin := handlers.NewRateLimitAdminHandler(store, lim, auditSink, &logger)

	apiSrv := api.New(api.Options{
		Config:           cfg,
		Logger:           &logger,
		Pinger:           stubPinger{},
		Prompt:           promptH,
		ThreatFeed:       threatFeedH,
		AuditSink:        auditSink,
		Metrics:          mreg,
		Authenticator:    verifier,
		RateLimitAdmin:   rlAdmin,
		RateLimiter:      lim,
		RateLimitMetrics: rlMetrics,
	})
	httpSrv := httptest.NewServer(apiSrv.Handler())

	return &testEnv{
		srv:     httpSrv,
		mreg:    mreg,
		cleanup: httpSrv.Close,
	}, lim, store
}

func TestRateLimit_OverrideBlocksSubsequentRequests(t *testing.T) {
	env, lim, store := setupServerWithRateLimit(t)
	defer env.cleanup()

	// Dev mode injects sub="dev" — that's the limiter key after auth.
	// Seed an override that blocks immediately and refresh the snapshot.
	ctx := context.Background()
	if err := store.Add(ctx, ratelimit.Override{
		Kind: "sub", Value: "dev", RPS: 0, Burst: 0, Reason: "integration",
	}); err != nil {
		t.Fatalf("seed override: %v", err)
	}
	if err := lim.Refresh(ctx, store); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	// Any authenticated endpoint is fine — pick the cheapest GET.
	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+"/api/v1/threatfeed/iocs", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
}

func TestRateLimit_AdminEndpointAddsOverride(t *testing.T) {
	env, lim, store := setupServerWithRateLimit(t)
	defer env.cleanup()

	// POST through the actual admin endpoint to exercise the wiring.
	// Use a different value than the dev-mode subject so the admin
	// request itself doesn't pre-warm a default-rate bucket for the key
	// we're about to override (documented limitation: existing buckets
	// keep the rate they were built with until janitor eviction).
	body := `{"kind":"sub","value":"other-actor","rps":0,"burst":0,"reason":"abuse"}`
	req, _ := http.NewRequest(http.MethodPost,
		env.srv.URL+"/api/v1/admin/ratelimit/overrides",
		strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}

	// Store-level confirmation independent of the limiter snapshot.
	list, _ := store.List(context.Background())
	if len(list) != 1 || list[0].Value != "other-actor" {
		t.Fatalf("store contents = %+v", list)
	}

	// Allow on the (fresh) override key returns false → admin endpoint
	// really did refresh the limiter snapshot, and the new bucket is
	// built from the override quota (RPS=0, Burst=0).
	if lim.Allow("sub:other-actor") {
		t.Fatal("limiter still allowing 'other-actor' after admin add")
	}
}
