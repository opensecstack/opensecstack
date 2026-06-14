package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/threatfeed/atlas"
)

// fakeAtlasSyncer keeps the test offline — no network IO.
type fakeAtlasSyncer struct{}

func (fakeAtlasSyncer) Sync(_ context.Context) (atlas.Report, error) {
	return atlas.Report{Added: 1, Unchanged: 10, Duration: 10 * time.Millisecond}, nil
}

func setupAdminEnv(t *testing.T) *testEnv {
	t.Helper()
	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret: testSecret,
			Issuer: testIssuer,
		},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1 << 20,
		},
	}

	mreg := metrics.New()
	scanner := prompt.NewScanner(prompt.DefaultLibrary, 0.3, 0.7, 1<<20)
	phScanner := phishing.NewScanner(phishing.DefaultLibrary, 0.3, 0.7, 1<<20)

	logger := zerolog.Nop()
	sink := audit.NewLoggerSink(&logger)
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)

	adminMetrics := metrics.NewAdminMetricsAdapter(mreg)
	adminAtlasH := handlers.NewAdminAtlasHandler(fakeAtlasSyncer{}, sink, &logger, adminMetrics)
	adminPatternsH := handlers.NewAdminPatternsHandler(
		scanner, phScanner, "", "", sink, &logger, adminMetrics,
	)

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		AdminAtlas:    adminAtlasH,
		AdminPatterns: adminPatternsH,
		Metrics:       mreg,
		Authenticator: verifier,
		AuditSink:     sink,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	return &testEnv{srv: httpSrv, mreg: mreg, cleanup: httpSrv.Close}
}

func TestAdmin_AtlasSync_RequiresAdmin(t *testing.T) {
	env := setupAdminEnv(t)
	defer env.cleanup()

	// No token -> 401.
	resp := doRequest(t, env, http.MethodPost, "/api/v1/admin/atlas/sync", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Viewer token -> 403.
	tok := mintToken(t, "viewer", time.Hour)
	resp = doRequest(t, env, http.MethodPost, "/api/v1/admin/atlas/sync", tok, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Admin token -> 200.
	tok = mintToken(t, "admin", time.Hour)
	resp = doRequest(t, env, http.MethodPost, "/api/v1/admin/atlas/sync", tok, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAdmin_PatternsReload_Admin(t *testing.T) {
	env := setupAdminEnv(t)
	defer env.cleanup()

	tok := mintToken(t, "admin", time.Hour)
	resp := doRequest(t, env, http.MethodPost, "/api/v1/admin/patterns/reload", tok, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()
}
