package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/api"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/config"
)

// buildAuthedServer wires a Server with no database connection (db == nil,
// so the advisory handler runs in its scaffold mode) but a real auth.Service
// backed by a bootstrap key — enough to exercise the route's auth/role
// gating without needing THREATFLOW_TEST_DB_URL.
func buildAuthedServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := &config.Config{
		Auth: config.AuthConfig{JWTSecret: "route-test-secret-padded-to-32ch"},
		Rate: config.RateLimitConfig{RequestsPerSec: 1000, Burst: 2000},
	}
	authSvc, err := auth.NewService(auth.Config{
		Secret: cfg.Auth.JWTSecret,
		TTL:    10 * time.Minute,
		BootstrapKeys: map[string]auth.Role{
			"route-test-operator": auth.RoleOperator,
			"route-test-viewer":   auth.RoleViewer,
		},
	})
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	noCache, _ := cache.Open(t.Context(), "", 0, zerolog.Nop())
	citadelClient := citadel.New(citadel.Config{}, zerolog.Nop())
	srv := api.NewServer(cfg, nil, citadelClient, authSvc, noCache)
	ts := httptest.NewServer(srv.Router())
	t.Cleanup(ts.Close)
	return ts
}

func exchangeToken(t *testing.T, baseURL, apiKey string) string {
	t.Helper()
	resp, err := http.Post(baseURL+"/api/v1/auth/token", "application/json",
		strings.NewReader(`{"api_key":"`+apiKey+`"}`))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status = %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.AccessToken
}

// TestAdvisoryIngest_RejectsMissingAuth proves POST /api/v1/advisories is
// gated exactly like POST /api/v1/stix/bundles (operator role required) —
// the route this ADR-004 gap left unregistered now enforces the same
// auth contract as every other mutation endpoint.
func TestAdvisoryIngest_RejectsMissingAuth(t *testing.T) {
	ts := buildAuthedServer(t)
	resp, err := http.Post(ts.URL+"/api/v1/advisories", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
}

// TestAdvisoryIngest_RejectsInsufficientRole proves a viewer-role token
// cannot ingest advisories — only operator+ can, matching /stix/bundles.
func TestAdvisoryIngest_RejectsInsufficientRole(t *testing.T) {
	ts := buildAuthedServer(t)
	token := exchangeToken(t, ts.URL, "route-test-viewer")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/advisories", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("want 403, got %d", resp.StatusCode)
	}
}

// TestAdvisoryIngest_AcceptsOperatorTokenInScaffoldMode proves an operator
// token clears the auth gate — with no database wired the handler falls
// back to its scaffold response (202), the same convention
// STIX.IngestBundle uses.
func TestAdvisoryIngest_AcceptsOperatorTokenInScaffoldMode(t *testing.T) {
	ts := buildAuthedServer(t)
	token := exchangeToken(t, ts.URL, "route-test-operator")

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/advisories", strings.NewReader(`{"document":{}}`))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("want 202, got %d", resp.StatusCode)
	}
}
