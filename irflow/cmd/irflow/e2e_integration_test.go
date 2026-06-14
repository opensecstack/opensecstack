//go:build integration

// End-to-end integration test. Boots the full api.Server stack against a
// real PostgreSQL (read from IRFLOW_TEST_DB_URL) and issues HTTP requests
// through httptest.Server. This is the highest-fidelity test we have —
// every layer from chi routing through PGStore runs exactly as in prod.
//
// Run via `make test-integration` (requires `make compose-test-up` first).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"

	"github.com/opensecstack/opensecstack/irflow/internal/api"
	"github.com/opensecstack/opensecstack/irflow/internal/auth"
	"github.com/opensecstack/opensecstack/irflow/internal/db"
	"github.com/opensecstack/opensecstack/irflow/internal/incident"
	"github.com/opensecstack/opensecstack/irflow/internal/metrics"
	"github.com/opensecstack/opensecstack/irflow/internal/playbook"
	"github.com/opensecstack/opensecstack/irflow/internal/webhook"
)

// -------------------- fixtures --------------------

var (
	e2ePoolOnce sync.Once
	e2ePool     *pgxpool.Pool
	e2ePoolErr  error
	e2eMigOnce  sync.Once
	e2eMigErr   error
)

func e2eRequirePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("IRFLOW_TEST_DB_URL")
	if dsn == "" {
		t.Skip("IRFLOW_TEST_DB_URL not set — skipping e2e test")
	}
	e2ePoolOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		e2ePool, e2ePoolErr = pgxpool.New(ctx, dsn)
	})
	if e2ePoolErr != nil {
		t.Fatalf("connect: %v", e2ePoolErr)
	}
	e2eMigOnce.Do(func() { e2eMigErr = e2eApplyMigrations(e2ePool) })
	if e2eMigErr != nil {
		t.Fatalf("migrate: %v", e2eMigErr)
	}
	if err := e2eTruncate(e2ePool); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	t.Cleanup(func() { _ = e2eTruncate(e2ePool) })
	return e2ePool
}

func e2eApplyMigrations(pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version VARCHAR(50) PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`); err != nil {
		return err
	}
	dir, err := e2eFindMigrationsDir()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(files)
	for _, f := range files {
		name := filepath.Base(f)
		var exists bool
		if err := pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		body, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, string(body)); err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, "INSERT INTO schema_migrations(version) VALUES ($1) ON CONFLICT DO NOTHING", name); err != nil {
			return err
		}
	}
	return nil
}

func e2eTruncate(pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `
		TRUNCATE timeline_entries, ioc_enrichments, incident_actions,
		         playbook_executions, incidents, playbooks
		RESTART IDENTITY CASCADE`)
	return err
}

func e2eFindMigrationsDir() (string, error) {
	_, this, _, _ := runtime.Caller(0)
	dir := filepath.Dir(this)
	for i := 0; i < 8; i++ {
		c := filepath.Join(dir, "migrations")
		if st, err := os.Stat(c); err == nil && st.IsDir() {
			return c, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", os.ErrNotExist
}

// -------------------- harness --------------------

const e2eAuthSecret = "e2e-auth-secret"
const e2eWebhookSecret = "e2e-webhook-secret"

type stubMarshal struct {
	outcome incident.MarshalResult
}

func (s *stubMarshal) Evaluate(_ context.Context, _ incident.MarshalRequest) (*incident.MarshalResult, error) {
	c := s.outcome
	return &c, nil
}

func bootServer(t *testing.T) *httptest.Server {
	t.Helper()
	pool := e2eRequirePool(t)

	logger := zap.NewNop()
	mx := metrics.New(nil)

	incidentStore := db.NewPGStore(pool)
	playbookStore := db.NewPGPlaybookStore(pool)
	executor := playbook.NewExecutor(logger)
	playbookSvc := playbook.NewService(playbookStore, executor, logger).WithMetrics(mx)

	incSvc := incident.NewService(
		incidentStore,
		incident.WithLogger(logger),
		incident.WithMetrics(mx),
		incident.WithMarshal(&stubMarshal{
			outcome: incident.MarshalResult{Outcome: incident.MarshalOutcomeExecute, WORMEntryID: "e2e-worm"},
		}),
	)

	srv := api.NewServer(api.Options{
		Logger:    logger,
		Incidents: incSvc,
		Playbooks: playbookSvc,
		Webhooks: api.WebhookSecrets{
			APIGuard:   e2eWebhookSecret,
			CITADEL:    e2eWebhookSecret,
			ThreatFlow: e2eWebhookSecret,
		},
		Auth:    auth.Config{Secret: e2eAuthSecret, Logger: logger},
		Metrics: mx,
	})

	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return ts
}

func issueToken(t *testing.T, role string) string {
	t.Helper()
	tok, err := auth.Issue(e2eAuthSecret, auth.Claims{Subject: "tester", Role: role}, 1*time.Hour)
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	return tok
}

func doJSON(t *testing.T, ts *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, buf
}

func signedWebhook(t *testing.T, ts *httptest.Server, path string, body []byte) (int, []byte) {
	t.Helper()
	ts_secs := time.Now().Unix()
	sig := webhook.Sign(e2eWebhookSecret, ts_secs, body)
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(webhook.HeaderSignature, sig)
	req.Header.Set(webhook.HeaderTimestamp, strconv.FormatInt(ts_secs, 10))
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, buf
}

// -------------------- tests --------------------

func TestE2E_IncidentCRUDFlow(t *testing.T) {
	ts := bootServer(t)
	token := issueToken(t, auth.RoleOperator)

	// Create.
	code, body := doJSON(t, ts, http.MethodPost, "/api/v1/incidents", token, map[string]string{
		"title":    "e2e incident",
		"severity": "P2",
		"source":   "manual",
	})
	if code != http.StatusCreated {
		t.Fatalf("create: status=%d body=%s", code, body)
	}
	var created incident.Incident
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.ID == "" || created.Status != incident.StatusOpen {
		t.Fatalf("created: %+v", created)
	}

	// Get.
	code, body = doJSON(t, ts, http.MethodGet, "/api/v1/incidents/"+created.ID, token, nil)
	if code != http.StatusOK {
		t.Fatalf("get: status=%d body=%s", code, body)
	}

	// Patch — transition to investigating.
	code, body = doJSON(t, ts, http.MethodPatch, "/api/v1/incidents/"+created.ID, token, map[string]string{"status": "investigating"})
	if code != http.StatusOK {
		t.Fatalf("patch: status=%d body=%s", code, body)
	}

	// List.
	code, body = doJSON(t, ts, http.MethodGet, "/api/v1/incidents?per_page=10", token, nil)
	if code != http.StatusOK {
		t.Fatalf("list: status=%d", code)
	}
	if !bytes.Contains(body, []byte(`"total_count":1`)) {
		t.Errorf("list total_count missing from %s", body)
	}

	// Delete — operator lacks delete permission; should 403.
	code, _ = doJSON(t, ts, http.MethodDelete, "/api/v1/incidents/"+created.ID, token, nil)
	if code != http.StatusForbidden {
		t.Errorf("delete as operator: status=%d, want 403", code)
	}

	// Delete as admin succeeds.
	adminTok := issueToken(t, auth.RoleAdmin)
	code, _ = doJSON(t, ts, http.MethodDelete, "/api/v1/incidents/"+created.ID, adminTok, nil)
	if code != http.StatusNoContent {
		t.Errorf("delete as admin: status=%d, want 204", code)
	}
}

func TestE2E_SubmitActionWithMarshalStub(t *testing.T) {
	ts := bootServer(t)
	token := issueToken(t, auth.RoleOperator)

	// Create incident.
	code, body := doJSON(t, ts, http.MethodPost, "/api/v1/incidents", token, map[string]string{
		"title":    "marshal test",
		"severity": "P2",
		"source":   "manual",
	})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var inc incident.Incident
	_ = json.Unmarshal(body, &inc)

	// Submit action — stub MARSHAL returns EXECUTE.
	code, body = doJSON(t, ts, http.MethodPost,
		"/api/v1/incidents/"+inc.ID+"/actions", token, map[string]string{
			"action_type": "contain",
			"operator_id": "alice",
			"verifier_id": "bob",
			"description": "block endpoint",
		})
	if code != http.StatusCreated {
		t.Fatalf("submit action: status=%d body=%s", code, body)
	}
	if !bytes.Contains(body, []byte(`"marshal_decision":"EXECUTE"`)) {
		t.Errorf("action should record EXECUTE decision: %s", body)
	}
	if !bytes.Contains(body, []byte(`"worm_entry_id":"e2e-worm"`)) {
		t.Errorf("action should record WORM entry id: %s", body)
	}
}

func TestE2E_APIGuardWebhookAutoCreatesIncident(t *testing.T) {
	ts := bootServer(t)

	payload, _ := json.Marshal(map[string]any{
		"event_id":   "evt-e2e-1",
		"event_type": "finding",
		"scan_id":    "scan-e2e",
		"target":     "https://api.example.com/v1",
		"finding": map[string]any{
			"id":       "f-1",
			"title":    "SQLi",
			"severity": "critical",
		},
		"occurred_at": time.Now().UTC().Format(time.RFC3339),
	})
	code, body := signedWebhook(t, ts, "/api/v1/webhooks/apiguard", payload)
	if code != http.StatusCreated {
		t.Fatalf("webhook: status=%d body=%s", code, body)
	}

	// Confirm the incident landed by hitting the protected list endpoint.
	token := issueToken(t, auth.RoleViewer)
	code, body = doJSON(t, ts, http.MethodGet, "/api/v1/incidents?per_page=10", token, nil)
	if code != http.StatusOK {
		t.Fatalf("list: %d %s", code, body)
	}
	if !bytes.Contains(body, []byte(`"severity":"P1"`)) {
		t.Errorf("incident list should contain a P1 incident from the webhook: %s", body)
	}
}

func TestE2E_PlaybookCreateAndExecute(t *testing.T) {
	ts := bootServer(t)
	token := issueToken(t, auth.RoleAdmin)

	// Create a playbook.
	create := map[string]any{
		"name":        "Test Playbook",
		"description": "e2e",
		"version":     "1.0",
		"status":      "active",
		"trigger":     map[string]string{"event_type": "manual"},
		"steps": []map[string]any{
			{"id": "a", "name": "A", "type": "action", "on_success": "b"},
			{"id": "b", "name": "B", "type": "notify"},
		},
	}
	code, body := doJSON(t, ts, http.MethodPost, "/api/v1/playbooks", token, create)
	if code != http.StatusCreated {
		t.Fatalf("create playbook: %d %s", code, body)
	}
	var pb playbook.Playbook
	_ = json.Unmarshal(body, &pb)

	// Execute (returns 202 with an Execution in "pending").
	code, body = doJSON(t, ts, http.MethodPost,
		"/api/v1/playbooks/"+pb.ID+"/execute", token, map[string]string{"incident_id": "inc-any"})
	if code != http.StatusAccepted {
		t.Fatalf("execute: %d %s", code, body)
	}
	var exec playbook.Execution
	_ = json.Unmarshal(body, &exec)

	// The executor runs async — poll the execution endpoint until completed.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		code, body = doJSON(t, ts, http.MethodGet, "/api/v1/executions/"+exec.ID, token, nil)
		if code == http.StatusOK && bytes.Contains(body, []byte(`"status":"completed"`)) {
			return
		}
		time.Sleep(75 * time.Millisecond)
	}
	t.Fatalf("execution did not reach completed; last body: %s", body)
}

func TestE2E_StatsReflectReality(t *testing.T) {
	ts := bootServer(t)
	token := issueToken(t, auth.RoleOperator)

	// Create one P1 manual incident.
	code, _ := doJSON(t, ts, http.MethodPost, "/api/v1/incidents", token, map[string]string{
		"title":    "critical",
		"severity": "P1",
		"source":   "manual",
	})
	if code != http.StatusCreated {
		t.Fatal("seed create failed")
	}

	code, body := doJSON(t, ts, http.MethodGet, "/api/v1/stats", token, nil)
	if code != http.StatusOK {
		t.Fatalf("stats: %d %s", code, body)
	}
	if !bytes.Contains(body, []byte(`"total":1`)) {
		t.Errorf("stats should report total=1: %s", body)
	}
	if !bytes.Contains(body, []byte(`"P1":1`)) {
		t.Errorf("stats should report P1=1: %s", body)
	}
}

func TestE2E_UnauthenticatedRequestRejected(t *testing.T) {
	ts := bootServer(t)
	code, _ := doJSON(t, ts, http.MethodGet, "/api/v1/incidents", "", nil)
	if code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", code)
	}
}

func TestE2E_HealthEndpointsArePublic(t *testing.T) {
	ts := bootServer(t)
	for _, path := range []string{"/health", "/health/detail"} {
		code, _ := doJSON(t, ts, http.MethodGet, path, "", nil)
		if code != http.StatusOK && code != http.StatusServiceUnavailable {
			t.Errorf("GET %s: status = %d, want 200 or 503", path, code)
		}
	}
}

func TestE2E_MetricsEndpointServesProm(t *testing.T) {
	ts := bootServer(t)

	// Trigger at least one non-metrics request first. Counters are
	// incremented in HTTPMiddleware AFTER the handler writes its response,
	// so a /metrics response cannot contain the counter for its own request.
	_, _ = doJSON(t, ts, http.MethodGet, "/health", "", nil)

	code, body := doJSON(t, ts, http.MethodGet, "/metrics", "", nil)
	if code != http.StatusOK {
		t.Fatalf("metrics: %d", code)
	}
	if !bytes.Contains(body, []byte("irflow_http_requests_total")) {
		t.Errorf("metrics body missing irflow_http_requests_total")
	}
}
