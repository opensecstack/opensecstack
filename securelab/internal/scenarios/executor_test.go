// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package scenarios_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap/zaptest"

	"github.com/opensecstack/securelab/internal/db"
	"github.com/opensecstack/securelab/internal/scenarios"
)

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

type mockDispatcher struct {
	mu      sync.Mutex
	success bool
	err     error
	calls   []scenarios.StepSpec
}

func (m *mockDispatcher) Dispatch(_ context.Context, step scenarios.StepSpec, _ string) (bool, error) {
	m.mu.Lock()
	m.calls = append(m.calls, step)
	m.mu.Unlock()
	return m.success, m.err
}

type mockMonitor struct {
	event *scenarios.DetectionEvent
	err   error
}

func (m *mockMonitor) WaitForDetection(ctx context.Context) (*scenarios.DetectionEvent, error) {
	if m.event != nil || m.err != nil {
		return m.event, m.err
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

// stubCitadel is a minimal citadelEmitter satisfying the unexported
// interface in executor.go by structural typing; it lets us exercise
// WithCitadel from the external test package.
type stubCitadel struct {
	called bool
}

func (s *stubCitadel) EmitRunCompleted(_ context.Context, _, _, _ string, _ float64) error {
	s.called = true
	return nil
}

// unreachablePool returns a *pgxpool.Pool pointed at a loopback address with
// no listener. pgxpool.New does not dial eagerly, so construction always
// succeeds; the first real query (e.g. via db.UpdateRunStatus) fails fast
// with a connection error. This lets us exercise Executor/Scheduler code
// paths that depend on a real *pgxpool.Pool value without requiring a live
// SECURELAB_DB_URL database (see testPool above, which is DB-gated and
// skipped in this environment).
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://nouser:nopass@127.0.0.1:1/nodb?sslmode=disable&connect_timeout=2")
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ---------------------------------------------------------------------------
// DB helper
// ---------------------------------------------------------------------------

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SECURELAB_DB_URL")
	if dsn == "" {
		t.Skip("SECURELAB_DB_URL not set — skipping executor tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// makeTestEnv inserts a minimal environment row and returns it with its DB ID.
func makeTestEnv(t *testing.T, pool *pgxpool.Pool) *db.Environment {
	t.Helper()
	env := &db.Environment{
		Name:      "test-env-" + t.Name(),
		Kind:      "docker",
		TargetURL: "http://192.168.99.99:8080",
		NetworkID: "net-test",
		Status:    "ready",
	}
	id, err := db.InsertEnvironment(context.Background(), pool, env)
	if err != nil {
		t.Fatalf("insert environment: %v", err)
	}
	env.ID = id
	return env
}

// makeTestScenario inserts a minimal scenario row and returns its ID.
func makeTestScenario(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	row := &db.Scenario{
		Name:              "exec-test-" + t.Name(),
		Severity:          "low",
		TimeoutSeconds:    60,
		MitreTechniqueIDs: []string{},
		Tags:              []string{},
		YAMLContent: `
name: exec-test
severity: low
steps:
  - kind: bola
`,
	}
	id, err := db.InsertScenario(context.Background(), pool, row)
	if err != nil {
		t.Fatalf("insert scenario: %v", err)
	}
	return id
}

// oneStepSpec returns a minimal ScenarioSpec with a single bola step.
func oneStepSpec() *scenarios.ScenarioSpec {
	return &scenarios.ScenarioSpec{
		Name:     "exec-test",
		Severity: "low",
		Timeout:  10 * time.Second,
		Steps:    []scenarios.StepSpec{{Kind: "bola"}},
	}
}

// ---------------------------------------------------------------------------
// TestExecutor tests
// ---------------------------------------------------------------------------

func TestExecutor_SuccessfulRunWithDetection(t *testing.T) {
	pool := testPool(t)

	env := makeTestEnv(t, pool)
	scenarioID := makeTestScenario(t, pool)

	runID, err := db.InsertRun(context.Background(), pool, &db.ScenarioRun{
		ScenarioID:    scenarioID,
		EnvironmentID: env.ID,
		Status:        "pending",
	})
	if err != nil {
		t.Fatalf("insert run: %v", err)
	}

	det := &scenarios.DetectionEvent{
		Platform:   "test-platform",
		ReceivedAt: time.Now().UTC(),
		Latency:    42,
	}
	disp := &mockDispatcher{success: true}
	mon := &mockMonitor{event: det}
	log := zaptest.NewLogger(t)

	exec := scenarios.NewExecutor(pool, disp, mon, log)
	if err := exec.Execute(context.Background(), runID, oneStepSpec(), env); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	run, err := db.GetRun(context.Background(), pool, runID)
	if err != nil || run == nil {
		t.Fatalf("GetRun: err=%v run=%v", err, run)
	}
	if run.Status != "passed" {
		t.Errorf("expected status=passed, got %q", run.Status)
	}
	if run.Detected == nil || !*run.Detected {
		t.Errorf("expected detected=true")
	}
}

func TestExecutor_FailedDispatcher(t *testing.T) {
	pool := testPool(t)

	env := makeTestEnv(t, pool)
	scenarioID := makeTestScenario(t, pool)

	runID, err := db.InsertRun(context.Background(), pool, &db.ScenarioRun{
		ScenarioID:    scenarioID,
		EnvironmentID: env.ID,
		Status:        "pending",
	})
	if err != nil {
		t.Fatalf("insert run: %v", err)
	}

	disp := &mockDispatcher{success: false, err: errors.New("attack failed")}
	mon := &mockMonitor{} // will block then time out (30 s detection window)
	log := zaptest.NewLogger(t)

	exec := scenarios.NewExecutor(pool, disp, mon, log)
	if err := exec.Execute(context.Background(), runID, oneStepSpec(), env); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	run, err := db.GetRun(context.Background(), pool, runID)
	if err != nil || run == nil {
		t.Fatalf("GetRun: err=%v run=%v", err, run)
	}
	// dispatcher returned an error → status should be "failed"
	if run.Status != "failed" {
		t.Errorf("expected status=failed, got %q", run.Status)
	}
}

func TestExecutor_NoDetection(t *testing.T) {
	pool := testPool(t)

	env := makeTestEnv(t, pool)
	scenarioID := makeTestScenario(t, pool)

	runID, err := db.InsertRun(context.Background(), pool, &db.ScenarioRun{
		ScenarioID:    scenarioID,
		EnvironmentID: env.ID,
		Status:        "pending",
	})
	if err != nil {
		t.Fatalf("insert run: %v", err)
	}

	disp := &mockDispatcher{success: true}
	mon := &mockMonitor{} // blocks until ctx cancelled
	log := zaptest.NewLogger(t)

	spec := oneStepSpec()
	spec.Timeout = 2 * time.Second // short timeout so the test finishes fast

	exec := scenarios.NewExecutor(pool, disp, mon, log)
	if err := exec.Execute(context.Background(), runID, spec, env); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}

	run, err := db.GetRun(context.Background(), pool, runID)
	if err != nil || run == nil {
		t.Fatalf("GetRun: err=%v run=%v", err, run)
	}
	if run.Detected == nil || *run.Detected {
		t.Errorf("expected detected=false when monitor times out")
	}
}

// TestExecutor_Execute_MarkRunningFails does not require SECURELAB_DB_URL:
// it points the executor at an unreachable database so the very first
// db.UpdateRunStatus call (marking the run "running") fails fast, exercising
// Execute's early-return error path deterministically and without a live DB.
func TestExecutor_Execute_MarkRunningFails(t *testing.T) {
	pool := unreachablePool(t)

	disp := &mockDispatcher{success: true}
	mon := &mockMonitor{}
	log := zaptest.NewLogger(t)

	exec := scenarios.NewExecutor(pool, disp, mon, log)
	env := &db.Environment{Name: "unreachable-env", TargetURL: "http://192.168.99.99:8080"}

	err := exec.Execute(context.Background(), "nonexistent-run", oneStepSpec(), env)
	if err == nil {
		t.Fatal("expected an error when the database is unreachable")
	}
	if !strings.Contains(err.Error(), "mark running") {
		t.Errorf("expected error to mention 'mark running', got: %v", err)
	}

	// The dispatcher must never have been invoked: Execute should fail before
	// reaching the step loop.
	disp.mu.Lock()
	calls := len(disp.calls)
	disp.mu.Unlock()
	if calls != 0 {
		t.Errorf("expected 0 dispatcher calls before mark-running failure, got %d", calls)
	}
}

// TestExecutor_WithCitadel_Attaches verifies WithCitadel accepts a
// citadelEmitter implementation without panicking. The emitter is only
// invoked after a successful final persist, which requires a live DB (see
// TestExecutor_SuccessfulRunWithDetection), so here we only assert the
// setter itself is safe to call.
func TestExecutor_WithCitadel_Attaches(t *testing.T) {
	pool := unreachablePool(t)
	exec := scenarios.NewExecutor(pool, &mockDispatcher{}, &mockMonitor{}, zaptest.NewLogger(t))

	stub := &stubCitadel{}
	exec.WithCitadel(stub)

	if stub.called {
		t.Error("EmitRunCompleted should not be called merely by attaching the emitter")
	}
}
