// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package db

import (
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/securelab/internal/config"
	"github.com/opensecstack/securelab/internal/db/migrations"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// dbURL returns the DSN to use for integration tests. Tests that call this
// skip automatically when DATABASE_URL is unset, so this file is a no-op on
// machines without a live Postgres available.
func dbURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("DATABASE_URL")
	if u == "" {
		t.Skip("DATABASE_URL not set — skipping db integration test")
	}
	return u
}

// migrationsOnce guards a single application of the embedded *.sql migration
// files against the target database for the lifetime of the test binary.
// The migrations use CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS
// guards (see migrations/*.sql), so re-running them is idempotent — this
// just avoids the redundant round-trips on every test.
var (
	migrationsOnce sync.Once
	migrationsErr  error
)

func ensureSchema(t *testing.T, connString string) {
	t.Helper()
	migrationsOnce.Do(func() {
		migrationsErr = applyMigrations(connString)
	})
	if migrationsErr != nil {
		t.Fatalf("applying migrations: %v", migrationsErr)
	}
}

// applyMigrations runs every embedded *.sql file from internal/db/migrations
// against connString in lexicographic (numeric-prefix) order, mirroring
// cmd/server/main.go's runMigrations.
func applyMigrations(connString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return err
	}

	entries, err := fs.ReadDir(migrations.FS, ".")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)

	for _, name := range names {
		data, err := migrations.FS.ReadFile(name)
		if err != nil {
			return err
		}
		if _, err := pool.Exec(ctx, string(data)); err != nil {
			return err
		}
	}
	return nil
}

// openPool returns a ready pgxpool.Pool against the test database, with the
// schema applied and the pool closed automatically at test end.
func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := dbURL(t)
	ensureSchema(t, url)

	cfg := &config.Config{DBUrl: url, DBMaxConns: 4}
	pool, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// truncateAll clears every table this package manages so tests don't
// interfere with each other via lingering rows (e.g. ListScenarios seeing
// scenarios inserted by a different test). Order matters: scenario_runs
// references scenarios and environments via FK RESTRICT.
func truncateAll(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	const sql = `TRUNCATE TABLE scenario_runs, mitre_coverage, scenarios, environments`
	if _, err := pool.Exec(context.Background(), sql); err != nil {
		t.Fatalf("truncating tables: %v", err)
	}
}

func newScenario(name string) *Scenario {
	return &Scenario{
		Name:              name,
		Description:       "a test scenario",
		MitreTechniqueIDs: []string{"T1059"},
		Tags:              []string{"test"},
		Severity:          "medium",
		TimeoutSeconds:    120,
		YAMLContent:       "steps: []",
	}
}

func newEnvironment(name string) *Environment {
	return &Environment{
		Name:      name,
		Kind:      "docker",
		TargetURL: "http://localhost:9999",
		NetworkID: "net-1",
		Status:    "ready",
	}
}

// ---------------------------------------------------------------------------
// New / pool bootstrap
// ---------------------------------------------------------------------------

func TestNew_PingSucceedsIntegration(t *testing.T) {
	pool := openPool(t)
	if err := pool.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestNew_InvalidConnStringIntegration(t *testing.T) {
	cfg := &config.Config{DBUrl: "://not a valid dsn", DBMaxConns: 4}
	_, err := New(context.Background(), cfg)
	if err == nil {
		t.Error("expected error constructing pool from an invalid connection string")
	}
}

func TestNew_UnreachableHostIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Reserved TEST-NET-1 address (RFC 5737) — never routable, so Ping fails
	// fast instead of hanging for the default connect timeout.
	cfg := &config.Config{
		DBUrl:      "postgres://user:pass@192.0.2.1:5432/nonexistent?connect_timeout=1",
		DBMaxConns: 4,
	}
	_, err := New(ctx, cfg)
	if err == nil {
		t.Error("expected error constructing pool against an unreachable host")
	}
}

// ---------------------------------------------------------------------------
// Scenario CRUD
// ---------------------------------------------------------------------------

func TestScenario_InsertGetListIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	s := newScenario("scenario-insert-get")
	id, err := InsertScenario(ctx, pool, s)
	if err != nil {
		t.Fatalf("InsertScenario: %v", err)
	}
	if id == "" {
		t.Fatal("expected a non-empty generated UUID")
	}

	got, err := GetScenario(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetScenario: %v", err)
	}
	if got == nil {
		t.Fatal("expected scenario, got nil")
	}
	if got.Name != s.Name {
		t.Errorf("Name: got %q, want %q", got.Name, s.Name)
	}
	if got.Severity != "medium" {
		t.Errorf("Severity: got %q, want medium", got.Severity)
	}
	if len(got.MitreTechniqueIDs) != 1 || got.MitreTechniqueIDs[0] != "T1059" {
		t.Errorf("MitreTechniqueIDs: got %v", got.MitreTechniqueIDs)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be populated")
	}

	list, err := ListScenarios(ctx, pool)
	if err != nil {
		t.Fatalf("ListScenarios: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 scenario, got %d", len(list))
	}
	if list[0].ID != id {
		t.Errorf("listed scenario ID: got %q, want %q", list[0].ID, id)
	}
}

func TestScenario_GetNotFoundIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	got, err := GetScenario(context.Background(), pool, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetScenario should return (nil, nil) for missing row, got error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil scenario for missing row, got %+v", got)
	}
}

func TestScenario_InsertDuplicateNameFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	s := newScenario("scenario-dup")
	if _, err := InsertScenario(ctx, pool, s); err != nil {
		t.Fatalf("InsertScenario (first): %v", err)
	}

	dup := newScenario("scenario-dup")
	if _, err := InsertScenario(ctx, pool, dup); err == nil {
		t.Error("expected unique constraint violation inserting a duplicate scenario name")
	}
}

func TestScenario_InsertInvalidSeverityFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	s := newScenario("scenario-bad-severity")
	s.Severity = "not-a-real-severity"
	if _, err := InsertScenario(context.Background(), pool, s); err == nil {
		t.Error("expected CHECK constraint violation for invalid severity")
	}
}

func TestScenario_ListEmptyIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	list, err := ListScenarios(context.Background(), pool)
	if err != nil {
		t.Fatalf("ListScenarios: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// Environment CRUD
// ---------------------------------------------------------------------------

func TestEnvironment_InsertGetListIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	e := newEnvironment("env-insert-get")
	id, err := InsertEnvironment(ctx, pool, e)
	if err != nil {
		t.Fatalf("InsertEnvironment: %v", err)
	}
	if id == "" {
		t.Fatal("expected a non-empty generated UUID")
	}

	got, err := GetEnvironment(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetEnvironment: %v", err)
	}
	if got == nil {
		t.Fatal("expected environment, got nil")
	}
	if got.Kind != "docker" {
		t.Errorf("Kind: got %q, want docker", got.Kind)
	}
	if got.Status != "ready" {
		t.Errorf("Status: got %q, want ready", got.Status)
	}

	list, err := ListEnvironments(ctx, pool)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 environment, got %d", len(list))
	}
}

func TestEnvironment_GetNotFoundIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	got, err := GetEnvironment(context.Background(), pool, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetEnvironment should return (nil, nil) for missing row, got error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil environment for missing row, got %+v", got)
	}
}

func TestEnvironment_InsertInvalidKindFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	e := newEnvironment("env-bad-kind")
	e.Kind = "vm"
	if _, err := InsertEnvironment(context.Background(), pool, e); err == nil {
		t.Error("expected CHECK constraint violation for invalid kind")
	}
}

func TestEnvironment_InsertDuplicateNameFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	e := newEnvironment("env-dup")
	if _, err := InsertEnvironment(ctx, pool, e); err != nil {
		t.Fatalf("InsertEnvironment (first): %v", err)
	}
	dup := newEnvironment("env-dup")
	if _, err := InsertEnvironment(ctx, pool, dup); err == nil {
		t.Error("expected unique constraint violation inserting a duplicate environment name")
	}
}

// ---------------------------------------------------------------------------
// ScenarioRun CRUD
// ---------------------------------------------------------------------------

func TestScenarioRun_InsertGetUpdateListIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	scenarioID, err := InsertScenario(ctx, pool, newScenario("run-scenario"))
	if err != nil {
		t.Fatalf("InsertScenario: %v", err)
	}
	envID, err := InsertEnvironment(ctx, pool, newEnvironment("run-env"))
	if err != nil {
		t.Fatalf("InsertEnvironment: %v", err)
	}

	run := &ScenarioRun{ScenarioID: scenarioID, EnvironmentID: envID, Status: "pending"}
	runID, err := InsertRun(ctx, pool, run)
	if err != nil {
		t.Fatalf("InsertRun: %v", err)
	}
	if runID == "" {
		t.Fatal("expected a non-empty generated UUID")
	}

	got, err := GetRun(ctx, pool, runID)
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got == nil {
		t.Fatal("expected run, got nil")
	}
	if got.Status != "pending" {
		t.Errorf("Status: got %q, want pending", got.Status)
	}
	if got.ScenarioID != scenarioID {
		t.Errorf("ScenarioID: got %q, want %q", got.ScenarioID, scenarioID)
	}

	// Drive the run through to completion.
	now := time.Now().UTC().Truncate(time.Millisecond)
	latency := 1500
	detected := true
	got.Status = "passed"
	got.StartedAt = &now
	got.FinishedAt = &now
	got.AttackEvents = json.RawMessage(`[{"event":"exploit"}]`)
	got.DetectionEvents = json.RawMessage(`[{"event":"alert"}]`)
	got.DetectionLatencyMs = &latency
	got.Detected = &detected
	got.Notes = "detected in time"

	if err := UpdateRunStatus(ctx, pool, got); err != nil {
		t.Fatalf("UpdateRunStatus: %v", err)
	}

	updated, err := GetRun(ctx, pool, runID)
	if err != nil {
		t.Fatalf("GetRun (after update): %v", err)
	}
	if updated.Status != "passed" {
		t.Errorf("Status: got %q, want passed", updated.Status)
	}
	if updated.Detected == nil || !*updated.Detected {
		t.Error("expected Detected to be true")
	}
	if updated.DetectionLatencyMs == nil || *updated.DetectionLatencyMs != 1500 {
		t.Errorf("DetectionLatencyMs: got %v, want 1500", updated.DetectionLatencyMs)
	}
	if updated.Notes != "detected in time" {
		t.Errorf("Notes: got %q, want %q", updated.Notes, "detected in time")
	}

	list, err := ListRuns(ctx, pool)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 run, got %d", len(list))
	}
}

func TestScenarioRun_GetNotFoundIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	got, err := GetRun(context.Background(), pool, "00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatalf("GetRun should return (nil, nil) for missing row, got error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil run for missing row, got %+v", got)
	}
}

func TestScenarioRun_InsertUnknownScenarioFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	envID, err := InsertEnvironment(ctx, pool, newEnvironment("orphan-run-env"))
	if err != nil {
		t.Fatalf("InsertEnvironment: %v", err)
	}

	run := &ScenarioRun{
		ScenarioID:    "00000000-0000-0000-0000-000000000000",
		EnvironmentID: envID,
		Status:        "pending",
	}
	if _, err := InsertRun(ctx, pool, run); err == nil {
		t.Error("expected FK violation inserting a run against a non-existent scenario")
	}
}

func TestScenarioRun_InsertInvalidStatusFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	scenarioID, err := InsertScenario(ctx, pool, newScenario("bad-status-scenario"))
	if err != nil {
		t.Fatalf("InsertScenario: %v", err)
	}
	envID, err := InsertEnvironment(ctx, pool, newEnvironment("bad-status-env"))
	if err != nil {
		t.Fatalf("InsertEnvironment: %v", err)
	}

	run := &ScenarioRun{ScenarioID: scenarioID, EnvironmentID: envID, Status: "not-a-status"}
	if _, err := InsertRun(ctx, pool, run); err == nil {
		t.Error("expected CHECK constraint violation for invalid status")
	}
}

func TestScenarioRun_DeleteScenarioRestrictedByRunFailsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	scenarioID, err := InsertScenario(ctx, pool, newScenario("restrict-scenario"))
	if err != nil {
		t.Fatalf("InsertScenario: %v", err)
	}
	envID, err := InsertEnvironment(ctx, pool, newEnvironment("restrict-env"))
	if err != nil {
		t.Fatalf("InsertEnvironment: %v", err)
	}
	if _, err := InsertRun(ctx, pool, &ScenarioRun{ScenarioID: scenarioID, EnvironmentID: envID, Status: "pending"}); err != nil {
		t.Fatalf("InsertRun: %v", err)
	}

	// scenario_runs.scenario_id has ON DELETE RESTRICT — deleting a
	// referenced scenario must fail while a run still points at it.
	_, err = pool.Exec(ctx, `DELETE FROM scenarios WHERE id = $1`, scenarioID)
	if err == nil {
		t.Error("expected FK RESTRICT violation deleting a scenario with an existing run")
	}
}

func TestScenarioRun_ListEmptyIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	list, err := ListRuns(context.Background(), pool)
	if err != nil {
		t.Fatalf("ListRuns: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

// ---------------------------------------------------------------------------
// MitreCoverage upsert / list
// ---------------------------------------------------------------------------

func TestMitreCoverage_UpsertInsertsThenIncrementsIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	first := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	c := &MitreCoverage{
		TechniqueID:    "T1059",
		TechniqueName:  "Command and Scripting Interpreter",
		Tactic:         "execution",
		ScenarioCount:  1,
		LastDetectedAt: &first,
		DetectionRate:  50.00,
	}
	if err := UpsertCoverage(ctx, pool, c); err != nil {
		t.Fatalf("UpsertCoverage (insert): %v", err)
	}

	list, err := ListCoverage(ctx, pool)
	if err != nil {
		t.Fatalf("ListCoverage: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 coverage row, got %d", len(list))
	}
	if list[0].ScenarioCount != 1 {
		t.Errorf("ScenarioCount: got %d, want 1", list[0].ScenarioCount)
	}

	// A second upsert for the same technique_id must hit the ON CONFLICT
	// path: scenario_count increments (independent of the value supplied),
	// and last_detected_at takes the GREATEST of old and new.
	later := first.Add(2 * time.Hour)
	c2 := &MitreCoverage{
		TechniqueID:    "T1059",
		TechniqueName:  "Command and Scripting Interpreter (updated)",
		Tactic:         "execution",
		ScenarioCount:  1,
		LastDetectedAt: &later,
		DetectionRate:  75.00,
	}
	if err := UpsertCoverage(ctx, pool, c2); err != nil {
		t.Fatalf("UpsertCoverage (conflict): %v", err)
	}

	list, err = ListCoverage(ctx, pool)
	if err != nil {
		t.Fatalf("ListCoverage (after conflict): %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected still 1 coverage row after upsert, got %d", len(list))
	}
	if list[0].ScenarioCount != 2 {
		t.Errorf("ScenarioCount after conflict: got %d, want 2 (incremented)", list[0].ScenarioCount)
	}
	if list[0].TechniqueName != "Command and Scripting Interpreter (updated)" {
		t.Errorf("TechniqueName after conflict: got %q, want updated value", list[0].TechniqueName)
	}
	if list[0].DetectionRate != 75.00 {
		t.Errorf("DetectionRate after conflict: got %v, want 75.00", list[0].DetectionRate)
	}
	if list[0].LastDetectedAt == nil || !list[0].LastDetectedAt.Equal(later) {
		t.Errorf("LastDetectedAt after conflict: got %v, want %v (GREATEST)", list[0].LastDetectedAt, later)
	}
}

func TestMitreCoverage_ListEmptyIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)

	list, err := ListCoverage(context.Background(), pool)
	if err != nil {
		t.Fatalf("ListCoverage: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected empty list, got %d", len(list))
	}
}

func TestMitreCoverage_ListOrderedByTechniqueIDIntegration(t *testing.T) {
	pool := openPool(t)
	truncateAll(t, pool)
	ctx := context.Background()

	for _, id := range []string{"T1078", "T1003", "T1059"} {
		c := &MitreCoverage{TechniqueID: id, ScenarioCount: 1, DetectionRate: 0}
		if err := UpsertCoverage(ctx, pool, c); err != nil {
			t.Fatalf("UpsertCoverage(%s): %v", id, err)
		}
	}

	list, err := ListCoverage(ctx, pool)
	if err != nil {
		t.Fatalf("ListCoverage: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 rows, got %d", len(list))
	}
	if !sort.StringsAreSorted([]string{list[0].TechniqueID, list[1].TechniqueID, list[2].TechniqueID}) {
		t.Errorf("expected rows ordered by technique_id, got %s, %s, %s",
			list[0].TechniqueID, list[1].TechniqueID, list[2].TechniqueID)
	}
}
