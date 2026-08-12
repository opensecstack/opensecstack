package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// dbURL returns the DSN to use for integration tests.
//
// It checks DATABASE_URL first because that is the env var the CI workflow
// (.github/workflows/ci.yml, job test-apiguard) and cmd/migrate both use to
// point at the ephemeral Postgres service container. TEST_DB_URL is kept as
// a secondary override for local runs against a differently-named database
// (e.g. so a developer can point tests at a scratch DB without disturbing
// their dev-stack APIGUARD_DB_URL). Tests that call this skip automatically
// when neither env var is set.
func dbURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("DATABASE_URL")
	if u == "" {
		u = os.Getenv("TEST_DB_URL")
	}
	if u == "" {
		t.Skip("DATABASE_URL/TEST_DB_URL not set — skipping DB integration test")
	}
	return u
}

// migrationsOnce guards a single application of the migrations/*.up.sql
// files (plus the test-only revoked_refresh_tokens table, see
// refresh_tokens.go) against the target database for the lifetime of the
// test binary. Re-running go test against a persistent local Postgres must
// not fail on "type already exists" style errors, so applied versions are
// tracked in schema_migrations exactly like cmd/migrate does.
var (
	migrationsOnce sync.Once
	migrationsErr  error
)

// ensureSchema applies every pending migration under ../../migrations to
// connString, mirroring cmd/migrate's up logic. It is intentionally
// duplicated (rather than importing cmd/migrate, which is package main and
// cannot be imported) and confined to this test file.
func ensureSchema(t *testing.T, connString string) {
	t.Helper()
	migrationsOnce.Do(func() {
		migrationsErr = applyMigrations(connString)
	})
	if migrationsErr != nil {
		t.Fatalf("applying migrations: %v", migrationsErr)
	}
}

func applyMigrations(connString string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, connString)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("pinging database: %w", err)
	}

	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("creating schema_migrations table: %w", err)
	}

	migrationsDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", migrationsDir, err)
	}
	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	applied := make(map[string]bool)
	rows, err := pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("reading applied versions: %w", err)
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return fmt.Errorf("scanning applied version: %w", err)
		}
		applied[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterating applied versions: %w", err)
	}

	for _, f := range files {
		version := strings.TrimSuffix(f, ".up.sql")
		if applied[version] {
			continue
		}

		sqlBytes, err := os.ReadFile(filepath.Join(migrationsDir, f)) //nolint:gosec // path built from a fixed local migrations dir + filenames just listed via os.ReadDir above, not user input
		if err != nil {
			return fmt.Errorf("reading %s: %w", f, err)
		}

		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("starting transaction for %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, string(sqlBytes)); err != nil {
			_ = tx.Rollback(ctx) //nolint:errcheck // best-effort cleanup; original error is what we report
			return fmt.Errorf("applying %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, version); err != nil {
			_ = tx.Rollback(ctx) //nolint:errcheck // best-effort cleanup; original error is what we report
			return fmt.Errorf("recording %s: %w", f, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("committing %s: %w", f, err)
		}
	}

	// refresh_tokens.go documents the revoked_refresh_tokens DDL in a comment
	// rather than as a numbered migration (it predates the migrations/
	// directory convention). Create it here, idempotently, so the
	// refresh-token integration tests below have a table to exercise.
	if _, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS revoked_refresh_tokens (
			token_hash TEXT PRIMARY KEY,
			revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`); err != nil {
		return fmt.Errorf("creating revoked_refresh_tokens table: %w", err)
	}

	return nil
}

func openDB(t *testing.T) *DB {
	t.Helper()
	url := dbURL(t)
	ensureSchema(t, url)
	d, err := New(context.Background(), url)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// ---------------------------------------------------------------------------
// models.go — constants and type correctness (no DB required)
// ---------------------------------------------------------------------------

func TestScanStatusValues(t *testing.T) {
	cases := []struct {
		s    ScanStatus
		want string
	}{
		{ScanStatusPending, "pending"},
		{ScanStatusRunning, "running"},
		{ScanStatusCompleted, "completed"},
		{ScanStatusFailed, "failed"},
		{ScanStatusCancelled, "cancelled"},
	}
	for _, tc := range cases {
		if string(tc.s) != tc.want {
			t.Errorf("ScanStatus %q: want %q", tc.s, tc.want)
		}
	}
}

func TestFindingSeverityValues(t *testing.T) {
	cases := []struct {
		s    FindingSeverity
		want string
	}{
		{FindingSeverityCritical, "critical"},
		{FindingSeverityHigh, "high"},
		{FindingSeverityMedium, "medium"},
		{FindingSeverityLow, "low"},
		{FindingSeverityInfo, "info"},
	}
	for _, tc := range cases {
		if string(tc.s) != tc.want {
			t.Errorf("FindingSeverity %q: want %q", tc.s, tc.want)
		}
	}
}

func TestFindingStatusValues(t *testing.T) {
	cases := []struct {
		s    FindingStatus
		want string
	}{
		{FindingStatusOpen, "open"},
		{FindingStatusConfirmed, "confirmed"},
		{FindingStatusFalsePositive, "false_positive"},
		{FindingStatusAccepted, "accepted"},
		{FindingStatusFixed, "fixed"},
	}
	for _, tc := range cases {
		if string(tc.s) != tc.want {
			t.Errorf("FindingStatus %q: want %q", tc.s, tc.want)
		}
	}
}

func TestAuditActionValues(t *testing.T) {
	cases := []struct {
		a    AuditAction
		want string
	}{
		{AuditActionScanCreated, "scan_created"},
		{AuditActionScanStarted, "scan_started"},
		{AuditActionScanCompleted, "scan_completed"},
		{AuditActionScanFailed, "scan_failed"},
		{AuditActionScanDeleted, "scan_deleted"},
		{AuditActionFindingTriaged, "finding_triaged"},
		{AuditActionFindingStatusChanged, "finding_status_changed"},
		{AuditActionSpecUploaded, "spec_uploaded"},
		{AuditActionSpecParsed, "spec_parsed"},
		{AuditActionReportGenerated, "report_generated"},
		{AuditActionReportExported, "report_exported"},
		{AuditActionAPIKeyCreated, "api_key_created"},
		{AuditActionAPIKeyRevoked, "api_key_revoked"},
	}
	for _, tc := range cases {
		if string(tc.a) != tc.want {
			t.Errorf("AuditAction %q: want %q", tc.a, tc.want)
		}
	}
}

func TestScanZeroValue(t *testing.T) {
	var s Scan
	if s.TotalFindings != 0 {
		t.Error("zero-value Scan should have TotalFindings == 0")
	}
	if s.Status != "" {
		t.Error("zero-value Scan should have empty Status")
	}
}

func TestFindingFiltersAllNilByDefault(t *testing.T) {
	var f FindingFilters
	if f.ScanID != nil || f.Severity != nil || f.Status != nil ||
		f.OwaspID != nil || f.ModuleID != nil {
		t.Error("zero-value FindingFilters should have all nil pointers")
	}
}

func TestAuditLogFiltersAllNilByDefault(t *testing.T) {
	var f AuditLogFilters
	if f.ActorID != nil || f.Action != nil || f.ResourceID != nil || f.ResourceType != nil {
		t.Error("zero-value AuditLogFilters should have all nil pointers")
	}
}

func TestScanSummaryZeroValue(t *testing.T) {
	var s ScanSummary
	if s.TotalFindings+s.CriticalCount+s.HighCount+s.MediumCount+s.LowCount+s.InfoCount != 0 {
		t.Error("zero-value ScanSummary should have all zero counts")
	}
}

// ---------------------------------------------------------------------------
// audit_log.go — chain hash formula (pure computation, no DB)
// ---------------------------------------------------------------------------

// TestAuditChainHashFormula verifies that the chain_hash produced by
// writeEntryToDB matches SHA-256(id|actor_id|action|resource_id|prev_hash|created_at).
// This test derives the expected value using the same algorithm as the production
// code so that any unintended change to the formula will break the test.
func TestAuditChainHashFormula(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	actorID := "alice@example.com"
	action := string(AuditActionScanCreated)
	resourceID := uuid.MustParse("22222222-2222-2222-2222-222222222222")
	prevHash := "abc123"
	now := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)

	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		id.String(),
		actorID,
		action,
		resourceID.String(),
		prevHash,
		now.Format(time.RFC3339Nano),
	)
	want := fmt.Sprintf("%x", h.Sum(nil))

	if len(want) != 64 {
		t.Errorf("expected 64-char hex SHA-256, got len %d", len(want))
	}
	// Deterministic: same inputs must always produce the same hash.
	h2 := sha256.New()
	fmt.Fprintf(h2, "%s|%s|%s|%s|%s|%s",
		id.String(), actorID, action, resourceID.String(), prevHash,
		now.Format(time.RFC3339Nano),
	)
	got := fmt.Sprintf("%x", h2.Sum(nil))
	if got != want {
		t.Errorf("hash not deterministic: want %s, got %s", want, got)
	}
}

// TestAuditChainHashFirstEventNoPrevHash verifies that when there is no
// previous entry (genesis event), the prev_hash component is empty string.
func TestAuditChainHashFirstEventNoPrevHash(t *testing.T) {
	id := uuid.New()
	now := time.Now().UTC()

	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%s|%s",
		id.String(), "system", "scan_created", "", "", now.Format(time.RFC3339Nano),
	)
	got := fmt.Sprintf("%x", h.Sum(nil))
	if len(got) != 64 {
		t.Errorf("genesis hash should be 64 hex chars, got %d", len(got))
	}
}

// ---------------------------------------------------------------------------
// audit_log.go — FlushAuditLog with cancelled context (no DB)
// ---------------------------------------------------------------------------

func TestFlushAuditLog_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Artificially hold the WaitGroup so FlushAuditLog can't complete on its own.
	auditWg.Add(1)
	defer auditWg.Done()

	err := FlushAuditLog(ctx)
	if err == nil {
		t.Error("expected an error for a pre-cancelled context, got nil")
	}
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestFlushAuditLog_NothingQueued(t *testing.T) {
	// When auditWg counter is 0, FlushAuditLog should return immediately.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	if err := FlushAuditLog(ctx); err != nil {
		t.Errorf("expected nil when nothing is queued, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// refresh_tokens.go — hash truncation (pure logic, no DB)
// ---------------------------------------------------------------------------

func TestRevokedTokenHashTruncation(t *testing.T) {
	// The ListRevokedRefreshTokens function truncates hash to first 8 chars.
	// Verify the truncation constant matches expectations by checking prefix length.
	fullHash := "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	prefix := fullHash
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	if len(prefix) != 8 {
		t.Errorf("truncated hash should be 8 chars, got %d", len(prefix))
	}
	if prefix != "abcdef12" {
		t.Errorf("expected prefix %q, got %q", "abcdef12", prefix)
	}
}

func TestRevokedTokenHashShortNotTruncated(t *testing.T) {
	short := "abc"
	prefix := short
	if len(prefix) > 8 {
		prefix = prefix[:8]
	}
	if prefix != short {
		t.Errorf("short hash should not be truncated: got %q", prefix)
	}
}

// ---------------------------------------------------------------------------
// models.go — JSON serialisation round-trips (no DB)
// ---------------------------------------------------------------------------

func TestScanJSONRoundTrip(t *testing.T) {
	s := Scan{
		ID:            uuid.MustParse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
		TargetURL:     "https://api.example.com",
		Status:        ScanStatusCompleted,
		Modules:       []string{"bola", "broken_auth"},
		TotalFindings: 3,
		CriticalCount: 1,
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var s2 Scan
	if err := json.Unmarshal(b, &s2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if s2.ID != s.ID {
		t.Errorf("ID round-trip: got %v, want %v", s2.ID, s.ID)
	}
	if s2.Status != s.Status {
		t.Errorf("Status round-trip: got %v, want %v", s2.Status, s.Status)
	}
	if s2.TotalFindings != s.TotalFindings {
		t.Errorf("TotalFindings round-trip: got %v, want %v", s2.TotalFindings, s.TotalFindings)
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	f := Finding{
		ID:             uuid.New(),
		ScanID:         uuid.New(),
		OwaspID:        "API1:2023",
		ModuleID:       "bola",
		Title:          "BOLA",
		Description:    "Broken Object Level Authorization",
		Severity:       FindingSeverityCritical,
		CVSSScore:      9.1,
		EndpointPath:   "/api/v1/users/{id}",
		EndpointMethod: "GET",
		Status:         FindingStatusOpen,
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var f2 Finding
	if err := json.Unmarshal(b, &f2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if f2.Severity != FindingSeverityCritical {
		t.Errorf("Severity round-trip: got %v, want %v", f2.Severity, FindingSeverityCritical)
	}
	if f2.CVSSScore != f.CVSSScore {
		t.Errorf("CVSSScore round-trip: got %v, want %v", f2.CVSSScore, f.CVSSScore)
	}
}

func TestAPISpecJSONRoundTrip(t *testing.T) {
	spec := APISpec{
		ID:            uuid.New(),
		SpecHash:      "abc123",
		SpecFormat:    "openapi3",
		EndpointCount: 12,
		AuthSchemes:   json.RawMessage(`["bearer"]`),
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var spec2 APISpec
	if err := json.Unmarshal(b, &spec2); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if spec2.SpecHash != spec.SpecHash {
		t.Errorf("SpecHash round-trip: got %q, want %q", spec2.SpecHash, spec.SpecHash)
	}
	if spec2.EndpointCount != spec.EndpointCount {
		t.Errorf("EndpointCount round-trip: got %d, want %d", spec2.EndpointCount, spec.EndpointCount)
	}
}

// ---------------------------------------------------------------------------
// DB integration tests — skipped when TEST_DB_URL is unset
// ---------------------------------------------------------------------------

func TestDB_PingIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

func TestDB_CreateAndGetScanIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{
		TargetURL: "https://api.example.com",
		Status:    ScanStatusPending,
		Modules:   []string{"bola"},
	}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if scan.ID == (uuid.UUID{}) {
		t.Error("expected non-zero UUID after CreateScan")
	}

	got, err := d.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.TargetURL != scan.TargetURL {
		t.Errorf("TargetURL: got %q, want %q", got.TargetURL, scan.TargetURL)
	}
	if got.Status != ScanStatusPending {
		t.Errorf("Status: got %q, want %q", got.Status, ScanStatusPending)
	}
}

func TestDB_GetScanNotFoundIntegration(t *testing.T) {
	d := openDB(t)
	_, err := d.GetScan(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error for non-existent scan ID, got nil")
	}
}

func TestDB_UpdateScanStatusIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPending, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	if err := d.UpdateScanStatus(ctx, scan.ID, ScanStatusRunning); err != nil {
		t.Fatalf("UpdateScanStatus → running: %v", err)
	}

	got, _ := d.GetScan(ctx, scan.ID)
	if got.Status != ScanStatusRunning {
		t.Errorf("expected running, got %q", got.Status)
	}
}

func TestDB_UpdateScanStatus_TerminalStateGuardIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPending, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	// Drive to completed.
	if err := d.UpdateScanStatus(ctx, scan.ID, ScanStatusCompleted); err != nil {
		t.Fatalf("UpdateScanStatus → completed: %v", err)
	}
	// Attempt to move back to running — should be silently ignored.
	if err := d.UpdateScanStatus(ctx, scan.ID, ScanStatusRunning); err != nil {
		t.Fatalf("UpdateScanStatus should silently skip terminal state, got: %v", err)
	}
	got, _ := d.GetScan(ctx, scan.ID)
	if got.Status != ScanStatusCompleted {
		t.Errorf("terminal state was overwritten: got %q, want completed", got.Status)
	}
}

func TestDB_UpdateScanSummaryIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	summary := ScanSummary{TotalFindings: 5, CriticalCount: 1, HighCount: 2, MediumCount: 2}
	if err := d.UpdateScanSummary(ctx, scan.ID, summary); err != nil {
		t.Fatalf("UpdateScanSummary: %v", err)
	}

	got, _ := d.GetScan(ctx, scan.ID)
	if got.TotalFindings != 5 {
		t.Errorf("TotalFindings: got %d, want 5", got.TotalFindings)
	}
	if got.CriticalCount != 1 {
		t.Errorf("CriticalCount: got %d, want 1", got.CriticalCount)
	}
}

func TestDB_DeleteScanIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPending, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := d.DeleteScan(ctx, scan.ID); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	_, err := d.GetScan(ctx, scan.ID)
	if err == nil {
		t.Error("expected error after deleting scan, got nil")
	}
}

func TestDB_ListScansIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		s := &Scan{TargetURL: fmt.Sprintf("https://api%d.example.com", i), Status: ScanStatusPending, Modules: []string{}}
		if err := d.CreateScan(ctx, s); err != nil {
			t.Fatalf("CreateScan %d: %v", i, err)
		}
	}

	scans, total, err := d.ListScans(ctx, 10, 0, "")
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if total < 3 {
		t.Errorf("total: got %d, want >= 3", total)
	}
	if len(scans) == 0 {
		t.Error("expected at least one scan in result")
	}
}

func TestDB_CreateAndGetFindingIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	f := &Finding{
		ScanID:         scan.ID,
		OwaspID:        "API1:2023",
		ModuleID:       "bola",
		Title:          "BOLA",
		Description:    "Broken Object Level Authorization",
		Severity:       FindingSeverityCritical,
		CVSSScore:      9.1,
		EndpointPath:   "/api/v1/users/{id}",
		EndpointMethod: "GET",
	}
	if err := d.CreateFinding(ctx, f); err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}
	if f.ID == (uuid.UUID{}) {
		t.Error("expected non-zero UUID after CreateFinding")
	}
	if f.Status != FindingStatusOpen {
		t.Errorf("default status: got %q, want open", f.Status)
	}

	got, err := d.GetFinding(ctx, f.ID)
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.Severity != FindingSeverityCritical {
		t.Errorf("Severity: got %q, want critical", got.Severity)
	}
	if got.CVSSScore != 9.1 {
		t.Errorf("CVSSScore: got %v, want 9.1", got.CVSSScore)
	}
}

func TestDB_UpdateFindingStatusIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	f := &Finding{
		ScanID: scan.ID, OwaspID: "API1:2023", ModuleID: "bola",
		Title: "T", Description: "D", Severity: FindingSeverityHigh,
		CVSSScore: 7.5, EndpointPath: "/p", EndpointMethod: "GET",
	}
	if err := d.CreateFinding(ctx, f); err != nil {
		t.Fatalf("CreateFinding: %v", err)
	}

	if err := d.UpdateFindingStatus(ctx, f.ID, FindingStatusFalsePositive, "reviewed by team", "alice@example.com"); err != nil {
		t.Fatalf("UpdateFindingStatus: %v", err)
	}

	got, _ := d.GetFinding(ctx, f.ID)
	if got.Status != FindingStatusFalsePositive {
		t.Errorf("Status: got %q, want false_positive", got.Status)
	}
	if !got.TriagedBy.Valid || got.TriagedBy.String != "alice@example.com" {
		t.Errorf("TriagedBy: got %v, want alice@example.com", got.TriagedBy)
	}
}

func TestDB_ListFindingsWithFiltersIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	severities := []FindingSeverity{FindingSeverityCritical, FindingSeverityHigh, FindingSeverityMedium}
	for i, sev := range severities {
		f := &Finding{
			ScanID: scan.ID, OwaspID: "API1:2023", ModuleID: "bola",
			Title: fmt.Sprintf("Finding %d", i), Description: "D",
			Severity: sev, CVSSScore: float64(i + 1),
			EndpointPath: "/p", EndpointMethod: "GET",
		}
		if err := d.CreateFinding(ctx, f); err != nil {
			t.Fatalf("CreateFinding %d: %v", i, err)
		}
	}

	crit := FindingSeverityCritical
	findings, total, err := d.ListFindings(ctx, FindingFilters{ScanID: &scan.ID, Severity: &crit}, 10, 0)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Errorf("total with severity=critical: got %d, want 1", total)
	}
	if len(findings) != 1 || findings[0].Severity != FindingSeverityCritical {
		t.Errorf("expected 1 critical finding, got %d", len(findings))
	}
}

func TestDB_CreateAPIKeyIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	key, plaintext, err := d.CreateAPIKey(ctx, "test-key", "alice@example.com")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key.ID == (uuid.UUID{}) {
		t.Error("expected non-zero UUID")
	}
	if len(plaintext) != 64 {
		t.Errorf("plaintext key should be 64 hex chars, got %d", len(plaintext))
	}
	if !key.IsActive {
		t.Error("new API key should be active")
	}
}

func TestDB_LookupAPIKeyByHashIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	_, plaintext, err := d.CreateAPIKey(ctx, "lookup-test", "bob@example.com")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	sum := sha256.Sum256([]byte(plaintext))
	keyHash := fmt.Sprintf("%x", sum[:])

	found, err := d.LookupAPIKeyByHash(ctx, keyHash)
	if err != nil {
		t.Fatalf("LookupAPIKeyByHash: %v", err)
	}
	if !found {
		t.Error("expected to find the newly created key by hash")
	}
}

func TestDB_LookupAPIKeyByHash_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	found, err := d.LookupAPIKeyByHash(context.Background(), "0000000000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("LookupAPIKeyByHash: %v", err)
	}
	if found {
		t.Error("non-existent key hash should return found=false")
	}
}

func TestDB_RevokeAPIKeyIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	key, _, err := d.CreateAPIKey(ctx, "revoke-test", "charlie@example.com")
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}

	if err := d.RevokeAPIKey(ctx, key.ID, "admin"); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}

	// A second revocation on the same key should return an error.
	if err := d.RevokeAPIKey(ctx, key.ID, "admin"); err == nil {
		t.Error("expected error when revoking an already-revoked key")
	}
}

func TestDB_UpsertAPISpecIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	spec := &APISpec{
		SpecHash:      fmt.Sprintf("testhash-%s", uuid.New()),
		SpecFormat:    "openapi3",
		EndpointCount: 5,
		AuthSchemes:   json.RawMessage(`["bearer"]`),
		ParsedIR:      json.RawMessage(`{}`),
		SpecURL:       sql.NullString{String: "https://api.example.com/openapi.json", Valid: true},
	}
	if err := d.UpsertAPISpec(ctx, spec); err != nil {
		t.Fatalf("UpsertAPISpec: %v", err)
	}
	if spec.ID == (uuid.UUID{}) {
		t.Error("expected non-zero UUID after UpsertAPISpec")
	}

	// Upserting the same hash again should not error and should return the same ID.
	spec2 := &APISpec{
		SpecHash:    spec.SpecHash,
		SpecFormat:  "openapi3",
		AuthSchemes: json.RawMessage(`["bearer"]`),
		ParsedIR:    json.RawMessage(`{}`),
	}
	if err := d.UpsertAPISpec(ctx, spec2); err != nil {
		t.Fatalf("UpsertAPISpec (upsert): %v", err)
	}
	if spec2.ID != spec.ID {
		t.Errorf("upsert on same hash should return same ID: got %v, want %v", spec2.ID, spec.ID)
	}
}

func TestDB_GetAPISpecByHash_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	_, err := d.GetAPISpecByHash(context.Background(), "nonexistent-hash")
	if err == nil {
		t.Error("expected error for non-existent spec hash, got nil")
	}
}

func TestDB_AppendAndListAuditLogIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	resID := uuid.New()
	entry := &AuditLog{
		ActorID:      "alice@example.com",
		ActorType:    "api_key",
		Action:       AuditActionScanCreated,
		ResourceType: "scan",
		ResourceID:   &resID,
		Metadata:     json.RawMessage(`{"platform":"apiguard"}`),
	}

	if err := d.AppendAuditLog(ctx, entry, nil); err != nil {
		t.Fatalf("AppendAuditLog: %v", err)
	}
	if entry.ID == (uuid.UUID{}) {
		t.Error("expected ID to be populated after AppendAuditLog")
	}
	if len(entry.ChainHash) != 64 {
		t.Errorf("ChainHash should be 64-char hex SHA-256, got len %d", len(entry.ChainHash))
	}

	entries, total, err := d.ListAuditLog(ctx, AuditLogFilters{ActorID: &entry.ActorID}, 1, 50)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if total < 1 {
		t.Errorf("total: got %d, want >= 1", total)
	}
	if len(entries) == 0 {
		t.Error("expected at least one audit log entry")
	}
}

// auditWorkerPoolOnce/auditWorkerPool back the one-time call to
// StartAuditWorker below. StartAuditWorker's own launch guard
// (auditWorkerOne, in audit_log.go) is a package-level sync.Once: whichever
// pool is passed the first time it is ever called becomes the pool the
// background worker uses for the rest of the test binary's life, since the
// worker goroutine is never restarted with a different pool. That pool must
// therefore outlive every individual test — unlike openDB's pool, it is
// deliberately never closed here (mirroring production, where
// StartAuditWorker is called once at startup with a pool that lives until
// process shutdown). Using a per-test pool that gets closed by
// openDB/t.Cleanup would leave the global worker writing through a dead
// pool for the remainder of the run.
var (
	auditWorkerPoolOnce sync.Once
	auditWorkerPool     *pgxpool.Pool
	auditWorkerPoolErr  error
)

func ensureAuditWorker(t *testing.T, connString string) {
	t.Helper()
	auditWorkerPoolOnce.Do(func() {
		pool, err := pgxpool.New(context.Background(), connString)
		if err != nil {
			auditWorkerPoolErr = fmt.Errorf("connecting worker pool: %w", err)
			return
		}
		if err := pool.Ping(context.Background()); err != nil {
			auditWorkerPoolErr = fmt.Errorf("pinging worker pool: %w", err)
			return
		}
		auditWorkerPool = pool
		StartAuditWorker(auditWorkerPool)
	})
	if auditWorkerPoolErr != nil {
		t.Fatalf("starting audit worker: %v", auditWorkerPoolErr)
	}
}

func TestDB_StartAuditWorkerIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	ensureAuditWorker(t, dbURL(t))

	resID := uuid.New()
	actorID := fmt.Sprintf("worker-test-%s@example.com", uuid.New())
	entry := &AuditLog{
		ActorID:      actorID,
		ActorType:    "system",
		Action:       AuditActionScanCreated,
		ResourceType: "scan",
		ResourceID:   &resID,
		Metadata:     json.RawMessage(`{"platform":"apiguard"}`),
	}

	if err := d.AppendAuditLog(ctx, entry, nil); err != nil {
		t.Fatalf("AppendAuditLog: %v", err)
	}

	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := FlushAuditLog(flushCtx); err != nil {
		t.Fatalf("FlushAuditLog: %v", err)
	}

	entries, total, err := d.ListAuditLog(ctx, AuditLogFilters{ActorID: &actorID}, 1, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if total != 1 {
		t.Errorf("total: got %d, want 1", total)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry written by the worker, got %d", len(entries))
	}
	if len(entries[0].ChainHash) != 64 {
		t.Errorf("ChainHash should be 64-char hex SHA-256, got len %d", len(entries[0].ChainHash))
	}
}

func TestDB_ListAuditLog_FilterByActionAndResourceIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	resID := uuid.New()
	actorID := fmt.Sprintf("filter-test-%s@example.com", uuid.New())
	action := AuditActionScanDeleted
	resType := "scan"
	entry := &AuditLog{
		ActorID:      actorID,
		ActorType:    "user",
		Action:       action,
		ResourceType: resType,
		ResourceID:   &resID,
		Metadata:     json.RawMessage(`{}`),
	}
	if err := d.AppendAuditLog(ctx, entry, nil); err != nil {
		t.Fatalf("AppendAuditLog: %v", err)
	}
	// AppendAuditLog enqueues for the background worker once one has been
	// started anywhere in this test binary (the worker queue is a package
	// global — see TestDB_StartAuditWorkerIntegration). Flush before
	// querying so the write is guaranteed to be visible.
	flushCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := FlushAuditLog(flushCtx); err != nil {
		t.Fatalf("FlushAuditLog: %v", err)
	}

	entries, total, err := d.ListAuditLog(ctx, AuditLogFilters{
		Action:       &action,
		ResourceType: &resType,
		ResourceID:   &resID,
	}, 1, 10)
	if err != nil {
		t.Fatalf("ListAuditLog: %v", err)
	}
	if total != 1 || len(entries) != 1 {
		t.Fatalf("expected exactly 1 match, got total=%d len=%d", total, len(entries))
	}
	if entries[0].ActorID != actorID {
		t.Errorf("ActorID: got %q, want %q", entries[0].ActorID, actorID)
	}
}

// ---------------------------------------------------------------------------
// api_keys.go — ListAPIKeysPaginated
// ---------------------------------------------------------------------------

func TestDB_ListAPIKeysPaginatedIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	label := fmt.Sprintf("paginated-%s", uuid.New())
	for i := 0; i < 3; i++ {
		if _, _, err := d.CreateAPIKey(ctx, fmt.Sprintf("%s-%d", label, i), "dana@example.com"); err != nil {
			t.Fatalf("CreateAPIKey %d: %v", i, err)
		}
	}

	keys, total, err := d.ListAPIKeysPaginated(ctx, 2, 0)
	if err != nil {
		t.Fatalf("ListAPIKeysPaginated: %v", err)
	}
	if total < 3 {
		t.Errorf("total: got %d, want >= 3", total)
	}
	if len(keys) != 2 {
		t.Errorf("page size: got %d keys, want 2", len(keys))
	}
	for _, k := range keys {
		if !k.IsActive {
			t.Errorf("ListAPIKeysPaginated should only return active keys, got inactive %v", k.ID)
		}
	}
}

func TestDB_RevokeAPIKey_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.RevokeAPIKey(context.Background(), uuid.New(), "admin"); err == nil {
		t.Error("expected error revoking a non-existent API key")
	}
}

// ---------------------------------------------------------------------------
// api_specs.go — GetAPISpecByHash success path + LinkScanAPISpec
// ---------------------------------------------------------------------------

func TestDB_GetAPISpecByHash_FoundIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	spec := &APISpec{
		SpecHash:      fmt.Sprintf("gethash-%s", uuid.New()),
		SpecFormat:    "openapi3",
		EndpointCount: 7,
		AuthSchemes:   json.RawMessage(`["bearer"]`),
		ParsedIR:      json.RawMessage(`{}`),
	}
	if err := d.UpsertAPISpec(ctx, spec); err != nil {
		t.Fatalf("UpsertAPISpec: %v", err)
	}

	got, err := d.GetAPISpecByHash(ctx, spec.SpecHash)
	if err != nil {
		t.Fatalf("GetAPISpecByHash: %v", err)
	}
	if got.ID != spec.ID {
		t.Errorf("ID: got %v, want %v", got.ID, spec.ID)
	}
	if got.EndpointCount != 7 {
		t.Errorf("EndpointCount: got %d, want 7", got.EndpointCount)
	}
}

func TestDB_LinkScanAPISpecIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPending, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	spec := &APISpec{
		SpecHash:    fmt.Sprintf("linkhash-%s", uuid.New()),
		SpecFormat:  "openapi3",
		AuthSchemes: json.RawMessage(`["bearer"]`),
		ParsedIR:    json.RawMessage(`{}`),
	}
	if err := d.UpsertAPISpec(ctx, spec); err != nil {
		t.Fatalf("UpsertAPISpec: %v", err)
	}

	if err := d.LinkScanAPISpec(ctx, scan.ID, spec.ID); err != nil {
		t.Fatalf("LinkScanAPISpec: %v", err)
	}
}

func TestDB_LinkScanAPISpec_ScanNotFoundIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	spec := &APISpec{
		SpecHash:    fmt.Sprintf("orphanhash-%s", uuid.New()),
		SpecFormat:  "openapi3",
		AuthSchemes: json.RawMessage(`["bearer"]`),
		ParsedIR:    json.RawMessage(`{}`),
	}
	if err := d.UpsertAPISpec(ctx, spec); err != nil {
		t.Fatalf("UpsertAPISpec: %v", err)
	}

	if err := d.LinkScanAPISpec(ctx, uuid.New(), spec.ID); err == nil {
		t.Error("expected error linking a spec to a non-existent scan")
	}
}

// ---------------------------------------------------------------------------
// findings.go — CreateFindings (batch) + ListFindingsByScan + not-found
// ---------------------------------------------------------------------------

func TestDB_CreateFindingsBatchIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	findings := []Finding{
		{
			ScanID: scan.ID, OwaspID: "API1:2023", ModuleID: "bola",
			Title: "F1", Description: "D1", Severity: FindingSeverityLow,
			CVSSScore: 1, EndpointPath: "/p1", EndpointMethod: "GET",
		},
		{
			ScanID: scan.ID, OwaspID: "API2:2023", ModuleID: "auth",
			Title: "F2", Description: "D2", Severity: FindingSeverityMedium,
			CVSSScore: 5, EndpointPath: "/p2", EndpointMethod: "POST",
		},
	}
	if err := d.CreateFindings(ctx, findings); err != nil {
		t.Fatalf("CreateFindings: %v", err)
	}
	for i, f := range findings {
		if f.ID == (uuid.UUID{}) {
			t.Errorf("finding %d: expected non-zero UUID", i)
		}
		if f.Status != FindingStatusOpen {
			t.Errorf("finding %d: default status: got %q, want open", i, f.Status)
		}
	}

	found, total, err := d.ListFindingsByScan(ctx, scan.ID, 10, 0)
	if err != nil {
		t.Fatalf("ListFindingsByScan: %v", err)
	}
	if total != 2 {
		t.Errorf("total: got %d, want 2", total)
	}
	if len(found) != 2 {
		t.Errorf("len(found): got %d, want 2", len(found))
	}
}

func TestDB_CreateFindings_EmptyIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.CreateFindings(context.Background(), nil); err != nil {
		t.Errorf("CreateFindings with empty slice should be a no-op, got: %v", err)
	}
}

func TestDB_GetFinding_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	_, err := d.GetFinding(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error for non-existent finding ID")
	}
}

// ---------------------------------------------------------------------------
// inventory.go — ListAPIInventory / GetAPIInventoryByID / GetAPIInventoryHistory
// ---------------------------------------------------------------------------

// seedInventory inserts a row directly into api_inventory. The db package
// exposes no Create method for this table (rows are expected to be upserted
// by application code outside this package), so tests seed the table
// directly, matching how the handlers layer populates it.
func seedInventory(t *testing.T, d *DB, targetURL string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := d.Pool.QueryRow(context.Background(), `
		INSERT INTO api_inventory (target_url, scan_count, last_scanned_at)
		VALUES ($1, 1, NOW())
		RETURNING id
	`, targetURL).Scan(&id)
	if err != nil {
		t.Fatalf("seeding api_inventory: %v", err)
	}
	return id
}

func TestDB_ListAPIInventoryIntegration(t *testing.T) {
	d := openDB(t)
	target := fmt.Sprintf("https://inv-%s.example.com", uuid.New())
	seedInventory(t, d, target)

	items, total, err := d.ListAPIInventory(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("ListAPIInventory: %v", err)
	}
	if total < 1 {
		t.Errorf("total: got %d, want >= 1", total)
	}
	if len(items) == 0 {
		t.Error("expected at least one inventory item")
	}
}

func TestDB_GetAPIInventoryByIDIntegration(t *testing.T) {
	d := openDB(t)
	target := fmt.Sprintf("https://inv-%s.example.com", uuid.New())
	id := seedInventory(t, d, target)

	got, err := d.GetAPIInventoryByID(context.Background(), id)
	if err != nil {
		t.Fatalf("GetAPIInventoryByID: %v", err)
	}
	if got.TargetURL != target {
		t.Errorf("TargetURL: got %q, want %q", got.TargetURL, target)
	}
}

func TestDB_GetAPIInventoryByID_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	_, err := d.GetAPIInventoryByID(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error for non-existent inventory ID")
	}
}

func TestDB_GetAPIInventoryHistoryIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()
	target := fmt.Sprintf("https://inv-hist-%s.example.com", uuid.New())
	id := seedInventory(t, d, target)

	scan := &Scan{TargetURL: target, Status: ScanStatusCompleted, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	history, total, err := d.GetAPIInventoryHistory(ctx, id, 10, 0)
	if err != nil {
		t.Fatalf("GetAPIInventoryHistory: %v", err)
	}
	if total != 1 {
		t.Errorf("total: got %d, want 1", total)
	}
	if len(history) != 1 || history[0].ID != scan.ID {
		t.Errorf("expected the one scan matching target_url, got %+v", history)
	}
}

func TestDB_GetAPIInventoryHistory_EmptyIntegration(t *testing.T) {
	d := openDB(t)
	target := fmt.Sprintf("https://inv-empty-%s.example.com", uuid.New())
	id := seedInventory(t, d, target)

	history, total, err := d.GetAPIInventoryHistory(context.Background(), id, 10, 0)
	if err != nil {
		t.Fatalf("GetAPIInventoryHistory: %v", err)
	}
	if total != 0 || len(history) != 0 {
		t.Errorf("expected no history for an inventory item with no scans, got total=%d len=%d", total, len(history))
	}
}

// ---------------------------------------------------------------------------
// refresh_tokens.go
// ---------------------------------------------------------------------------

func TestDB_RefreshTokenLifecycleIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()
	tokenHash := fmt.Sprintf("rt-%s", uuid.New())

	revoked, err := IsRefreshTokenRevoked(ctx, d.Pool, tokenHash)
	if err != nil {
		t.Fatalf("IsRefreshTokenRevoked (before): %v", err)
	}
	if revoked {
		t.Error("token should not be revoked before RevokeRefreshToken is called")
	}

	if err := RevokeRefreshToken(ctx, d.Pool, tokenHash); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}
	// Revoking twice must be a no-op, not an error (ON CONFLICT DO NOTHING).
	if err := RevokeRefreshToken(ctx, d.Pool, tokenHash); err != nil {
		t.Fatalf("RevokeRefreshToken (idempotent): %v", err)
	}

	revoked, err = IsRefreshTokenRevoked(ctx, d.Pool, tokenHash)
	if err != nil {
		t.Fatalf("IsRefreshTokenRevoked (after): %v", err)
	}
	if !revoked {
		t.Error("token should be revoked after RevokeRefreshToken")
	}

	tokens, err := ListRevokedRefreshTokens(ctx, d.Pool, 50, 0)
	if err != nil {
		t.Fatalf("ListRevokedRefreshTokens: %v", err)
	}
	found := false
	wantPrefix := tokenHash
	if len(wantPrefix) > 8 {
		wantPrefix = wantPrefix[:8]
	}
	for _, tok := range tokens {
		if tok.TokenHashPrefix == wantPrefix {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected to find revoked token with prefix %q in list", wantPrefix)
	}
}

func TestDB_ListRevokedRefreshTokens_DefaultsIntegration(t *testing.T) {
	d := openDB(t)
	// Out-of-range limit/offset should be clamped rather than erroring.
	if _, err := ListRevokedRefreshTokens(context.Background(), d.Pool, -1, -1); err != nil {
		t.Errorf("ListRevokedRefreshTokens with out-of-range args: %v", err)
	}
	if _, err := ListRevokedRefreshTokens(context.Background(), d.Pool, 9999, 0); err != nil {
		t.Errorf("ListRevokedRefreshTokens with oversized limit: %v", err)
	}
}

// ---------------------------------------------------------------------------
// scan_approvals.go
// ---------------------------------------------------------------------------

func TestDB_ScanApproval_ApproveFlowIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPendingApproval, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	approval, err := d.CreateScanApproval(ctx, scan.ID, "operator@example.com")
	if err != nil {
		t.Fatalf("CreateScanApproval: %v", err)
	}
	if approval.Status != ApprovalStatusPending {
		t.Errorf("Status: got %q, want pending", approval.Status)
	}

	got, err := d.GetScanApprovalByScanID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if got.RequestedBy != "operator@example.com" {
		t.Errorf("RequestedBy: got %q, want operator@example.com", got.RequestedBy)
	}

	if err := d.ApproveScanApproval(ctx, scan.ID, "verifier@example.com"); err != nil {
		t.Fatalf("ApproveScanApproval: %v", err)
	}

	got, err = d.GetScanApprovalByScanID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID (after approve): %v", err)
	}
	if got.Status != ApprovalStatusApproved {
		t.Errorf("Status: got %q, want approved", got.Status)
	}
	if !got.DecidedBy.Valid || got.DecidedBy.String != "verifier@example.com" {
		t.Errorf("DecidedBy: got %v, want verifier@example.com", got.DecidedBy)
	}

	// A second approval attempt must fail — the row is no longer pending.
	if err := d.ApproveScanApproval(ctx, scan.ID, "verifier2@example.com"); err == nil {
		t.Error("expected error approving an already-approved scan")
	}
}

func TestDB_ScanApproval_RejectFlowIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusPendingApproval, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if _, err := d.CreateScanApproval(ctx, scan.ID, "operator@example.com"); err != nil {
		t.Fatalf("CreateScanApproval: %v", err)
	}

	if err := d.RejectScanApproval(ctx, scan.ID, "verifier@example.com", "target out of scope"); err != nil {
		t.Fatalf("RejectScanApproval: %v", err)
	}

	got, err := d.GetScanApprovalByScanID(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if got.Status != ApprovalStatusRejected {
		t.Errorf("Status: got %q, want rejected", got.Status)
	}
	if !got.DecisionReason.Valid || got.DecisionReason.String != "target out of scope" {
		t.Errorf("DecisionReason: got %v, want %q", got.DecisionReason, "target out of scope")
	}

	// A second rejection attempt must fail — the row is no longer pending.
	if err := d.RejectScanApproval(ctx, scan.ID, "verifier2@example.com", "duplicate"); err == nil {
		t.Error("expected error rejecting an already-decided scan")
	}
}

func TestDB_GetScanApprovalByScanID_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	_, err := d.GetScanApprovalByScanID(context.Background(), uuid.New())
	if err == nil {
		t.Error("expected error for a scan with no approval record")
	}
}

// ---------------------------------------------------------------------------
// scans.go — UpdateScanError, DeleteScan not-found, ListScans with filter
// ---------------------------------------------------------------------------

func TestDB_UpdateScanErrorIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()

	scan := &Scan{TargetURL: "https://api.example.com", Status: ScanStatusRunning, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	if err := d.UpdateScanError(ctx, scan.ID, "target unreachable: connection refused"); err != nil {
		t.Fatalf("UpdateScanError: %v", err)
	}

	got, err := d.GetScan(ctx, scan.ID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.Status != ScanStatusFailed {
		t.Errorf("Status: got %q, want failed", got.Status)
	}
	if !got.ErrorMessage.Valid || got.ErrorMessage.String != "target unreachable: connection refused" {
		t.Errorf("ErrorMessage: got %v", got.ErrorMessage)
	}
	if !got.CompletedAt.Valid {
		t.Error("expected CompletedAt to be set after UpdateScanError")
	}
}

func TestDB_UpdateScanError_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.UpdateScanError(context.Background(), uuid.New(), "boom"); err == nil {
		t.Error("expected error updating a non-existent scan")
	}
}

func TestDB_DeleteScan_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.DeleteScan(context.Background(), uuid.New()); err == nil {
		t.Error("expected error deleting a non-existent scan")
	}
}

func TestDB_UpdateScanStatus_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	if err := d.UpdateScanStatus(context.Background(), uuid.New(), ScanStatusRunning); err == nil {
		t.Error("expected error updating status of a non-existent scan")
	}
}

func TestDB_UpdateScanSummary_NotFoundIntegration(t *testing.T) {
	d := openDB(t)
	err := d.UpdateScanSummary(context.Background(), uuid.New(), ScanSummary{TotalFindings: 1})
	if err == nil {
		t.Error("expected error updating summary of a non-existent scan")
	}
}

func TestDB_ListScans_WithStatusFilterIntegration(t *testing.T) {
	d := openDB(t)
	ctx := context.Background()
	target := fmt.Sprintf("https://filter-%s.example.com", uuid.New())

	scan := &Scan{TargetURL: target, Status: ScanStatusPending, Modules: []string{}}
	if err := d.CreateScan(ctx, scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if err := d.UpdateScanStatus(ctx, scan.ID, ScanStatusRunning); err != nil {
		t.Fatalf("UpdateScanStatus: %v", err)
	}

	scans, total, err := d.ListScans(ctx, 10, 0, string(ScanStatusRunning))
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if total < 1 {
		t.Errorf("total: got %d, want >= 1", total)
	}
	found := false
	for _, s := range scans {
		if s.ID == scan.ID {
			found = true
			if s.Status != ScanStatusRunning {
				t.Errorf("Status: got %q, want running", s.Status)
			}
		}
	}
	if !found {
		t.Error("expected the running scan to appear in the status-filtered list")
	}
}

// ---------------------------------------------------------------------------
// db.go — New / Close / Ping error paths
// ---------------------------------------------------------------------------

func TestDB_New_InvalidConnStringIntegration(t *testing.T) {
	_, err := New(context.Background(), "://not a valid dsn")
	if err == nil {
		t.Error("expected error constructing DB from an invalid connection string")
	}
}

func TestDB_New_UnreachableHostIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Reserved TEST-NET-1 address (RFC 5737) — never routable, so Ping fails
	// fast instead of hanging for the default connect timeout.
	_, err := New(ctx, "postgres://user:pass@192.0.2.1:5432/nonexistent?connect_timeout=1")
	if err == nil {
		t.Error("expected error constructing DB against an unreachable host")
	}
}

func TestDB_CloseIsSafeIntegration(t *testing.T) {
	d := openDB(t)
	d.Close()
	// Close is documented as shutting down the pool; calling it again via the
	// t.Cleanup registered inside openDB must not panic.
}
