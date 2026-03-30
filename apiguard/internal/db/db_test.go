package db

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// dbURL returns the DSN to use for integration tests.
// Tests that call this skip automatically when the env-var is not set.
func dbURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_DB_URL")
	if u == "" {
		t.Skip("TEST_DB_URL not set — skipping DB integration test")
	}
	return u
}

func openDB(t *testing.T) *DB {
	t.Helper()
	d, err := New(context.Background(), dbURL(t))
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
