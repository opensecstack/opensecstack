package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/citadel"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
)

// ---------------------------------------------------------------------------
// Pure unit tests — no database, no network required.
// ---------------------------------------------------------------------------

// TestPendingRequest_RememberTakeDelete verifies the in-memory registry that
// holds a scan's ephemeral request (and the Operator's bearer token) between
// creation and approval behaves as a single-use, deletable store.
func TestPendingRequest_RememberTakeDelete(t *testing.T) {
	s := &Scans{}
	id := uuid.New()
	req := createScanRequest{Target: "https://api.example.com", AuthToken: "target-secret"}

	// Nothing stored yet.
	if _, _, found := s.takePendingRequest(id); found {
		t.Fatal("expected no pending request before rememberPendingRequest")
	}

	s.rememberPendingRequest(id, req, "operator-bearer-token")

	got, actorToken, found := s.takePendingRequest(id)
	if !found {
		t.Fatal("expected pending request to be found")
	}
	if got.Target != req.Target || got.AuthToken != req.AuthToken {
		t.Errorf("pending request mismatch: got %+v, want %+v", got, req)
	}
	if actorToken != "operator-bearer-token" {
		t.Errorf("expected actorToken %q, got %q", "operator-bearer-token", actorToken)
	}

	// Single-use: a second take must not find it.
	if _, _, found := s.takePendingRequest(id); found {
		t.Error("expected pending request to be consumed after first take")
	}
}

// TestPendingRequest_DeleteWithoutTaking verifies deletePendingRequest (used
// on manual rejection) discards an entry without needing to read it back.
func TestPendingRequest_DeleteWithoutTaking(t *testing.T) {
	s := &Scans{}
	id := uuid.New()
	s.rememberPendingRequest(id, createScanRequest{Target: "https://x"}, "tok")
	s.deletePendingRequest(id)
	if _, _, found := s.takePendingRequest(id); found {
		t.Error("expected pending request to be gone after deletePendingRequest")
	}
}

// TestPendingRequest_ExpiresAfterTTL verifies stale pending requests (e.g. an
// approval that never happened) are swept out rather than kept forever.
func TestPendingRequest_ExpiresAfterTTL(t *testing.T) {
	s := &Scans{}
	id := uuid.New()
	s.rememberPendingRequest(id, createScanRequest{Target: "https://x"}, "tok")

	// Backdate the entry past the TTL directly (white-box, same package).
	s.pendingMu.Lock()
	entry := s.pendingReqs[id]
	entry.createdAt = time.Now().Add(-pendingApprovalTTL - time.Minute)
	s.pendingReqs[id] = entry
	s.pendingMu.Unlock()

	if _, _, found := s.takePendingRequest(id); found {
		t.Error("expected expired pending request to be swept, not returned")
	}
}

// TestApprovalCitadelKerkese_DistinctIdentitiesAndTokens verifies the Kerkese
// built for a real second-approver decision carries two distinct, real
// sinauth UserIDs (Operator vs Verifier) and two distinct real bearer tokens
// — the core guarantee this feature exists to provide, replacing the fixed
// "apiguard-system-verifier" placeholder used when approval is not required.
func TestApprovalCitadelKerkese_DistinctIdentitiesAndTokens(t *testing.T) {
	s := &Scans{cfg: &config.Config{Citadel: config.CitadelConfig{ProjectID: "apiguard-test", DryRun: true}}}
	scanID := uuid.New()
	req := createScanRequest{Target: "https://api.example.com", Modules: []string{"broken_auth"}}

	const (
		operatorUserID = "11111111-1111-1111-1111-111111111111"
		operatorToken  = "operator-real-bearer-token"
		verifierUserID = "22222222-2222-2222-2222-222222222222"
		verifierToken  = "verifier-real-bearer-token"
	)

	k := s.approvalCitadelKerkese(scanID, operatorUserID, operatorToken, verifierUserID, verifierToken, req)

	if k.Actor.UserID != operatorUserID {
		t.Errorf("Actor.UserID = %q, want %q", k.Actor.UserID, operatorUserID)
	}
	if k.Verifier.UserID != verifierUserID {
		t.Errorf("Verifier.UserID = %q, want %q", k.Verifier.UserID, verifierUserID)
	}
	if k.Actor.UserID == k.Verifier.UserID {
		t.Error("Actor and Verifier UserIDs must be distinct — this is the whole point of Gate 3 NDS")
	}
	if k.SoD.OperatorUserID != operatorUserID || k.SoD.VerifierUserID != verifierUserID {
		t.Errorf("SoD identities mismatch: got operator=%q verifier=%q", k.SoD.OperatorUserID, k.SoD.VerifierUserID)
	}

	if k.ActorToken != operatorToken {
		t.Errorf("ActorToken = %q, want %q", k.ActorToken, operatorToken)
	}
	if k.VerifierToken != verifierToken {
		t.Errorf("VerifierToken = %q, want %q", k.VerifierToken, verifierToken)
	}
	if k.ActorToken == k.VerifierToken {
		t.Error("ActorToken and VerifierToken must be distinct real tokens, not the same value")
	}
	// Never the old fixed placeholder.
	if k.Verifier.UserID == "apiguard-system-verifier" {
		t.Error("Verifier must never be the fixed placeholder when a real approval flow is used")
	}
}

// TestApprove_Unauthorized_NoClaims verifies the endpoint rejects requests
// with no authenticated caller before touching the database at all — this
// runs without TEST_DB_URL because the auth check is the very first thing
// the handler does.
func TestApprove_Unauthorized_NoClaims(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+uuid.New().String()+"/approve", nil)
	req = injectChiID(req, uuid.New().String())
	rec := httptest.NewRecorder()
	h.Approve(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for unauthenticated approve, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestReject_Unauthorized_NoClaims mirrors TestApprove_Unauthorized_NoClaims
// for the reject endpoint.
func TestReject_Unauthorized_NoClaims(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+uuid.New().String()+"/reject", nil)
	req = injectChiID(req, uuid.New().String())
	rec := httptest.NewRecorder()
	h.Reject(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for unauthenticated reject, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestApprove_InvalidUUID verifies UUID validation happens before anything
// else (no DB, no auth needed to fail this).
func TestApprove_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/not-a-uuid/approve", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Approve(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Integration tests — require a live Postgres (TEST_DB_URL), like
// internal/db's own test suite. These exercise Approve()/Reject()/Create()
// end-to-end against real scan_approvals rows. A fake CITADEL server
// captures the Kerkese so we can assert on its contents without depending on
// a real CITADEL deployment or network access for the scan itself.
// ---------------------------------------------------------------------------

// handlersMigrationsOnce/handlersMigrationsErr guard a single application of
// migrations/*.up.sql against the target database for the lifetime of this
// package's test binary. `go test ./...` runs each package's tests in its
// own process against the same CI Postgres service container, and there is
// no guarantee that internal/db's own test binary (which applies migrations
// via its own ensureSchema helper) runs — let alone finishes — before this
// package's binary connects. Relying on that cross-process ordering was the
// root cause of "relation \"scans\" does not exist" failures in CI: this
// package must ensure its own schema instead of assuming another package's
// test run already created it.
var (
	handlersMigrationsOnce sync.Once
	handlersMigrationsErr  error
)

// ensureHandlersTestSchema applies every pending migration under
// ../../../migrations to connString, mirroring cmd/migrate's up logic and
// internal/db's db_test.go helper of the same shape. It is intentionally
// duplicated (rather than shared) because that logic lives in a _test.go
// file in package db, which is not importable from here.
func ensureHandlersTestSchema(t *testing.T, connString string) {
	t.Helper()
	handlersMigrationsOnce.Do(func() {
		handlersMigrationsErr = applyHandlersTestMigrations(connString)
	})
	if handlersMigrationsErr != nil {
		t.Fatalf("applying migrations: %v", handlersMigrationsErr)
	}
}

func applyHandlersTestMigrations(connString string) error {
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

	migrationsDir := filepath.Join("..", "..", "..", "migrations")
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

	return nil
}

func approvalTestDB(t *testing.T) *db.DB {
	t.Helper()
	u := os.Getenv("DATABASE_URL")
	if u == "" {
		u = os.Getenv("TEST_DB_URL")
	}
	if u == "" {
		t.Skip("DATABASE_URL/TEST_DB_URL not set — skipping DB integration test")
	}
	ensureHandlersTestSchema(t, u)
	d, err := db.New(context.Background(), u)
	if err != nil {
		t.Fatalf("db.New: %v", err)
	}
	t.Cleanup(d.Close)
	return d
}

// fakeCitadel spins up an httptest.Server that mimics CITADEL's
// /api/v1/marshal/evaluate endpoint just enough to drive Approve(): it
// captures every submitted Kerkese and always returns the configured outcome.
type fakeCitadel struct {
	server  *httptest.Server
	mu      sync.Mutex
	kerkese []citadel.Kerkese
	outcome string
}

func newFakeCitadel(outcome string) *fakeCitadel {
	f := &fakeCitadel{outcome: outcome}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var k citadel.Kerkese
		_ = json.NewDecoder(r.Body).Decode(&k)
		f.mu.Lock()
		f.kerkese = append(f.kerkese, k)
		f.mu.Unlock()

		reasons := []string(nil)
		if outcome != citadel.OutcomeExecute {
			reasons = []string{"fake CITADEL: forced " + outcome + " for test"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(citadel.Decision{
			Outcome: outcome,
			Reasons: reasons,
		})
	}))
	return f
}

func (f *fakeCitadel) close() { f.server.Close() }

func (f *fakeCitadel) lastKerkese() (citadel.Kerkese, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.kerkese) == 0 {
		return citadel.Kerkese{}, false
	}
	return f.kerkese[len(f.kerkese)-1], true
}

// setupApprovalScan creates a scan in 'pending_approval' status plus its
// scan_approvals row directly against the DB (bypassing Create(), which is
// tested separately), and remembers the ephemeral request in-memory exactly
// as Create() would have. Returns the scan ID.
func setupApprovalScan(t *testing.T, d *db.DB, h *Scans, requestedBy, actorToken string) uuid.UUID {
	t.Helper()
	scan := &db.Scan{TargetURL: "https://api.example.com", Status: db.ScanStatusPendingApproval, Modules: []string{}}
	if err := d.CreateScan(context.Background(), scan); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteScan(context.Background(), scan.ID) })

	if _, err := d.CreateScanApproval(context.Background(), scan.ID, requestedBy); err != nil {
		t.Fatalf("CreateScanApproval: %v", err)
	}
	h.rememberPendingRequest(scan.ID, createScanRequest{Target: scan.TargetURL}, actorToken)
	return scan.ID
}

func approveRequest(scanID uuid.UUID, approverUserID, approverToken string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+scanID.String()+"/approve", nil)
	req = injectChiID(req, scanID.String())
	req.Header.Set("Authorization", "Bearer "+approverToken)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: approverUserID})
	return req.WithContext(ctx)
}

// TestApprove_SameUser_Forbidden verifies the Separation-of-Duties guard:
// the user who requested the scan may never also approve it.
func TestApprove_SameUser_Forbidden(t *testing.T) {
	d := approvalTestDB(t)
	h := NewScans(zerolog.Nop(), d, nil, context.Background())

	const operatorUserID = "same-user-11111111-1111-1111-1111-111111111111"
	scanID := setupApprovalScan(t, d, h, operatorUserID, "operator-token")

	req := approveRequest(scanID, operatorUserID, "operator-token-again")
	rec := httptest.NewRecorder()
	h.Approve(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 for same-user approval attempt, got %d; body: %s", rec.Code, rec.Body.String())
	}

	approval, err := d.GetScanApprovalByScanID(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if approval.Status != db.ApprovalStatusPending {
		t.Errorf("same-user rejection must not change approval status; got %q", approval.Status)
	}
}

// TestApprove_DifferentUser_CitadelHardStop_CapturesRealDistinctIdentities
// verifies a genuinely different second user passes the identity check, that
// the Kerkese CITADEL receives carries two distinct real UserIDs and two
// distinct real bearer tokens, and that a HARD_STOP outcome rejects the scan
// (rather than silently letting it through).
func TestApprove_DifferentUser_CitadelHardStop_CapturesRealDistinctIdentities(t *testing.T) {
	d := approvalTestDB(t)
	fc := newFakeCitadel(citadel.OutcomeHardStop)
	defer fc.close()

	cfg := &config.Config{Citadel: config.CitadelConfig{ProjectID: "apiguard-test", DryRun: true}}
	cc := citadel.New(fc.server.URL, "test-key", "test-secret")
	h := NewScansWithCitadel(zerolog.Nop(), d, nil, cc, context.Background(), cfg)

	const (
		operatorUserID = "operator-22222222-2222-2222-2222-222222222222"
		operatorToken  = "operator-real-token"
		verifierUserID = "verifier-33333333-3333-3333-3333-333333333333"
		verifierToken  = "verifier-real-token"
	)
	scanID := setupApprovalScan(t, d, h, operatorUserID, operatorToken)

	req := approveRequest(scanID, verifierUserID, verifierToken)
	rec := httptest.NewRecorder()
	h.Approve(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 when CITADEL HARD_STOPs the approval, got %d; body: %s", rec.Code, rec.Body.String())
	}

	k, ok := fc.lastKerkese()
	if !ok {
		t.Fatal("expected CITADEL to have received a Kerkese")
	}
	if k.Actor.UserID != operatorUserID || k.Verifier.UserID != verifierUserID {
		t.Errorf("Kerkese identities: got actor=%q verifier=%q, want actor=%q verifier=%q",
			k.Actor.UserID, k.Verifier.UserID, operatorUserID, verifierUserID)
	}
	if k.Actor.UserID == k.Verifier.UserID {
		t.Error("Kerkese must never carry the same identity for Actor and Verifier")
	}
	if k.ActorToken != operatorToken || k.VerifierToken != verifierToken {
		t.Errorf("Kerkese tokens: got actor_token=%q verifier_token=%q, want %q / %q",
			k.ActorToken, k.VerifierToken, operatorToken, verifierToken)
	}
	if k.ActorToken == k.VerifierToken {
		t.Error("Kerkese must never carry the same token for both parties")
	}

	approval, err := d.GetScanApprovalByScanID(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if approval.Status != db.ApprovalStatusRejected {
		t.Errorf("expected approval status rejected after HARD_STOP, got %q", approval.Status)
	}
}

// TestApprove_DifferentUser_CitadelExecutes_Approves verifies the happy path:
// a genuinely different second user approves, CITADEL returns EXECUTE, and
// the approval record + scan status move forward accordingly.
func TestApprove_DifferentUser_CitadelExecutes_Approves(t *testing.T) {
	d := approvalTestDB(t)
	fc := newFakeCitadel(citadel.OutcomeExecute)
	defer fc.close()

	cfg := &config.Config{Citadel: config.CitadelConfig{ProjectID: "apiguard-test", DryRun: true}}
	cc := citadel.New(fc.server.URL, "test-key", "test-secret")
	h := NewScansWithCitadel(zerolog.Nop(), d, nil, cc, context.Background(), cfg)

	const (
		operatorUserID = "operator-44444444-4444-4444-4444-444444444444"
		verifierUserID = "verifier-55555555-5555-5555-5555-555555555555"
	)
	scanID := setupApprovalScan(t, d, h, operatorUserID, "operator-token")

	req := approveRequest(scanID, verifierUserID, "verifier-token")
	rec := httptest.NewRecorder()
	h.Approve(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 for a distinct-user approval CITADEL executes, got %d; body: %s", rec.Code, rec.Body.String())
	}

	approval, err := d.GetScanApprovalByScanID(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if approval.Status != db.ApprovalStatusApproved {
		t.Errorf("expected approval status approved, got %q", approval.Status)
	}
	if !approval.DecidedBy.Valid || approval.DecidedBy.String != verifierUserID {
		t.Errorf("expected decided_by=%q, got %+v", verifierUserID, approval.DecidedBy)
	}

	// Let the background launchScan goroutine (scanner is nil in this test —
	// it will fail fast trying to run, which is fine: we only care that the
	// approval/database transition happened, not that a real scan completed)
	// finish before the test process exits, without hanging forever.
	waitCh := make(chan struct{})
	go func() { h.WaitScans(); close(waitCh) }()
	select {
	case <-waitCh:
	case <-time.After(5 * time.Second):
		t.Log("background scan goroutine did not finish within 5s (scanner is nil in this test); not a test failure")
	}
}

// TestReject_DifferentUser_MarksRejected verifies a genuine second reviewer
// can manually decline a pending scan without ever calling CITADEL.
func TestReject_DifferentUser_MarksRejected(t *testing.T) {
	d := approvalTestDB(t)
	h := NewScans(zerolog.Nop(), d, nil, context.Background())

	const (
		operatorUserID = "operator-66666666-6666-6666-6666-666666666666"
		reviewerUserID = "reviewer-77777777-7777-7777-7777-777777777777"
	)
	scanID := setupApprovalScan(t, d, h, operatorUserID, "operator-token")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+scanID.String()+"/reject",
		strings.NewReader(`{"reason":"target out of scope"}`))
	req = injectChiID(req, scanID.String())
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: reviewerUserID})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.Reject(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 for a distinct-user reject, got %d; body: %s", rec.Code, rec.Body.String())
	}

	approval, err := d.GetScanApprovalByScanID(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if approval.Status != db.ApprovalStatusRejected {
		t.Errorf("expected approval status rejected, got %q", approval.Status)
	}
	if !approval.DecidedBy.Valid || approval.DecidedBy.String != reviewerUserID {
		t.Errorf("expected decided_by=%q, got %+v", reviewerUserID, approval.DecidedBy)
	}

	scan, err := d.GetScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Status != db.ScanStatusFailed {
		t.Errorf("expected scan status failed after rejection, got %q", scan.Status)
	}
}

// TestCreate_RequireApproval_ReturnsPendingApproval verifies that with
// citadel.require_approval enabled, scan creation stops at 'pending_approval'
// instead of launching — the default-off case is already covered by the
// pre-existing TestScansCreate_* tests, which continue to pass unmodified.
func TestCreate_RequireApproval_ReturnsPendingApproval(t *testing.T) {
	d := approvalTestDB(t)
	cfg := &config.Config{Citadel: config.CitadelConfig{ProjectID: "apiguard-test", RequireApproval: true}}
	h := NewScansWithCitadel(zerolog.Nop(), d, nil, nil, context.Background(), cfg)

	// Use a local spec_path (not spec_url) so this test needs no DNS/network
	// access — Create() never reaches the point of actually parsing it, since
	// citadel.require_approval stops the request at 'pending_approval'.
	specFile, err := os.CreateTemp("", "apiguard-approval-test-spec-*.json")
	if err != nil {
		t.Fatalf("creating temp spec file: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(specFile.Name()) })
	_ = specFile.Close()

	const operatorUserID = "operator-88888888-8888-8888-8888-888888888888"
	bodyBytes, err := json.Marshal(map[string]string{
		"target":    "https://api.example.com",
		"spec_path": specFile.Name(),
	})
	if err != nil {
		t.Fatalf("marshaling request body: %v", err)
	}
	body := strings.NewReader(string(bodyBytes))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans", body)
	req.Header.Set("Content-Type", "application/json")
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: operatorUserID})
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.Create(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["status"] != string(db.ScanStatusPendingApproval) {
		t.Errorf("expected status %q, got %q", db.ScanStatusPendingApproval, resp["status"])
	}
	scanID, err := uuid.Parse(resp["id"])
	if err != nil {
		t.Fatalf("parsing returned scan id: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteScan(context.Background(), scanID) })

	approval, err := d.GetScanApprovalByScanID(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScanApprovalByScanID: %v", err)
	}
	if approval.RequestedBy != operatorUserID {
		t.Errorf("expected requested_by=%q, got %q", operatorUserID, approval.RequestedBy)
	}
	if approval.Status != db.ApprovalStatusPending {
		t.Errorf("expected approval status pending, got %q", approval.Status)
	}

	scan, err := d.GetScan(context.Background(), scanID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.Status != db.ScanStatusPendingApproval {
		t.Errorf("expected scan status pending_approval, got %q", scan.Status)
	}
}
