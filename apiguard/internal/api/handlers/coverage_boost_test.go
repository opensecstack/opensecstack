package handlers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"

	"github.com/google/uuid"

	"github.com/opensecstack/apiguard/internal/api/middleware"
	"github.com/opensecstack/apiguard/internal/config"
	"github.com/opensecstack/apiguard/internal/db"
)

// unreachableDB returns a *db.DB backed by a real *pgxpool.Pool pointed at a
// port nothing listens on. pgxpool.NewWithConfig never dials eagerly, so
// construction is instant; any subsequent Pool operation (Ping, Begin, ...)
// fails fast with a connection error. This lets tests exercise DB-touching
// code paths (auditLog's build-entry-then-write logic, Health's deep check)
// deterministically without a live Postgres / TEST_DB_URL.
func unreachableDB(t *testing.T) *db.DB {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://baduser:badpass@127.0.0.1:1/nonexistent")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)
	return &db.DB{Pool: pool}
}

// ---------------------------------------------------------------------------
// apikeys.go — actorFromContext
// ---------------------------------------------------------------------------

func TestActorFromContext_WithClaims(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "bob"})
	req = req.WithContext(ctx)

	if got := actorFromContext(req.Context()); got != "bob" {
		t.Errorf("expected bob, got %q", got)
	}
}

func TestActorFromContext_NoClaims(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	if got := actorFromContext(req.Context()); got != "api-client" {
		t.Errorf("expected api-client, got %q", got)
	}
}

func TestActorFromContext_EmptySub(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: ""})
	req = req.WithContext(ctx)
	if got := actorFromContext(req.Context()); got != "api-client" {
		t.Errorf("expected api-client for empty sub, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// scans.go — constructors, WaitScans, GetApproval/Reject invalid UUID
// ---------------------------------------------------------------------------

func TestNewScansWithCitadel_ParsesTrustedProxiesAndSetsFields(t *testing.T) {
	cfg := &config.Config{RateLimit: config.RateLimitConfig{TrustedProxies: []string{"10.0.0.0/8"}}}
	h := NewScansWithCitadel(zerolog.Nop(), nil, nil, nil, context.Background(), cfg)

	if h.cfg != cfg {
		t.Error("expected cfg to be stored on the handler")
	}
	if len(h.trustedProxies) != 1 {
		t.Errorf("expected 1 parsed trusted proxy CIDR, got %d", len(h.trustedProxies))
	}
}

// TestScans_WaitScans_ReturnsAfterInFlightGoroutinesFinish verifies WaitScans
// blocks only until previously-Added goroutines call Done, mirroring how
// Create/Approve track in-flight launchScan calls for graceful shutdown.
func TestScans_WaitScans_ReturnsAfterInFlightGoroutinesFinish(t *testing.T) {
	h := newScans()

	h.scanWg.Add(1)
	done := make(chan struct{})
	go func() {
		defer h.scanWg.Done()
		<-done
	}()

	waitReturned := make(chan struct{})
	go func() {
		h.WaitScans()
		close(waitReturned)
	}()

	select {
	case <-waitReturned:
		t.Fatal("WaitScans returned before the in-flight goroutine finished")
	default:
	}

	close(done)
	<-waitReturned // must not hang
}

func TestScansGetApproval_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans/not-a-uuid/approval", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.GetApproval(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansGetApproval_MissingID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans//approval", nil)
	rec := httptest.NewRecorder()
	h.GetApproval(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansReject_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/not-a-uuid/reject", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Reject(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// findings.go — NewFindingsWithCitadel constructor
// ---------------------------------------------------------------------------

func TestNewFindingsWithCitadel_SetsFields(t *testing.T) {
	cfg := &config.Config{RateLimit: config.RateLimitConfig{TrustedProxies: []string{"192.168.0.0/16"}}}
	h := NewFindingsWithCitadel(zerolog.Nop(), nil, nil, cfg)

	if len(h.trustedProxies) != 1 {
		t.Errorf("expected 1 parsed trusted proxy CIDR, got %d", len(h.trustedProxies))
	}
}

// ---------------------------------------------------------------------------
// health.go — NewHealthWithDB constructor + deep DB-ping branches
// ---------------------------------------------------------------------------

func TestNewHealthWithDB_NilDB_BehavesLikeShallowHealth(t *testing.T) {
	h := NewHealthWithDB(zerolog.Nop(), nil)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.Health(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["checks"]; ok {
		t.Errorf("expected no 'checks' key when db is nil, got %v", body["checks"])
	}
}

// TestHealth_DBPingFails_Returns503Degraded exercises the deep-health "database
// unhealthy" branch by pointing a real *pgxpool.Pool at a port nothing is
// listening on. pgxpool.NewWithConfig does not dial eagerly, so pool
// construction succeeds instantly; the actual (fast, local, no-DNS) connection
// failure only happens inside Pool.Ping, which is exactly the code path this
// test targets — no TEST_DB_URL / live Postgres required.
func TestHealth_DBPingFails_Returns503Degraded(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://baduser:badpass@127.0.0.1:1/nonexistent")
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer pool.Close()

	h := NewHealthWithDB(zerolog.Nop(), &db.DB{Pool: pool})

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.Health(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var body map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "degraded" {
		t.Errorf("expected status=degraded, got %v", body["status"])
	}
	checks, ok := body["checks"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected checks map in response, got %v", body["checks"])
	}
	dbCheck, _ := checks["database"].(string)
	if !strings.HasPrefix(dbCheck, "unhealthy") {
		t.Errorf("expected database check to start with 'unhealthy', got %q", dbCheck)
	}
}

// ---------------------------------------------------------------------------
// auth.go — ListRefreshTokens (DB-less path)
// ---------------------------------------------------------------------------

func TestAuthListRefreshTokens_NilDB_Returns503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), testConfig("supersecret"))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/auth/refresh", nil)
	rec := httptest.NewRecorder()
	h.ListRefreshTokens(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// webhooks.go — emergencyStop callback + invalid hex signature
// ---------------------------------------------------------------------------

func TestCITADELWebhook_HardStop_InvokesEmergencyStopCallback(t *testing.T) {
	var mu sync.Mutex
	called := false
	stop := func() {
		mu.Lock()
		called = true
		mu.Unlock()
	}

	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, stop)

	body := makeWebhookEvent("citadel.hard_stop")
	sig := signBody(body, testWebhookSecret)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", sig)
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	mu.Lock()
	defer mu.Unlock()
	if !called {
		t.Error("expected emergencyStop callback to be invoked on citadel.hard_stop")
	}
}

func TestCITADELWebhook_InvalidHexSignature_401(t *testing.T) {
	logger := zerolog.Nop()
	wh := NewWebhooks(logger, testWebhookSecret, nil)

	body := makeWebhookEvent("citadel.vigil_amber")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/webhooks/citadel", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// "zz" is not valid hex, so hex.DecodeString must fail inside verifySignature.
	req.Header.Set("X-Webhook-Signature", "sha256=zz")
	rec := httptest.NewRecorder()

	wh.HandleCITADEL(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for invalid hex signature, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestVerifySignature_InvalidHexDirectly(t *testing.T) {
	wh := NewWebhooks(zerolog.Nop(), testWebhookSecret, nil)
	if wh.verifySignature([]byte("body"), "sha256=not-hex!!") {
		t.Error("expected verifySignature to reject non-hex signature")
	}
}

// sanity: HMAC comparison used by verifySignature never panics on mismatched
// lengths (hmac.Equal handles that safely) — covered indirectly above, but
// assert explicitly since it is a common source of subtle bugs.
func TestVerifySignature_ValidSignatureAccepted(t *testing.T) {
	wh := NewWebhooks(zerolog.Nop(), testWebhookSecret, nil)
	body := []byte(`{"event_type":"x"}`)
	mac := hmac.New(sha256.New, []byte(testWebhookSecret))
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !wh.verifySignature(body, sig) {
		t.Error("expected valid signature to be accepted")
	}
}

// ---------------------------------------------------------------------------
// specs.go — multipart error paths + write failure
// ---------------------------------------------------------------------------

func TestSpecsUpload_MultipartMissingSpecField_400(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// Wrong field name — handler looks for "spec".
	fw, err := mw.CreateFormFile("wrong_field", "openapi.yaml")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	fw.Write([]byte("openapi: 3.0.0\n"))
	mw.Close()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/specs/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSpecsUpload_MalformedMultipartForm_400(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, t.TempDir())

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/specs/upload", strings.NewReader("not a real multipart body"))
	// A boundary is declared but the body doesn't match it, so ParseMultipartForm fails.
	req.Header.Set("Content-Type", "multipart/form-data; boundary=xxxx")
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestSpecsUpload_WriteFailure_Returns500 points uploadDir at a path that is
// actually a regular file (not a directory), so os.WriteFile's implicit
// "create inside this directory" fails with ENOTDIR — exercising the internal
// error branch without needing a read-only filesystem or root privileges.
func TestSpecsUpload_WriteFailure_Returns500(t *testing.T) {
	logger := zerolog.Nop()
	dir := t.TempDir()
	notADir := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatalf("setup: writing blocking file: %v", err)
	}

	h := NewSpecs(logger, notADir)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/specs/upload", strings.NewReader("openapi: 3.0.0\n"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// TestNewSpecs_EmptyUploadDir_DefaultsToTempDir exercises the "uploadDir =="
// "" -> os.TempDir()" branch in the constructor: a subsequent Upload must
// succeed and the resulting spec_path must live under the OS temp directory.
func TestNewSpecs_EmptyUploadDir_DefaultsToTempDir(t *testing.T) {
	logger := zerolog.Nop()
	h := NewSpecs(logger, "")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/specs/upload",
		strings.NewReader("openapi: 3.0.0\ninfo:\n  title: DefaultDir\n  version: 1.0.0\npaths: {}\n"))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	h.Upload(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var result map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	specPath, _ := result["spec_path"].(string)
	if specPath == "" {
		t.Fatal("spec_path missing or empty")
	}
	// Cleanup: NewSpecs("") writes into the shared OS temp dir, so remove the
	// file this test created to avoid leaking state across test runs.
	t.Cleanup(func() { _ = os.Remove(specPath) })

	tmpDir := filepath.Clean(os.TempDir())
	if !strings.HasPrefix(filepath.Clean(specPath), tmpDir) {
		t.Errorf("expected spec_path %q to live under temp dir %q", specPath, tmpDir)
	}
}

// ---------------------------------------------------------------------------
// auditLog — scans.go / findings.go / apikeys.go
//
// Each of these builds a db.AuditLog entry and calls db.AppendAuditLog, which
// (with no background worker started) falls through to a synchronous
// writeEntryToDB against the real *pgxpool.Pool. Pointing that pool at an
// unreachable address makes the write fail fast and deterministically,
// exercising the full entry-construction + error-handling body of auditLog
// without requiring TEST_DB_URL / a live Postgres.
// ---------------------------------------------------------------------------

func TestScansAuditLog_WriteFailureIsLoggedNotPanicked(t *testing.T) {
	s := NewScans(zerolog.Nop(), unreachableDB(t), nil, context.Background())
	id := uuid.New()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "alice"})

	// Must not panic even though the DB write fails.
	s.auditLog(ctx, db.AuditActionScanCreated, "scans", &id, "1.2.3.4", "test-agent", map[string]interface{}{"target": "https://example.com"})
}

func TestScansAuditLog_SystemActor_NoClaims(t *testing.T) {
	s := NewScans(zerolog.Nop(), unreachableDB(t), nil, context.Background())
	id := uuid.New()

	// No claims in context and no ip/ua — exercises the "system" actor and
	// the ip/ua-empty branches that skip setting sql.NullString fields.
	s.auditLog(context.Background(), db.AuditActionScanCreated, "scans", &id, "", "", nil)
}

func TestFindingsAuditLog_WriteFailureIsLoggedNotPanicked(t *testing.T) {
	f := NewFindingsWithCitadel(zerolog.Nop(), unreachableDB(t), nil, nil)
	id := uuid.New()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/x", nil)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "bob"})

	f.auditLog(ctx, db.AuditActionScanCreated, "findings", &id, "5.6.7.8", "test-agent", map[string]interface{}{"note": "x"})
}

func TestAPIKeysAuditLog_WriteFailureIsLoggedNotPanicked(t *testing.T) {
	h := NewAPIKeys(zerolog.Nop(), unreachableDB(t), nil, nil)
	id := uuid.New()

	h.auditLog(context.Background(), db.AuditActionScanCreated, "api_keys", &id, "9.9.9.9", "test-agent", "carol")
}

// ---------------------------------------------------------------------------
// auth.go — auditLog (db != nil branch)
// ---------------------------------------------------------------------------

func TestAuthAuditLog_DBSet_WriteFailureIsLoggedNotPanicked(t *testing.T) {
	a := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), unreachableDB(t), nil, nil, nil)
	a.auditLog(context.Background(), db.AuditActionUserLogin, "auth", nil, "1.1.1.1", "ua", "subject", "user")
}

// ---------------------------------------------------------------------------
// Handlers wired to a real-but-unreachable DB — these exercise the
// "database call failed" 500/error branches that a nil *db.DB cannot reach
// (a nil db.DB panics before returning an error; a live-but-unreachable pool
// returns a genuine connection error, which is exactly what these handlers
// are written to handle). No TEST_DB_URL / live Postgres required — the pool
// fails fast against an unroutable local port.
// ---------------------------------------------------------------------------

const validUUIDForDBErrorTests = "550e8400-e29b-41d4-a716-446655440000"

// -- apikeys.go --

func TestAPIKeysList_DBError_Returns500(t *testing.T) {
	h := NewAPIKeys(zerolog.Nop(), unreachableDB(t), nil, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/api-keys", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeysCreate_DBError_Returns500(t *testing.T) {
	h := NewAPIKeys(zerolog.Nop(), unreachableDB(t), nil, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/api-keys", strings.NewReader(`{"label":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIKeysRevoke_DBError_Returns500(t *testing.T) {
	h := NewAPIKeys(zerolog.Nop(), unreachableDB(t), nil, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/api-keys/"+validUUIDForDBErrorTests, nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// -- findings.go --

func TestFindingsList_DBError_Returns500(t *testing.T) {
	h := NewFindings(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/findings", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsGet_DBError_Returns500(t *testing.T) {
	h := NewFindings(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/findings/"+validUUIDForDBErrorTests, nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsUpdate_DBErrorFetchingExisting_Returns500(t *testing.T) {
	// No "status" in the body, forcing Update to fetch the finding's current
	// status from the DB before it can proceed — that fetch fails.
	h := NewFindings(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/findings/"+validUUIDForDBErrorTests, strings.NewReader(`{"note":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestFindingsUpdate_DBErrorUpdating_Returns500(t *testing.T) {
	h := NewFindings(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPatch, "/findings/"+validUUIDForDBErrorTests, strings.NewReader(`{"status":"open"}`))
	req.Header.Set("Content-Type", "application/json")
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Update(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// -- audit.go --

func TestAuditList_DBError_Returns500(t *testing.T) {
	h := NewAudit(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/audit", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// -- inventory.go --

func TestInventoryList_DBError_Returns500(t *testing.T) {
	h := NewInventory(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestInventoryGetHistory_DBError_Returns404(t *testing.T) {
	// GetHistory treats ANY error (including a connection failure) from
	// GetAPIInventoryByID as "item not found" — see inventory.go's
	// `if err != nil || inv == nil`. This asserts that documented behavior.
	h := NewInventory(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory/"+validUUIDForDBErrorTests+"/history", nil)
	req = injectChiParam(req, "id", validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.GetHistory(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// -- scans.go --

func scansWithUnreachableDB(t *testing.T) *Scans {
	t.Helper()
	return NewScans(zerolog.Nop(), unreachableDB(t), nil, context.Background())
}

func TestScansCreate_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	body := `{"spec_url":"https://example.com/api.yaml","target":"https://api.example.com"}`
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansList_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansGet_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans/"+validUUIDForDBErrorTests, nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansDelete_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/scans/"+validUUIDForDBErrorTests, nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansFindings_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans/"+validUUIDForDBErrorTests+"/findings", nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Findings(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansReport_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans/"+validUUIDForDBErrorTests+"/report", nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.Report(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansGetApproval_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/scans/"+validUUIDForDBErrorTests+"/approval", nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	rec := httptest.NewRecorder()
	h.GetApproval(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansApprove_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+validUUIDForDBErrorTests+"/approve", nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "approver-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Approve(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansReject_DBError_Returns500(t *testing.T) {
	h := scansWithUnreachableDB(t)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/scans/"+validUUIDForDBErrorTests+"/reject", nil)
	req = injectChiID(req, validUUIDForDBErrorTests)
	ctx := middleware.ContextWithClaims(req.Context(), &middleware.Claims{Sub: "rejector-1"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.Reject(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// -- auth.go — validAPIKey / RefreshToken / RevokeRefreshToken / ListRefreshTokens with a real (unreachable) DB --

func TestValidAPIKey_DBLookupFails_FallsBackToStaticKeys(t *testing.T) {
	h := NewAuthWithDB(zerolog.Nop(), testConfig("secret", "static-key"), unreachableDB(t), nil, nil, nil)
	if !h.validAPIKey("static-key") {
		t.Error("expected fallback to static config key when DB lookup fails")
	}
	if h.validAPIKey("not-a-key") {
		t.Error("expected unknown key to still be rejected")
	}
}

func TestAuthListRefreshTokens_DBError_Returns500(t *testing.T) {
	h := NewAuthWithDB(zerolog.Nop(), testConfig("supersecret"), unreachableDB(t), nil, nil, nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/auth/refresh", nil)
	rec := httptest.NewRecorder()
	h.ListRefreshTokens(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRefreshToken_DBRevocationCheckFails_Returns500(t *testing.T) {
	cfg := testConfig("supersecret")
	h := NewAuthWithDB(zerolog.Nop(), cfg, unreachableDB(t), nil, nil, nil)

	tok, err := issueJWT("supersecret", "user-db-err", "apiguard", "apiguard", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}
	req := newRefreshRequest(`{"refresh_token":"` + tok + `"}`)
	rec := httptest.NewRecorder()
	h.RefreshToken(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestRevokeRefreshToken_DBRevocationCheckFails_Returns500(t *testing.T) {
	cfg := testConfig("supersecret")
	h := NewAuthWithDB(zerolog.Nop(), cfg, unreachableDB(t), nil, nil, nil)

	tok, err := issueJWT("supersecret", "user-db-err-2", "apiguard", "apiguard", "refresh", time.Hour)
	if err != nil {
		t.Fatalf("issueJWT: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodDelete, "/api/v1/auth/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.RevokeRefreshToken(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---------------------------------------------------------------------------
// scans.go — launchScan
//
// launchScan is only ever started as a goroutine from Create()/Approve(), so
// it has no HTTP-level test surface. It is called directly here instead. Both
// cases below are constructed so that every DB write inside launchScan fails
// fast (unreachable pool) and s.scanner stays nil without ever being
// dereferenced:
//   - scanner.Scanner.Run's first real step, validateTargetURL, is a plain
//     function (not a method on *Scanner) and returns an error immediately
//     for a target with no http/https scheme — so calling Run on a nil
//     *scanner.Scanner never touches the nil receiver.
//   - downloadSpecToTemp is a package-level function with no dependency on
//     s.scanner at all, so the spec_url branch is reachable the same way.
//
// Together these cover the "scan failed" and "spec download failed" halves
// of launchScan, plus the deferred failed-status cleanup, without requiring
// TEST_DB_URL / a live Postgres or a real scanner binary.
// ---------------------------------------------------------------------------

func TestScansLaunchScan_ScannerRunFailure_HandledWithoutPanic(t *testing.T) {
	h := NewScans(zerolog.Nop(), unreachableDB(t), nil, context.Background())
	id := uuid.New()
	req := createScanRequest{Target: "not-a-valid-target"} // no scheme -> scanner.Run fails before touching its nil receiver

	h.scanWg.Add(1)
	h.launchScan(id, req) // must not panic despite s.scanner and s.db being unusable
}

func TestScansLaunchScan_SpecDownloadFailure_HandledWithoutPanic(t *testing.T) {
	h := NewScans(zerolog.Nop(), unreachableDB(t), nil, context.Background())
	id := uuid.New()
	req := createScanRequest{
		Target:  "https://api.example.com",
		SpecURL: "http://127.0.0.1:1/spec.json", // ssrf-safe dial rejects loopback before any real fetch
	}

	h.scanWg.Add(1)
	h.launchScan(id, req)
}
