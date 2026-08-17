package integration

// Media / C2PA verification integration tests.
//
// The C2PA binary (VERTGUARD_MEDIA_BINARY_PATH) is never present in the
// test environment, so a stub MediaVerifier is injected directly. The
// stub returns a minimal *media.Result so the handler can produce a
// full response without shelling out. A matching stub MediaStore records
// scans in memory so GetScan lookups work within the same test.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/api"
	"github.com/opensecstack/vertguard/internal/api/handlers"
	"github.com/opensecstack/vertguard/internal/auth"
	"github.com/opensecstack/vertguard/internal/config"
	"github.com/opensecstack/vertguard/internal/db"
	"github.com/opensecstack/vertguard/internal/media"
	"github.com/opensecstack/vertguard/internal/metrics"
	"github.com/opensecstack/vertguard/internal/ml"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/rs/zerolog"
)

// ─── Stub ML enricher ────────────────────────────────────────────────

// stubMediaMLEnricher implements handlers.MediaMLEnricher with hardcoded
// return values. No gRPC is needed; it is suitable for unit / integration
// tests that only need to verify the enrichment path is exercised.
type stubMediaMLEnricher struct {
	confidence float64
	verdict    string
}

func (s *stubMediaMLEnricher) ScoreMedia(_ context.Context, _, _ string, _ int64, _, _ bool, _, _ string) (*ml.Result, error) {
	return &ml.Result{
		Confidence:   s.confidence,
		Verdict:      s.verdict,
		ModelVersion: "stub-v0",
	}, nil
}

// ─── Stub verifier ───────────────────────────────────────────────────

// stubMediaVerifier implements handlers.MediaVerifier without the C2PA
// binary. It returns a minimal Result flagging the file as unsigned.
type stubMediaVerifier struct{}

func (stubMediaVerifier) Verify(_ context.Context, r io.Reader, _ string) (*media.Result, error) {
	// Drain the reader so the handler's counting/hashing tee sees all
	// bytes — without this, file_size and file_hash would be zero/empty.
	if _, err := io.Copy(io.Discard, r); err != nil {
		return nil, err
	}
	return &media.Result{
		HasManifest:    false,
		SignatureValid: false,
		ClaimsCount:    0,
		Format:         "image/png",
		Errors:         []string{},
		Warnings:       []string{},
		TrustStatus:    media.TrustStatusUnsigned,
	}, nil
}

// ─── Stub store ──────────────────────────────────────────────────────

// stubMediaStore is a thread-safe in-memory implementation of
// handlers.MediaStore used by tests that do not have a real database.
type stubMediaStore struct {
	mu    sync.RWMutex
	scans map[string]*db.MediaScan
}

func newStubMediaStore() *stubMediaStore {
	return &stubMediaStore{scans: make(map[string]*db.MediaScan)}
}

func (s *stubMediaStore) SaveMediaScan(_ context.Context, scan *db.MediaScan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scans[scan.ScanID] = scan
	return nil
}

func (s *stubMediaStore) GetMediaScan(_ context.Context, scanID string) (*db.MediaScan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scan, ok := s.scans[scanID]
	if !ok {
		return nil, io.EOF // any non-nil error causes the handler to 404
	}
	return scan, nil
}

// ─── Test server helper ──────────────────────────────────────────────

// mediaTestEnv wraps the standard testEnv with the in-memory store so
// individual tests can look up the scan IDs produced by the verify call.
type mediaTestEnv struct {
	*testEnv
	store *stubMediaStore
}

// setupMediaServer builds a test HTTP server wired with the stub
// verifier + store. devMode=false so auth is enforced.
func setupMediaServer(t *testing.T) *mediaTestEnv {
	t.Helper()

	store := newStubMediaStore()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret:  testSecret,
			Issuer:  testIssuer,
			DevMode: false,
		},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1024 * 1024,
		},
	}

	mreg := metrics.New()
	scanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(
		scanner, nil, metrics.NewPromptMetricsAdapter(mreg),
	)
	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	mediaH := handlers.NewMediaHandler(stubMediaVerifier{}, store, logger)

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		ThreatFeed:    threatFeedH,
		Media:         mediaH,
		Metrics:       mreg,
		Authenticator: verifier,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	env := &testEnv{
		srv:     httpSrv,
		mreg:    mreg,
		cleanup: httpSrv.Close,
	}
	return &mediaTestEnv{testEnv: env, store: store}
}

// doMediaVerify sends a raw-body POST to /api/v1/media/verify with the
// provided body bytes and optional Bearer token. The Content-Type header
// is set to the supplied ct value.
func doMediaVerify(t *testing.T, env *mediaTestEnv, token string, body []byte, ct string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(
		http.MethodPost,
		env.srv.URL+"/api/v1/media/verify",
		bytes.NewReader(body),
	)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	return resp
}

// doGetScan sends a GET to /api/v1/media/scans/{scanID} with the given
// Bearer token.
func doGetScan(t *testing.T, env *mediaTestEnv, token, scanID string) *http.Response {
	t.Helper()
	resp := doRequest(t, env.testEnv, http.MethodGet, "/api/v1/media/scans/"+scanID, token, "")
	return resp
}

// ─── Tiny synthetic PNG ──────────────────────────────────────────────

// tinyPNG returns the bytes of a 1×1 white PNG image constructed
// in-memory. The magic bytes are sufficient for http.DetectContentType
// to identify it as image/png, which is in the handler's allowed list.
func tinyPNG() []byte {
	// Minimal valid 1x1 white PNG (67 bytes).
	// Generated offline and embedded as a literal byte slice so the
	// test has no filesystem or external dependencies.
	return []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, // PNG signature
		0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52, // IHDR length + type
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // width=1, height=1
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, // bit depth, colour, CRC
		0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, // IDAT length + type
		0x54, 0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, // IDAT data
		0x00, 0x00, 0x02, 0x00, 0x01, 0xe2, 0x21, 0xbc, // IDAT data + CRC
		0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, // IEND length + type
		0x44, 0xae, 0x42, 0x60, 0x82, // IEND CRC
	}
}

// ─── Tests ───────────────────────────────────────────────────────────

// TestMedia_NoFile verifies that an empty request body is rejected.
//
// The handler peeks the first 512 bytes, gets an empty slice, and calls
// http.DetectContentType which returns "application/octet-stream" for
// empty input. That type is not in the allowed-media list, so the handler
// returns 415 Unsupported Media Type — not 400. The test asserts the
// actual behaviour so it stays green without a content-type header hack.
func TestMedia_NoFile(t *testing.T) {
	env := setupMediaServer(t)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doMediaVerify(t, env, tok, []byte{}, "")
	defer resp.Body.Close()

	// An empty body produces no recognisable magic bytes, so
	// DetectContentType returns "application/octet-stream" which is
	// rejected before any file I/O occurs.
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("empty body: status = %d, want 415", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	code, _ := body["code"].(string)
	if code != "unsupported_media_type" {
		t.Fatalf("error code = %q, want %q", code, "unsupported_media_type")
	}
}

// TestMedia_Unauthorized verifies that requests without a JWT are
// rejected with 401 before the handler is reached.
func TestMedia_Unauthorized(t *testing.T) {
	env := setupMediaServer(t)
	defer env.cleanup()

	resp := doMediaVerify(t, env, "" /* no token */, tinyPNG(), "image/png")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
}

// TestMedia_VerifySmallFile sends a minimal in-memory PNG and asserts
// that the handler returns 200 with a non-empty scan_id. Because the
// C2PA binary is absent, the stub verifier is used, which reports the
// file as unsigned — the response still carries all expected fields.
func TestMedia_VerifySmallFile(t *testing.T) {
	env := setupMediaServer(t)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doMediaVerify(t, env, tok, tinyPNG(), "image/png")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify status = %d, want 200; body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	scanID, _ := result["scan_id"].(string)
	if scanID == "" {
		t.Fatal("expected non-empty scan_id in verify response")
	}

	// Stub returns unsigned file — trust_status must be "unsigned".
	trustStatus, _ := result["trust_status"].(string)
	if trustStatus != media.TrustStatusUnsigned {
		t.Fatalf("trust_status = %q, want %q", trustStatus, media.TrustStatusUnsigned)
	}

	// has_manifest must be false (stub returns no C2PA manifest).
	if hasManifest, _ := result["has_manifest"].(bool); hasManifest {
		t.Fatal("expected has_manifest=false when no C2PA binary is available")
	}

	// errors and warnings must be present (even if empty slices).
	if _, ok := result["errors"]; !ok {
		t.Fatal("response missing 'errors' field")
	}
	if _, ok := result["warnings"]; !ok {
		t.Fatal("response missing 'warnings' field")
	}

	// file_size must reflect the actual bytes sent.
	fileSize, _ := result["file_size"].(float64)
	if int64(fileSize) != int64(len(tinyPNG())) {
		t.Fatalf("file_size = %d, want %d", int64(fileSize), len(tinyPNG()))
	}
}

// TestMedia_GetScan retrieves the scan record produced by Verify and
// checks that the persisted fields match what was returned by the verify
// call. This exercises the full save→lookup path through the stub store.
func TestMedia_GetScan(t *testing.T) {
	env := setupMediaServer(t)
	defer env.cleanup()

	// Step 1: perform a verify so a scan record is created.
	tok := mintToken(t, auth.RoleOperator, time.Hour)
	vresp := doMediaVerify(t, env, tok, tinyPNG(), "image/png")
	defer vresp.Body.Close()

	if vresp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(vresp.Body)
		t.Fatalf("verify status = %d, want 200; body: %s", vresp.StatusCode, body)
	}

	var vresult map[string]any
	if err := json.NewDecoder(vresp.Body).Decode(&vresult); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	scanID, _ := vresult["scan_id"].(string)
	if scanID == "" {
		t.Fatal("no scan_id in verify response")
	}

	// Step 2: retrieve the scan.
	// RequireRead allows viewer role and above.
	viewerTok := mintToken(t, auth.RoleViewer, time.Hour)
	gresp := doGetScan(t, env, viewerTok, scanID)
	defer gresp.Body.Close()

	if gresp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(gresp.Body)
		t.Fatalf("get scan status = %d, want 200; body: %s", gresp.StatusCode, body)
	}

	var scan db.MediaScan
	if err := json.NewDecoder(gresp.Body).Decode(&scan); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	if scan.ScanID != scanID {
		t.Fatalf("scan.ScanID = %q, want %q", scan.ScanID, scanID)
	}
	if scan.FileSize != int64(len(tinyPNG())) {
		t.Fatalf("scan.FileSize = %d, want %d", scan.FileSize, len(tinyPNG()))
	}
	if scan.FileHash == "" {
		t.Fatal("scan.FileHash must be non-empty")
	}
}

// TestMedia_WithMLEnricher_StubBackend verifies that when an ML enricher is
// wired on the MediaHandler the scan response carries ml_score fields
// populated from the enricher's verdict. The stub enricher is synchronous
// and never dials gRPC, so the test runs hermetically.
func TestMedia_WithMLEnricher_StubBackend(t *testing.T) {
	store := newStubMediaStore()

	cfg := &config.Config{
		Server: config.ServerConfig{
			Port:         0,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		Auth: config.AuthConfig{
			Secret:  testSecret,
			Issuer:  testIssuer,
			DevMode: false,
		},
		Prompt: config.PromptConfig{
			CleanThreshold: 0.30,
			BlockThreshold: 0.70,
			MaxInputSize:   1024 * 1024,
		},
	}

	mreg := metrics.New()
	scanner := prompt.NewScanner(
		prompt.DefaultLibrary,
		cfg.Prompt.CleanThreshold,
		cfg.Prompt.BlockThreshold,
		int(cfg.Prompt.MaxInputSize),
	)
	promptH := handlers.NewPromptHandler(scanner, nil, metrics.NewPromptMetricsAdapter(mreg))
	threatFeedH := handlers.NewThreatFeedHandler()
	verifier := auth.NewVerifier(cfg.Auth.Secret, cfg.Auth.Issuer)
	logger := zerolog.Nop()

	enricher := &stubMediaMLEnricher{confidence: 0.1, verdict: "CLEAN"}
	mediaH := handlers.NewMediaHandler(stubMediaVerifier{}, store, logger)
	mediaH.ML = enricher

	apiSrv := api.New(api.Options{
		Config:        cfg,
		Logger:        &logger,
		Pinger:        stubPinger{},
		Prompt:        promptH,
		ThreatFeed:    threatFeedH,
		Media:         mediaH,
		Metrics:       mreg,
		Authenticator: verifier,
	})

	httpSrv := httptest.NewServer(apiSrv.Handler())
	defer httpSrv.Close()

	env := &mediaTestEnv{
		testEnv: &testEnv{srv: httpSrv, mreg: mreg, cleanup: httpSrv.Close},
		store:   store,
	}

	tok := mintToken(t, auth.RoleOperator, time.Hour)
	resp := doMediaVerify(t, env, tok, tinyPNG(), "image/png")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("verify status = %d, want 200; body: %s", resp.StatusCode, body)
	}

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// ml_verdict must be present and match the stub's hardcoded value.
	mlVerdict, _ := result["ml_verdict"].(string)
	if mlVerdict != "CLEAN" {
		t.Fatalf("ml_verdict = %q, want %q", mlVerdict, "CLEAN")
	}

	// ml_confidence must be the stub's hardcoded 0.1.
	mlConfidence, _ := result["ml_confidence"].(float64)
	if mlConfidence != 0.1 {
		t.Fatalf("ml_confidence = %f, want 0.1", mlConfidence)
	}

	// ml_backend_version must reflect the stub model tag.
	mlVersion, _ := result["ml_backend_version"].(string)
	if mlVersion != "stub-v0" {
		t.Fatalf("ml_backend_version = %q, want %q", mlVersion, "stub-v0")
	}
}

// TestMedia_GetScanNotFound asserts that a well-formed but unknown UUID
// returns 404 with a machine-readable error code.
func TestMedia_GetScanNotFound(t *testing.T) {
	env := setupMediaServer(t)
	defer env.cleanup()

	tok := mintToken(t, auth.RoleViewer, time.Hour)
	// Use a valid UUID that was never inserted.
	unknown := "00000000-0000-0000-0000-000000000000"
	gresp := doGetScan(t, env, tok, unknown)
	defer gresp.Body.Close()

	if gresp.StatusCode != http.StatusNotFound {
		body, _ := io.ReadAll(gresp.Body)
		t.Fatalf("get unknown scan status = %d, want 404; body: %s", gresp.StatusCode, body)
	}

	var errBody map[string]any
	if err := json.NewDecoder(gresp.Body).Decode(&errBody); err != nil {
		t.Fatalf("decode error body: %v", err)
	}
	code, _ := errBody["code"].(string)
	if !strings.Contains(code, "not_found") {
		t.Fatalf("error code = %q, want it to contain %q", code, "not_found")
	}
}
