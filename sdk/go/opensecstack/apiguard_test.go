package opensecstack

import (
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeAPIGuardServer creates an httptest.Server that serves a minimal set of
// APIGuard endpoints. token is the JWT served by the auth endpoint; handler
// handles all non-auth requests.
func makeAPIGuardServer(t *testing.T, token string, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" && r.Method == http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":%q}`, token)
			return
		}
		handler(w, r)
	}))
}

// ----------------------------------------------------------------------------
// TestAuthenticate_Success (APIGuard)
// ----------------------------------------------------------------------------

func TestAPIGuardAuthenticate_Success(t *testing.T) {
	var authCalls int32
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			atomic.AddInt32(&authCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":%q}`, token)
			return
		}
	}))
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("authenticate failed: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 auth call, got %d", got)
	}
	c.mu.RLock()
	if c.jwt != token {
		t.Errorf("cached token mismatch: want %q got %q", token, c.jwt)
	}
	c.mu.RUnlock()
}

// ----------------------------------------------------------------------------
// TestAuthenticate_Cached (APIGuard)
// ----------------------------------------------------------------------------

func TestAPIGuardAuthenticate_Cached(t *testing.T) {
	var authCalls int32
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/token" {
			atomic.AddInt32(&authCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"access_token":%q}`, token)
		}
	}))
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")

	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("first authenticate: %v", err)
	}
	if err := c.authenticate(t.Context()); err != nil {
		t.Fatalf("second authenticate: %v", err)
	}
	if got := atomic.LoadInt32(&authCalls); got != 1 {
		t.Errorf("expected 1 auth call (cached), got %d", got)
	}
}

// ----------------------------------------------------------------------------
// TestListScans_Success with pagination
// ----------------------------------------------------------------------------

func TestListScans_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	wantScans := []Scan{
		{ID: "scan-1", Status: ScanStatusCompleted},
		{ID: "scan-2", Status: ScanStatusRunning},
	}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		page := r.URL.Query().Get("page")
		perPage := r.URL.Query().Get("per_page")
		if page == "" || perPage == "" {
			http.Error(w, "missing pagination params", http.StatusBadRequest)
			return
		}
		resp := scansResponse{
			Items:   wantScans,
			Total:   2,
			Page:    1,
			PerPage: 20,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	scans, err := c.ListScans(t.Context(), ListScansOptions{Page: 1, PerPage: 20})
	if err != nil {
		t.Fatalf("ListScans: %v", err)
	}
	if len(scans) != 2 {
		t.Errorf("expected 2 scans, got %d", len(scans))
	}
	if scans[0].ID != "scan-1" {
		t.Errorf("unexpected first scan ID: %q", scans[0].ID)
	}
}

// ----------------------------------------------------------------------------
// TestGetFindings_WithFilters
// ----------------------------------------------------------------------------

func TestGetFindings_WithFilters(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	wantFindings := []Finding{
		{ID: "f-1", Severity: FindingSeverityCritical, Status: FindingStatusOpen},
	}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		q := r.URL.Query()
		if q.Get("severity") != "critical" || q.Get("status") != "open" {
			http.Error(w, "missing filters", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wantFindings)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	findings, err := c.GetFindings(t.Context(), "scan-abc", GetFindingsOptions{
		Severity: "critical",
		Status:   "open",
	})
	if err != nil {
		t.Fatalf("GetFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "f-1" {
		t.Errorf("unexpected findings: %+v", findings)
	}
}

// ----------------------------------------------------------------------------
// TestGetReport_Format
// ----------------------------------------------------------------------------

func TestGetReport_Format(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	reportData := []byte(`{"scan_id":"s1","findings":[]}`)

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		format := r.URL.Query().Get("format")
		if format != "json" {
			http.Error(w, fmt.Sprintf("unexpected format %q", format), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(reportData)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	// Use a short report timeout so the test does not hang.
	c.ReportTimeout = 5 * time.Second

	data, err := c.GetReport(t.Context(), "scan-1", "json")
	if err != nil {
		t.Fatalf("GetReport: %v", err)
	}
	if string(data) != string(reportData) {
		t.Errorf("report data mismatch: got %q", string(data))
	}
}

// ----------------------------------------------------------------------------
// TestUploadSpec_Multipart
// ----------------------------------------------------------------------------

func TestUploadSpec_Multipart(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	// Create a temporary spec file.
	dir := t.TempDir()
	specPath := filepath.Join(dir, "openapi.yaml")
	if err := os.WriteFile(specPath, []byte("openapi: 3.0.0\n"), 0600); err != nil {
		t.Fatalf("writing temp spec: %v", err)
	}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/specs/upload" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		// Verify the Content-Type is multipart/form-data.
		ct := r.Header.Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(ct)
		if err != nil || mediaType != "multipart/form-data" {
			http.Error(w, "expected multipart/form-data", http.StatusBadRequest)
			return
		}
		if err := r.ParseMultipartForm(1 << 20); err != nil {
			http.Error(w, "parse multipart: "+err.Error(), http.StatusBadRequest)
			return
		}
		_, fh, err := r.FormFile("spec")
		if err != nil {
			http.Error(w, "no spec file", http.StatusBadRequest)
			return
		}
		resp := UploadSpecResponse{
			SpecPath: "/tmp/specs/" + fh.Filename,
			SpecHash: "abc123",
			Size:     fh.Size,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	result, err := c.UploadSpec(t.Context(), specPath)
	if err != nil {
		t.Fatalf("UploadSpec: %v", err)
	}
	if result.SpecHash != "abc123" {
		t.Errorf("unexpected spec hash: %q", result.SpecHash)
	}
}

// ----------------------------------------------------------------------------
// TestRetryOn5xx
// ----------------------------------------------------------------------------

// TestRetryOn5xx verifies that the client retries on 5xx responses and
// ultimately returns the successful 200 on the third attempt.
func TestRetryOn5xx(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	var callCount int32

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		if n <= 2 {
			// First two calls return 500.
			http.Error(w, `{"error":"temporary server error"}`, http.StatusInternalServerError)
			return
		}
		// Third call succeeds.
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(Scan{ID: "scan-retried", Status: ScanStatusCompleted})
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	// Allow up to 2 retries (3 total attempts) with a very short backoff so
	// the test does not take seconds to run.
	c.MaxRetries = 2
	c.RetryWaitBase = 1 * time.Millisecond

	scan, err := c.GetScan(t.Context(), "scan-retried")
	if err != nil {
		t.Fatalf("GetScan: expected success after retries, got error: %v", err)
	}
	if scan.ID != "scan-retried" {
		t.Errorf("unexpected scan ID: got %q, want %q", scan.ID, "scan-retried")
	}
	if got := atomic.LoadInt32(&callCount); got != 3 {
		t.Errorf("expected 3 total calls (2 failures + 1 success), got %d", got)
	}
}

// ----------------------------------------------------------------------------
// TestNoRetryOn4xx
// ----------------------------------------------------------------------------

// TestNoRetryOn4xx verifies that the client does NOT retry on 4xx client
// errors and returns immediately after the first response.
func TestNoRetryOn4xx(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	var callCount int32

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&callCount, 1)
		http.Error(w, `{"error":"not found"}`, http.StatusBadRequest)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	// Configure retries — they must NOT fire for 4xx.
	c.MaxRetries = 3
	c.RetryWaitBase = 1 * time.Millisecond

	_, err := c.GetScan(t.Context(), "no-such-scan")
	if err == nil {
		t.Fatal("GetScan: expected an error for HTTP 400, got nil")
	}
	if got := atomic.LoadInt32(&callCount); got != 1 {
		t.Errorf("expected exactly 1 call (no retry on 4xx), got %d", got)
	}
}

// ----------------------------------------------------------------------------
// TestRefreshToken_Concurrent
// ----------------------------------------------------------------------------

// ----------------------------------------------------------------------------
// TestCreateScanFull_Success
// ----------------------------------------------------------------------------

func TestCreateScanFull_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var req createScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		scan := Scan{ID: "new-scan-id", SpecURL: req.SpecURL, Status: ScanStatusPending}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(scan)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	scan, err := c.CreateScanFull(t.Context(), CreateScanOptions{
		SpecURL: "https://api.example.com/openapi.json",
		Modules: []string{"bola", "broken_auth"},
	})
	if err != nil {
		t.Fatalf("CreateScanFull: %v", err)
	}
	if scan.ID != "new-scan-id" {
		t.Errorf("unexpected scan ID: %q", scan.ID)
	}
	if scan.Status != ScanStatusPending {
		t.Errorf("unexpected status: %q", scan.Status)
	}
}

// ----------------------------------------------------------------------------
// TestDeleteScan_Success
// ----------------------------------------------------------------------------

func TestDeleteScan_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	var deleteCalled bool

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/scans/scan-to-delete" && r.Method == http.MethodDelete {
			deleteCalled = true
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	if err := c.DeleteScan(t.Context(), "scan-to-delete"); err != nil {
		t.Fatalf("DeleteScan: %v", err)
	}
	if !deleteCalled {
		t.Error("DELETE endpoint was not called")
	}
}

// ----------------------------------------------------------------------------
// TestPatchFinding_Success
// ----------------------------------------------------------------------------

func TestPatchFinding_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := Finding{ID: "finding-123", Status: FindingStatusConfirmed}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/finding-123" || r.Method != http.MethodPatch {
			http.NotFound(w, r)
			return
		}
		var req PatchFindingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		want.TriageNote = req.Note
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	got, err := c.PatchFinding(t.Context(), "finding-123", PatchFindingRequest{
		Status: string(FindingStatusConfirmed),
		Note:   "verified in staging",
	})
	if err != nil {
		t.Fatalf("PatchFinding: %v", err)
	}
	if got.ID != "finding-123" {
		t.Errorf("ID: got %q, want finding-123", got.ID)
	}
	if got.Status != FindingStatusConfirmed {
		t.Errorf("Status: got %q, want confirmed", got.Status)
	}
}

// ----------------------------------------------------------------------------
// TestGetAuditLog_APIGuard_Success
// ----------------------------------------------------------------------------

func TestGetAuditLog_APIGuard_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	wantEntries := []AuditEntry{
		{ID: "audit-1", Action: "scan.created", ResourceType: "scan"},
		{ID: "audit-2", Action: "finding.triaged", ResourceType: "finding"},
	}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/audit" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("per_page") == "" || r.URL.Query().Get("page") == "" {
			http.Error(w, "missing pagination params", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wantEntries)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	entries, err := c.GetAuditLog(t.Context(), 10, 1)
	if err != nil {
		t.Fatalf("GetAuditLog: %v", err)
	}
	if len(entries) != 2 || entries[0].ID != "audit-1" {
		t.Errorf("unexpected entries: %+v", entries)
	}
}

// ----------------------------------------------------------------------------
// TestListFindings_Success
// ----------------------------------------------------------------------------

func TestListFindings_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	wantFindings := []Finding{{ID: "lf-1", Severity: FindingSeverityHigh, Status: FindingStatusOpen}}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("scan_id") != "scan-abc" {
			http.Error(w, "missing scan_id filter", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wantFindings)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	findings, err := c.ListFindings(t.Context(), ListFindingsOptions{ScanID: "scan-abc"})
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if len(findings) != 1 || findings[0].ID != "lf-1" {
		t.Errorf("unexpected findings: %+v", findings)
	}
}

// ----------------------------------------------------------------------------
// TestGetFinding_Success
// ----------------------------------------------------------------------------

func TestGetFinding_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	want := Finding{ID: "f-uuid-001", Severity: FindingSeverityCritical, Status: FindingStatusOpen}

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/findings/f-uuid-001" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	got, err := c.GetFinding(t.Context(), "f-uuid-001")
	if err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if got.ID != want.ID || got.Severity != FindingSeverityCritical {
		t.Errorf("unexpected finding: %+v", got)
	}
}

// ----------------------------------------------------------------------------
// TestGetReportStream_APIGuard_Success
// ----------------------------------------------------------------------------

func TestGetReportStream_APIGuard_Success(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())
	reportData := `{"findings":[],"summary":"clean"}`

	srv := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scans/stream-scan/report" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("format") != "sarif" {
			http.Error(w, "unexpected format", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, reportData)
	})
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")
	var buf strings.Builder
	if err := c.GetReportStream(t.Context(), "stream-scan", "sarif", &buf); err != nil {
		t.Fatalf("GetReportStream: %v", err)
	}
	if buf.String() != reportData {
		t.Errorf("report data mismatch: got %q", buf.String())
	}
}

// ----------------------------------------------------------------------------
// TestRefreshToken_Concurrent verifies that 10 goroutines calling RefreshToken
// concurrently do not cause a data race on the cached jwt / tokenExpiry fields.
// Run with: go test -race -run TestRefreshToken_Concurrent ./...
func TestRefreshToken_Concurrent(t *testing.T) {
	newToken := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	var refreshCalls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/refresh" && r.Method == http.MethodPost {
			atomic.AddInt32(&refreshCalls, 1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"access_token":%q,"refresh_token":"ref2","expires_in":3600}`, newToken)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	c := NewAPIGuardClient(srv.URL, "test-key")

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)
	errs := make([]error, goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, errs[i] = c.RefreshToken(t.Context(), "old-refresh-token")
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: RefreshToken returned error: %v", i, err)
		}
	}

	// After all goroutines complete, the cached token must equal the one
	// returned by the server.
	c.mu.RLock()
	cachedJWT := c.jwt
	c.mu.RUnlock()

	if cachedJWT != newToken {
		t.Errorf("cached jwt = %q, want %q", cachedJWT, newToken)
	}

	if got := atomic.LoadInt32(&refreshCalls); got != goroutines {
		// Each goroutine issues its own HTTP call (RefreshToken is not
		// deduplicated like authenticate).  All calls must have been made.
		t.Errorf("expected %d refresh calls, got %d", goroutines, got)
	}
}

// ----------------------------------------------------------------------------
// TestAPIGuardClient_ContextCancellation
// ----------------------------------------------------------------------------

// TestAPIGuardClient_ContextCancellation verifies that a context cancelled
// before the server responds causes ListScans to return a non-nil error.
func TestAPIGuardClient_ContextCancellation(t *testing.T) {
	// Slow server: delays 2 seconds before replying so the short-lived context
	// is guaranteed to expire first.
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer slow.Close()

	client := NewAPIGuardClient(slow.URL, "token")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := client.ListScans(ctx, ListScansOptions{Page: 1, PerPage: 20})
	if err == nil {
		t.Error("expected error on context cancellation, got nil")
	}
}

// ----------------------------------------------------------------------------
// TestAPIGuardClient_NonJSONResponse_ReturnsError
// ----------------------------------------------------------------------------

// TestAPIGuardClient_NonJSONResponse_ReturnsError verifies that a 200 response
// with a text/html Content-Type (e.g. a proxy error page) is surfaced as an
// error rather than causing a confusing JSON decode failure downstream.
func TestAPIGuardClient_NonJSONResponse_ReturnsError(t *testing.T) {
	token := makeTestJWT(time.Now().Add(1 * time.Hour).Unix())

	ts := makeAPIGuardServer(t, token, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html>Gateway Error</html>"))
	})
	defer ts.Close()

	client := NewAPIGuardClient(ts.URL, "token")
	_, err := client.ListScans(context.Background(), ListScansOptions{Page: 1, PerPage: 20})
	if err == nil {
		t.Error("expected error for non-JSON response, got nil")
	}
}
