package opensecstack

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			fmt.Fprintf(w, `{"access_token":%q}`, token)
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
			fmt.Fprintf(w, `{"access_token":%q}`, token)
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
			fmt.Fprintf(w, `{"access_token":%q}`, token)
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
		json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(wantFindings)
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
		w.Write(reportData)
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
		json.NewEncoder(w).Encode(resp)
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
		json.NewEncoder(w).Encode(Scan{ID: "scan-retried", Status: ScanStatusCompleted})
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
