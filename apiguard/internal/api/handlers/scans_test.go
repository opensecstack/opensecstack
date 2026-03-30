package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

// ---- helpers ----------------------------------------------------------------

func newScans() *Scans {
	return NewScans(zerolog.Nop(), nil, nil, context.Background())
}

// ---- Create validation ------------------------------------------------------

func TestScansCreate_MalformedJSON(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodPost, "/scans", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_MissingSpecAndTarget(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	// Both spec and target missing — should get 422
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for missing spec+target, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_MissingTarget(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{"spec_url": "https://example.com/openapi.yaml"})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("want 422 for missing target, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_InvalidTargetScheme(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{
		"spec_url": "https://example.com/api.yaml",
		"target":   "ftp://example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid target scheme, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_InvalidTargetNoHostname(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{
		"spec_url": "https://example.com/api.yaml",
		"target":   "https://",
	})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for target with no hostname, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_SpecPathTraversal(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{
		"spec_path": "/etc/passwd",
		"target":    "https://api.example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for path traversal spec_path, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansCreate_SpecPathTraversal_DotDot(t *testing.T) {
	h := newScans()
	body, _ := json.Marshal(map[string]string{
		"spec_path": "../../etc/shadow",
		"target":    "https://api.example.com",
	})
	req := httptest.NewRequest(http.MethodPost, "/scans", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Create(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for path traversal, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---- List validation --------------------------------------------------------

func TestScansList_InvalidStatus(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans?status=invalid_status", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid status, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansList_ValidStatuses(t *testing.T) {
	validStatuses := []string{"pending", "running", "completed", "failed", "cancelled"}
	for _, st := range validStatuses {
		t.Run(st, func(t *testing.T) {
			h := newScans()
			req := httptest.NewRequest(http.MethodGet, "/scans?status="+st, nil)
			rec := httptest.NewRecorder()
			func() {
				defer func() { recover() }() //nolint:errcheck
				h.List(rec, req)
			}()
			if rec.Code == http.StatusBadRequest {
				t.Errorf("status %q should be accepted, got 400; body: %s", st, rec.Body.String())
			}
		})
	}
}

func TestScansList_NoParams(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	rec := httptest.NewRecorder()
	func() {
		defer func() { recover() }() //nolint:errcheck
		h.List(rec, req)
	}()
	// Should not be 400 — validation should pass before DB hit
	if rec.Code == http.StatusBadRequest {
		t.Errorf("no-params request should not be 400; body: %s", rec.Body.String())
	}
}

// ---- Get validation ---------------------------------------------------------

func TestScansGet_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/not-a-uuid", nil)
	req = injectChiID(req, "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansGet_MissingID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/", nil)
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansGet_ValidUUID_HitsDB(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/"+validID, nil)
	req = injectChiID(req, validID)
	rec := httptest.NewRecorder()
	func() {
		defer func() { recover() }() //nolint:errcheck
		h.Get(rec, req)
	}()
	// UUID validation passed — must not return 400
	if rec.Code == http.StatusBadRequest {
		t.Errorf("valid UUID should not return 400; body: %s", rec.Body.String())
	}
}

// ---- Delete validation -------------------------------------------------------

func TestScansDelete_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodDelete, "/scans/bad", nil)
	req = injectChiID(req, "bad")
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansDelete_MissingID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodDelete, "/scans/", nil)
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

// ---- Findings sub-handler ---------------------------------------------------

func TestScansFindingsSub_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/not-uuid/findings", nil)
	req = injectChiID(req, "not-uuid")
	rec := httptest.NewRecorder()
	h.Findings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansFindingsSub_MissingID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans//findings", nil)
	rec := httptest.NewRecorder()
	h.Findings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for missing id, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansFindingsSub_InvalidSeverity(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/"+validID+"/findings?severity=extreme", nil)
	req = injectChiID(req, validID)
	rec := httptest.NewRecorder()
	h.Findings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid severity, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansFindingsSub_InvalidStatus(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/"+validID+"/findings?status=bad_status", nil)
	req = injectChiID(req, validID)
	rec := httptest.NewRecorder()
	h.Findings(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid status, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansFindingsSub_ValidSeverities(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		t.Run(sev, func(t *testing.T) {
			h := newScans()
			req := httptest.NewRequest(http.MethodGet, "/scans/"+validID+"/findings?severity="+sev, nil)
			req = injectChiID(req, validID)
			rec := httptest.NewRecorder()
			func() {
				defer func() { recover() }() //nolint:errcheck
				h.Findings(rec, req)
			}()
			if rec.Code == http.StatusBadRequest {
				t.Errorf("severity %q should pass validation, got 400; body: %s", sev, rec.Body.String())
			}
		})
	}
}

func TestScansFindingsSub_ValidStatuses(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	for _, st := range []string{"open", "confirmed", "false_positive", "accepted", "fixed"} {
		t.Run(st, func(t *testing.T) {
			h := newScans()
			req := httptest.NewRequest(http.MethodGet, "/scans/"+validID+"/findings?status="+st, nil)
			req = injectChiID(req, validID)
			rec := httptest.NewRecorder()
			func() {
				defer func() { recover() }() //nolint:errcheck
				h.Findings(rec, req)
			}()
			if rec.Code == http.StatusBadRequest {
				t.Errorf("status %q should pass validation, got 400; body: %s", st, rec.Body.String())
			}
		})
	}
}

// ---- Report handler ---------------------------------------------------------

func TestScansReport_InvalidUUID(t *testing.T) {
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/bad-id/report", nil)
	req = injectChiID(req, "bad-id")
	rec := httptest.NewRecorder()
	h.Report(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestScansReport_ValidUUID_PassesValidation(t *testing.T) {
	const validID = "550e8400-e29b-41d4-a716-446655440000"
	h := newScans()
	req := httptest.NewRequest(http.MethodGet, "/scans/"+validID+"/report", nil)
	req = injectChiID(req, validID)
	rec := httptest.NewRecorder()
	func() {
		defer func() { recover() }() //nolint:errcheck
		h.Report(rec, req)
	}()
	if rec.Code == http.StatusBadRequest {
		t.Errorf("valid UUID should not return 400; body: %s", rec.Body.String())
	}
}

// ---- validateTarget unit tests ----------------------------------------------

func TestValidateTarget_ValidHTTP(t *testing.T) {
	if err := validateTarget("http://api.example.com"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateTarget_ValidHTTPS(t *testing.T) {
	if err := validateTarget("https://api.example.com/v2"); err != nil {
		t.Errorf("expected nil, got %v", err)
	}
}

func TestValidateTarget_InvalidScheme(t *testing.T) {
	for _, u := range []string{"ftp://example.com", "ws://example.com", "file:///etc/passwd"} {
		if err := validateTarget(u); err == nil {
			t.Errorf("expected error for %q, got nil", u)
		}
	}
}

func TestValidateTarget_NoScheme(t *testing.T) {
	if err := validateTarget("example.com/api"); err == nil {
		t.Error("expected error for URL with no scheme")
	}
}

func TestValidateTarget_EmptyHostname(t *testing.T) {
	if err := validateTarget("https://"); err == nil {
		t.Error("expected error for URL with empty hostname")
	}
}

// ---- parsePagination unit tests ---------------------------------------------

func TestParsePagination_Defaults(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scans", nil)
	page, perPage := parsePagination(req, 1, 20, 100)
	if page != 1 {
		t.Errorf("expected default page=1, got %d", page)
	}
	if perPage != 20 {
		t.Errorf("expected default per_page=20, got %d", perPage)
	}
}

func TestParsePagination_ExplicitValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scans?page=3&per_page=50", nil)
	page, perPage := parsePagination(req, 1, 20, 100)
	if page != 3 {
		t.Errorf("expected page=3, got %d", page)
	}
	if perPage != 50 {
		t.Errorf("expected per_page=50, got %d", perPage)
	}
}

func TestParsePagination_CappedAtMax(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scans?per_page=999", nil)
	_, perPage := parsePagination(req, 1, 20, 100)
	if perPage != 100 {
		t.Errorf("expected per_page capped at 100, got %d", perPage)
	}
}

func TestParsePagination_ZeroPageFallsBack(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scans?page=0", nil)
	page, _ := parsePagination(req, 1, 20, 100)
	if page != 1 {
		t.Errorf("expected page=0 to fall back to default 1, got %d", page)
	}
}

func TestParsePagination_NonNumericIgnored(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/scans?page=abc&per_page=xyz", nil)
	page, perPage := parsePagination(req, 1, 20, 100)
	if page != 1 {
		t.Errorf("expected default page=1 for non-numeric, got %d", page)
	}
	if perPage != 20 {
		t.Errorf("expected default per_page=20 for non-numeric, got %d", perPage)
	}
}

// ---- isNotFound unit tests --------------------------------------------------

func TestIsNotFound_Nil(t *testing.T) {
	if isNotFound(nil) {
		t.Error("isNotFound(nil) must return false")
	}
}

func TestIsNotFound_NotFoundMessage(t *testing.T) {
	if !isNotFound(fmt.Errorf("scan not found")) {
		t.Error("expected true for 'not found' error message")
	}
}

func TestIsNotFound_SQLErrNoRows(t *testing.T) {
	if !isNotFound(sql.ErrNoRows) {
		t.Error("expected true for sql.ErrNoRows")
	}
}

func TestIsNotFound_OtherError(t *testing.T) {
	if isNotFound(fmt.Errorf("connection refused")) {
		t.Error("expected false for non-not-found error")
	}
}

// ---- reportContentType unit tests -------------------------------------------

func TestReportContentType(t *testing.T) {
	cases := []struct {
		format string
		want   string
	}{
		{"json", "application/json"},
		{"sarif", "application/sarif+json"},
		{"html", "text/html; charset=utf-8"},
		{"text", "text/plain; charset=utf-8"},
		{"pdf", "application/json"}, // unknown falls back to json
		{"", "application/json"},
	}
	for _, tc := range cases {
		if got := reportContentType(tc.format); got != tc.want {
			t.Errorf("reportContentType(%q) = %q, want %q", tc.format, got, tc.want)
		}
	}
}
