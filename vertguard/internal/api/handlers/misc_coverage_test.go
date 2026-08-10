package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/ml"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
	"github.com/opensecstack/vertguard/internal/ratelimit"
)

// ─── stubs.go — every TODO handler must return 501 with a stable
// machine-readable code and doc pointer. ──────────────────────────────

func TestTODOHandlers_Return501WithDocRef(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		docRef  string
	}{
		{"PromptScanTODO", PromptScanTODO, "docs/module-3-prompt-injection.md"},
		{"PromptScanGetTODO", PromptScanGetTODO, "docs/module-3-prompt-injection.md"},
		{"ThreatFeedIOCsTODO", ThreatFeedIOCsTODO, "docs/module-4-ai-threat-feed.md"},
		{"ThreatFeedAtlasTODO", ThreatFeedAtlasTODO, "docs/mitre-atlas-mapping.md"},
		{"ThreatFeedAtlasCoverageTODO", ThreatFeedAtlasCoverageTODO, "docs/mitre-atlas-mapping.md"},
		{"AdminPatternsReloadTODO", AdminPatternsReloadTODO, "docs/module-3-prompt-injection.md"},
		{"AdminAtlasSyncTODO", AdminAtlasSyncTODO, "docs/mitre-atlas-mapping.md"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			rr := httptest.NewRecorder()
			tc.handler(rr, req)
			if rr.Code != http.StatusNotImplemented {
				t.Fatalf("status=%d, want 501", rr.Code)
			}
			var resp struct {
				Error  string `json:"error"`
				Code   string `json:"code"`
				DocRef string `json:"doc_ref"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if resp.Code != "phase_4_1_wip" {
				t.Errorf("code = %q, want phase_4_1_wip", resp.Code)
			}
			if resp.DocRef != tc.docRef {
				t.Errorf("doc_ref = %q, want %q", resp.DocRef, tc.docRef)
			}
			if resp.Error == "" {
				t.Error("error message empty")
			}
			ct := rr.Header().Get("Content-Type")
			if ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
		})
	}
}

// ─── ratelimit_admin.go List ────────────────────────────────────────

func TestRateLimitAdmin_List_NilStore_Returns503(t *testing.T) {
	h := &RateLimitAdminHandler{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ratelimit/overrides", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", rr.Code)
	}
}

func TestRateLimitAdmin_List_Success(t *testing.T) {
	store := ratelimit.NewMemoryOverrideStore()
	ctx := context.Background()
	if err := store.Add(ctx, ratelimit.Override{Kind: "sub", Value: "abuser", RPS: 1, Burst: 1}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := &RateLimitAdminHandler{Store: store}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ratelimit/overrides", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Overrides []ratelimit.Override `json:"overrides"`
		Count     int                  `json:"count"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Count != 1 || len(resp.Overrides) != 1 || resp.Overrides[0].Value != "abuser" {
		t.Fatalf("unexpected list: %+v", resp)
	}
}

type erroringOverrideStore struct{}

func (erroringOverrideStore) List(context.Context) ([]ratelimit.Override, error) {
	return nil, errors.New("db unavailable")
}
func (erroringOverrideStore) Add(context.Context, ratelimit.Override) error { return nil }
func (erroringOverrideStore) Remove(context.Context, string, string) error  { return nil }

func TestRateLimitAdmin_List_StoreError_Returns500(t *testing.T) {
	h := &RateLimitAdminHandler{Store: erroringOverrideStore{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/ratelimit/overrides", nil)
	rr := httptest.NewRecorder()
	h.List(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", rr.Code)
	}
}

// ─── admin_patterns.go — phishing overlay path (compilePhishingDoc /
// buildPhishingLibrary) is only exercised via the prompt overlay in
// the existing suite; these cover the phishing side explicitly. ──────

func TestAdminPatterns_Reload_WithPhishingOverlay(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "phishing_overlay.yaml")
	overlay := `
- id: TEST.phish.v1
  category: CREDENTIAL_HARVEST
  description: test phishing pattern
  atlas_technique: AML.T9998
  base_score: 0.55
  regex: "(?i)verify-your-account-now"
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	ph := newPhishingScannerForTest()
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()

	h := NewAdminPatternsHandler(nil, ph, "", overlayPath, sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	want := len(phishing.DefaultLibrary) + 1
	if len(ph.Patterns()) != want {
		t.Fatalf("phishing patterns: got %d want %d", len(ph.Patterns()), want)
	}
	r, err := ph.Scan("verify-your-account-now please", "email_body")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, m := range r.Matches {
		if m.PatternID == "TEST.phish.v1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("custom phishing overlay pattern did not fire; matches=%+v", r.Matches)
	}
}

func TestAdminPatterns_Reload_InvalidPhishingOverlay(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "bad_phishing.yaml")
	bad := `
- id: BAD.phish.v1
  regex: "([unbalanced"
`
	if err := os.WriteFile(overlayPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	ph := newPhishingScannerForTest()
	preCount := len(ph.Patterns())
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()

	h := NewAdminPatternsHandler(nil, ph, "", overlayPath, sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(ph.Patterns()) != preCount {
		t.Fatalf("scanner mutated after failed reload: got %d want %d", len(ph.Patterns()), preCount)
	}
}

func TestAdminPatterns_Reload_PhishingOverlayMissingIDOrRegex(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "missing_fields.yaml")
	bad := `
- category: CREDENTIAL_HARVEST
  description: no id, no regex
`
	if err := os.WriteFile(overlayPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	ph := newPhishingScannerForTest()
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()
	h := NewAdminPatternsHandler(nil, ph, "", overlayPath, sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
}

// ─── trivial constructors (currently 0% — real wiring code, worth a
// cheap assertion that the returned struct actually holds what was
// passed in, catching field-name typos on refactor). ─────────────────

func TestNewMediaHandler_WiresFieldsAndDefaults(t *testing.T) {
	logger := zerolog.Nop()
	h := NewMediaHandler(nil, nil, logger)
	if h == nil {
		t.Fatal("NewMediaHandler returned nil")
	}
	if h.MaxBodySize != 100*1024*1024 {
		t.Errorf("MaxBodySize = %d, want 100MiB default", h.MaxBodySize)
	}
	if h.ML != nil || h.Citadel != nil {
		t.Errorf("ML/Citadel should start nil")
	}
	h2 := h.WithML(fakeMLEnricher{})
	if h2 != h {
		t.Error("WithML must return the same handler for chaining")
	}
	if h.ML == nil {
		t.Error("WithML did not set ML")
	}
	h3 := h.WithCitadel(&citadel.Client{}, "acme")
	if h3 != h {
		t.Error("WithCitadel must return the same handler for chaining")
	}
	if h.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme", h.Tenant)
	}
}

type fakeMLEnricher struct{}

func (fakeMLEnricher) ScoreMedia(context.Context, string, string, int64, bool, bool, string, string) (*ml.Result, error) {
	return nil, nil
}

func TestNewPhishingHandler_WiresFields(t *testing.T) {
	scanner := newPhishingScannerForTest()
	metrics := &fakePhishingMetrics{}
	h := NewPhishingHandler(scanner, nil, metrics)
	if h == nil {
		t.Fatal("NewPhishingHandler returned nil")
	}
	if h.Scanner != scanner {
		t.Error("Scanner not wired")
	}
	if h.Metrics != metrics {
		t.Error("Metrics not wired")
	}
	if h.Store != nil {
		t.Error("Store should be nil when passed nil")
	}
}

type fakePhishingMetrics struct{}

func (fakePhishingMetrics) ObservePhishingScan(string, float64)       {}
func (fakePhishingMetrics) IncPhishingIndicatorMatch(string, string) {}

func TestNewPromptHandler_WiresFields(t *testing.T) {
	scanner := &fakeScanner{res: cleanResult()}
	metrics := &fakePromptMetrics{}
	h := NewPromptHandler(scanner, nil, metrics)
	if h == nil {
		t.Fatal("NewPromptHandler returned nil")
	}
	if h.Scanner != scanner {
		t.Error("Scanner not wired")
	}
	if h.Metrics != metrics {
		t.Error("Metrics not wired")
	}
}

type fakePromptMetrics struct {
	observed []string
	matches  []string
}

func (f *fakePromptMetrics) ObservePromptScan(classification string, _ float64) {
	f.observed = append(f.observed, classification)
}
func (f *fakePromptMetrics) IncPatternMatch(patternID, category string) {
	f.matches = append(f.matches, patternID+"/"+category)
}

// ─── prompt.go Scan — the two remaining un-exercised branches:
// generic scan_failed (500) and input_too_large (413). ───────────────

func TestScan_GenericScannerError_Returns500(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{err: errors.New("boom")}}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "scan_failed" {
		t.Errorf("code = %q, want scan_failed", resp["code"])
	}
}

func TestScan_InputTooLargeError_Returns413(t *testing.T) {
	h := &PromptHandler{Scanner: &fakeScanner{err: &prompt.InputTooLargeError{Limit: 10, Actual: 20}}}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "input_too_large" {
		t.Errorf("code = %q, want input_too_large", resp["code"])
	}
}

func TestScan_MetricsWired_ObservesClassificationAndMatches(t *testing.T) {
	res := cleanResult()
	res.Matches = []prompt.Match{{PatternID: "P1", Category: prompt.CategoryCustom}}
	m := &fakePromptMetrics{}
	h := &PromptHandler{Scanner: &fakeScanner{res: res}, Metrics: m}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(m.observed) != 1 || m.observed[0] != string(prompt.ClassificationClean) {
		t.Errorf("observed = %+v", m.observed)
	}
	if len(m.matches) != 1 || m.matches[0] != "P1/"+string(prompt.CategoryCustom) {
		t.Errorf("matches = %+v", m.matches)
	}
}

func TestScan_CitadelWired_EmitsDetection(t *testing.T) {
	wa := &fakeWORM{}
	h := &PromptHandler{Scanner: &fakeScanner{res: cleanResult()}, Citadel: wa}
	w := httptest.NewRecorder()
	h.Scan(w, newReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if wa.count.Load() == 0 {
		t.Error("expected CITADEL emission when Citadel is wired")
	}
}
