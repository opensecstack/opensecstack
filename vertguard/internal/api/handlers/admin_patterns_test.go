package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"

	"github.com/opensecstack/vertguard/internal/audit"
	"github.com/opensecstack/vertguard/internal/phishing"
	"github.com/opensecstack/vertguard/internal/prompt"
)

func newPromptScannerForTest() *prompt.Scanner {
	return prompt.NewScanner(prompt.DefaultLibrary, 0.3, 0.7, 1<<20)
}

func newPhishingScannerForTest() *phishing.Scanner {
	return phishing.NewScanner(phishing.DefaultLibrary, 0.3, 0.7, 1<<20)
}

func TestAdminPatterns_Reload_NoOverlay(t *testing.T) {
	pp := newPromptScannerForTest()
	ph := newPhishingScannerForTest()
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()

	h := NewAdminPatternsHandler(pp, ph, "", "", sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if len(pp.Patterns()) != len(prompt.DefaultLibrary) {
		t.Fatalf("prompt patterns count mismatch: got %d want %d",
			len(pp.Patterns()), len(prompt.DefaultLibrary))
	}
	if len(ph.Patterns()) != len(phishing.DefaultLibrary) {
		t.Fatalf("phishing patterns count mismatch: got %d want %d",
			len(ph.Patterns()), len(phishing.DefaultLibrary))
	}
	if len(sink.events) != 1 || sink.events[0].Action != "ADMIN_PATTERNS_RELOAD" {
		t.Fatalf("expected one ADMIN_PATTERNS_RELOAD event, got %+v", sink.events)
	}
	if len(mx.calls) != 1 || mx.calls[0] != "patterns/ok" {
		t.Fatalf("expected one patterns/ok metric, got %+v", mx.calls)
	}
}

func TestAdminPatterns_Reload_WithOverlay(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "overlay.yaml")
	overlay := `
- id: TEST.custom.v1
  category: CUSTOM
  description: test custom pattern
  atlas_technique: AML.T9999
  base_score: 0.42
  regex: "(?i)nuke-the-site"
`
	if err := os.WriteFile(overlayPath, []byte(overlay), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	pp := newPromptScannerForTest()
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()

	h := NewAdminPatternsHandler(pp, nil, overlayPath, "", sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	want := len(prompt.DefaultLibrary) + 1
	if len(pp.Patterns()) != want {
		t.Fatalf("prompt patterns: got %d want %d", len(pp.Patterns()), want)
	}
	// New pattern must actually fire.
	r, err := pp.Scan("nuke-the-site now", "user_chat_input")
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := false
	for _, m := range r.Matches {
		if m.PatternID == "TEST.custom.v1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("custom overlay pattern did not fire on its trigger; matches=%+v", r.Matches)
	}
}

func TestAdminPatterns_Reload_InvalidOverlay(t *testing.T) {
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "bad.yaml")
	// Regex with an unbalanced group is RE2-invalid.
	bad := `
- id: BAD.v1
  regex: "([unbalanced"
`
	if err := os.WriteFile(overlayPath, []byte(bad), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	pp := newPromptScannerForTest()
	preCount := len(pp.Patterns())
	sink := &captureSink{}
	mx := &fakeAdminMetrics{}
	logger := zerolog.Nop()

	h := NewAdminPatternsHandler(pp, nil, overlayPath, "", sink, &logger, mx)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/patterns/reload", nil)
	h.Reload(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	// Scanner must remain untouched on failure.
	if len(pp.Patterns()) != preCount {
		t.Fatalf("scanner mutated after failed reload: got %d want %d",
			len(pp.Patterns()), preCount)
	}
	if len(sink.events) != 1 || sink.events[0].Outcome != audit.OutcomeError {
		t.Fatalf("expected one error audit event, got %+v", sink.events)
	}
	if len(mx.calls) != 1 || mx.calls[0] != "patterns/fail" {
		t.Fatalf("expected patterns/fail metric, got %+v", mx.calls)
	}
}
