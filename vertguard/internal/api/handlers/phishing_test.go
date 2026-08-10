package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/vertguard/internal/citadel"
	"github.com/opensecstack/vertguard/internal/phishing"
)

// newPhishingReq builds a POST request with a JSON body for the
// phishing scan endpoint.
func newPhishingReq(t *testing.T, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal req body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/phishing/scan", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	return r
}

// newPhishingScanner returns a real *phishing.Scanner seeded with a
// single deterministic pattern so tests can drive classification
// outcomes without depending on the full default library.
func newPhishingScanner(t *testing.T) *phishing.Scanner {
	t.Helper()
	pat := phishing.MustCompilePattern(
		"PH-TEST-001", phishing.CategoryCredentialHarvest,
		"test credential harvest pattern", "", 0.9,
		`(?i)verify-your-account`,
	)
	return phishing.NewScanner([]phishing.Pattern{pat}, 0.3, 0.7, 1<<20)
}

// fakeWORMEmitter records whether EmitAsync was called and with what
// evidence, without any network I/O.
type fakeWORMEmitter struct {
	called bool
	ev     citadel.Evidence
}

func (f *fakeWORMEmitter) EmitAsync(_ context.Context, ev citadel.Evidence) bool {
	f.called = true
	f.ev = ev
	return true
}

func TestPhishingScan_MalformedJSON_Returns400(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/phishing/scan", bytes.NewReader([]byte("{not json")))
	h.Scan(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestPhishingScan_EmptyInput_Returns400(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": ""}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "input_empty" {
		t.Errorf("code = %q, want input_empty", resp["code"])
	}
}

func TestPhishingScan_InvalidKind_Returns400(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "http://example.com", "kind": "carrier_pigeon"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "kind_invalid" {
		t.Errorf("code = %q, want kind_invalid", resp["code"])
	}
}

// TestPhishingScan_DefaultKind_IsURL confirms an omitted kind defaults
// to "url" rather than being rejected.
func TestPhishingScan_DefaultKind_IsURL(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "http://example.com/safe"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var res phishing.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Kind != phishing.KindURL {
		t.Errorf("Kind = %q, want %q", res.Kind, phishing.KindURL)
	}
}

// TestPhishingScan_KnownKinds_Accepted exercises every explicit kind
// value so a future regression that drops one is caught.
func TestPhishingScan_KnownKinds_Accepted(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	for _, k := range []string{"url", "email", "html"} {
		k := k
		t.Run(k, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.Scan(w, newPhishingReq(t, map[string]string{"input": "http://example.com/safe", "kind": k}))
			if w.Code != http.StatusOK {
				t.Fatalf("kind %q: want 200, got %d", k, w.Code)
			}
		})
	}
}

// TestPhishingScan_MatchTriggersBlocked exercises the real pattern
// match → BLOCKED classification path end-to-end through the handler.
func TestPhishingScan_MatchTriggersBlocked(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "please verify-your-account now", "kind": "email"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var res phishing.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Classification != phishing.ClassificationBlocked {
		t.Errorf("Classification = %q, want BLOCKED", res.Classification)
	}
	if len(res.Matches) != 1 || res.Matches[0].PatternID != "PH-TEST-001" {
		t.Errorf("Matches = %+v, want a single PH-TEST-001 hit", res.Matches)
	}
}

// TestPhishingScan_StoreNil_Succeeds mirrors the prompt-handler
// contract: persistence is best-effort and Store=nil must not affect
// the response.
func TestPhishingScan_StoreNil_Succeeds(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "hello"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestPhishingScan_CitadelEmits_OnMatch verifies the handler forwards
// deduplicated categories + patterns to CITADEL on a match, and that
// the emitter is invoked at all — a governed detection that silently
// skips WORM emission is an audit-path defect per repo policy.
func TestPhishingScan_CitadelEmits_OnMatch(t *testing.T) {
	emitter := &fakeWORMEmitter{}
	h := &PhishingHandler{Scanner: newPhishingScanner(t), Citadel: emitter, Tenant: "acme"}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "verify-your-account", "kind": "email"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if !emitter.called {
		t.Fatal("expected Citadel.EmitAsync to be called on a matched scan")
	}
	if emitter.ev.EventType != "phishing_scan" {
		t.Errorf("EventType = %q, want phishing_scan", emitter.ev.EventType)
	}
	if emitter.ev.Tenant != "acme" {
		t.Errorf("Tenant = %q, want acme", emitter.ev.Tenant)
	}
	if len(emitter.ev.Patterns) != 1 || emitter.ev.Patterns[0] != "PH-TEST-001" {
		t.Errorf("Patterns = %v, want [PH-TEST-001]", emitter.ev.Patterns)
	}
}

// TestPhishingScan_CitadelNil_Succeeds confirms the handler skips the
// WORM emit cleanly when no emitter is wired.
func TestPhishingScan_CitadelNil_Succeeds(t *testing.T) {
	h := &PhishingHandler{Scanner: newPhishingScanner(t)}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "verify-your-account"}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
}

// TestPhishingScan_InputTooLarge_Returns413 exercises the scanner's
// size-cap error path via the handler's errors.As unwrap.
func TestPhishingScan_InputTooLarge_Returns413(t *testing.T) {
	pat := phishing.MustCompilePattern("PH-X", phishing.CategoryCredentialHarvest, "x", "", 0.5, `x`)
	tiny := phishing.NewScanner([]phishing.Pattern{pat}, 0.3, 0.7, 8) // 8-byte cap
	h := &PhishingHandler{Scanner: tiny}
	w := httptest.NewRecorder()
	h.Scan(w, newPhishingReq(t, map[string]string{"input": "this input is definitely longer than 8 bytes"}))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "input_too_large" {
		t.Errorf("code = %q, want input_too_large", resp["code"])
	}
}
