package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/vertguard/internal/identity"
)

// fakeIdentityMetrics records calls for assertion.
type fakeIdentityMetrics struct {
	scans   []string
	matches []string
}

func (f *fakeIdentityMetrics) ObserveIdentityScan(classification string, _ float64) {
	f.scans = append(f.scans, classification)
}
func (f *fakeIdentityMetrics) IncIdentityIndicatorMatch(indicatorID, _ string) {
	f.matches = append(f.matches, indicatorID)
}

func newIdentityReq(t *testing.T, body any) *http.Request {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/identity/verify", bytes.NewReader(buf))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func newTestIdentityScanner() *identity.Scanner {
	return identity.NewScanner(identity.DefaultLibrary, 0.30, 0.70, 64*1024, 10*time.Minute, 5)
}

func TestNewIdentityHandler(t *testing.T) {
	s := newTestIdentityScanner()
	h := NewIdentityHandler(s, nil, nil)
	if h.Scanner != s {
		t.Fatal("NewIdentityHandler did not wire the scanner")
	}
}

func TestIdentityHandler_WithML_Chains(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	got := h.WithML(nil)
	if got != h {
		t.Fatal("WithML should return the same handler for chaining")
	}
}

func TestIdentityHandler_Verify_MissingClaimType(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	w := httptest.NewRecorder()
	h.Verify(w, newIdentityReq(t, map[string]any{"context": "kyc"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "claim_type_missing" {
		t.Errorf("code=%q, want claim_type_missing", resp["code"])
	}
}

func TestIdentityHandler_Verify_InvalidClaimType(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	w := httptest.NewRecorder()
	h.Verify(w, newIdentityReq(t, map[string]any{"claim_type": "bogus_type"}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "claim_type_invalid" {
		t.Errorf("code=%q, want claim_type_invalid", resp["code"])
	}
}

func TestIdentityHandler_Verify_InvalidContext(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	w := httptest.NewRecorder()
	h.Verify(w, newIdentityReq(t, map[string]any{
		"claim_type": "passport",
		"context":    "not_a_real_context",
	}))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "context_invalid" {
		t.Errorf("code=%q, want context_invalid", resp["code"])
	}
}

func TestIdentityHandler_Verify_DefaultContextIsKYC(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	w := httptest.NewRecorder()
	h.Verify(w, newIdentityReq(t, map[string]any{"claim_type": "passport"}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", w.Code, w.Body.String())
	}
	var res identity.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Context != identity.ContextKYC {
		t.Fatalf("context = %q, want kyc", res.Context)
	}
}

func TestIdentityHandler_Verify_MalformedJSON(t *testing.T) {
	h := &IdentityHandler{Scanner: newTestIdentityScanner()}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/identity/verify", bytes.NewReader([]byte("{bad")))
	h.Verify(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", w.Code)
	}
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp["code"] != "input_malformed" {
		t.Errorf("code=%q, want input_malformed", resp["code"])
	}
}

func TestIdentityHandler_Verify_OversizedInput(t *testing.T) {
	s := identity.NewScanner(identity.DefaultLibrary, 0.30, 0.70, 50, 10*time.Minute, 5)
	h := &IdentityHandler{Scanner: s}
	// Build an oversized claim via a long id_number field value.
	longVal := ""
	for i := 0; i < 1000; i++ {
		longVal += "a"
	}
	w2 := httptest.NewRecorder()
	h.Verify(w2, newIdentityReq(t, map[string]any{
		"claim_type": "passport",
		"context":    "kyc",
		"fields":     map[string]string{"id_number": longVal},
	}))
	if w2.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d, want 413, body=%s", w2.Code, w2.Body.String())
	}
	var resp map[string]string
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	if resp["code"] != "input_too_large" {
		t.Errorf("code=%q, want input_too_large", resp["code"])
	}
}

func TestIdentityHandler_Verify_Success_MetricsAndCitadel(t *testing.T) {
	metrics := &fakeIdentityMetrics{}
	worm := &fakeWORM{}
	h := &IdentityHandler{
		Scanner: newTestIdentityScanner(),
		Metrics: metrics,
		Citadel: worm,
		Tenant:  "tenant-x",
	}
	w := httptest.NewRecorder()
	h.Verify(w, newIdentityReq(t, map[string]any{
		"claim_type": "passport",
		"context":    "kyc",
		"fields": map[string]string{
			"email": "throwaway@mailinator.com",
			"name":  "x",
		},
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200, body=%s", w.Code, w.Body.String())
	}
	var res identity.ScanResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(metrics.scans) != 1 || metrics.scans[0] != string(res.Classification) {
		t.Fatalf("metrics.scans = %v, want [%s]", metrics.scans, res.Classification)
	}
	if worm.count.Load() != 1 {
		t.Fatalf("worm emit count = %d, want 1", worm.count.Load())
	}
	if worm.last.EventType != "identity_verify" {
		t.Fatalf("worm event type = %q, want identity_verify", worm.last.EventType)
	}
	if worm.last.Tenant != "tenant-x" {
		t.Fatalf("worm tenant = %q, want tenant-x", worm.last.Tenant)
	}
}
