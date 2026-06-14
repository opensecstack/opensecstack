package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestValidateReason_Bounds covers the validateReason helper directly.
// Exercising the helper rather than only the HTTP edge keeps the
// rejection contract pinned even if individual handlers stop calling
// it (a regression we want a separate test to surface).
func TestValidateReason_Bounds(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
	}{
		{"empty", "", true},
		{"plain", "ticket VG-1234: brute force from 1.2.3.4", true},
		{"tab_allowed", "abuse\treport", true},
		{"newline_rejected", "abuse\nreport", false},
		{"cr_rejected", "abuse\rreport", false},
		{"nul_rejected", "abuse\x00report", false},
		{"max_len_ok", strings.Repeat("a", 256), true},
		{"over_len_rejected", strings.Repeat("a", 257), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateReason(tc.in)
			if tc.ok && err != nil {
				t.Fatalf("expected ok, got err: %v", err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected rejection, got nil")
			}
		})
	}
}

// TestRateLimitAdmin_BadReasonRejected ensures the wired handler emits
// the contract-defined 400 + bad_reason code.
func TestRateLimitAdmin_BadReasonRejected(t *testing.T) {
	h, _, _, _ := newTestRateLimitAdmin(t)
	body := `{"kind":"sub","value":"abuser","rps":0,"burst":0,"reason":"bad\nreason"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/ratelimit/overrides", bytes.NewBufferString(body))
	rw := httptest.NewRecorder()
	h.Create(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rw.Code, rw.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rw.Body.Bytes(), &got)
	if got["code"] != "bad_reason" {
		t.Fatalf("code = %v, want bad_reason; body=%s", got["code"], rw.Body.String())
	}
}
