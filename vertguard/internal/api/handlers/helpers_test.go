package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ─── validateReason ─────────────────────────────────────────────────

func TestValidateReason_Empty_Allowed(t *testing.T) {
	if err := validateReason(""); err != nil {
		t.Errorf("empty reason should be allowed, got %v", err)
	}
}

func TestValidateReason_ExactlyMaxLen_Allowed(t *testing.T) {
	s := strings.Repeat("a", MaxReasonLen)
	if err := validateReason(s); err != nil {
		t.Errorf("reason at exactly MaxReasonLen should be allowed, got %v", err)
	}
}

func TestValidateReason_OverMaxLen_Rejected(t *testing.T) {
	s := strings.Repeat("a", MaxReasonLen+1)
	if err := validateReason(s); err != ErrBadReason {
		t.Errorf("want ErrBadReason for over-length reason, got %v", err)
	}
}

func TestValidateReason_TabAllowed(t *testing.T) {
	if err := validateReason("ticket\tVG-1234"); err != nil {
		t.Errorf("tab should be allowed, got %v", err)
	}
}

func TestValidateReason_ControlCharsRejected(t *testing.T) {
	tests := []struct {
		name string
		s    string
	}{
		{"newline", "line1\nline2"},
		{"null_byte", "abc\x00def"},
		{"escape", "abc\x1bdef"},
		{"vertical_tab", "abc\x0bdef"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateReason(tc.s); err != ErrBadReason {
				t.Errorf("validateReason(%q) = %v, want ErrBadReason", tc.s, err)
			}
		})
	}
}

func TestValidateReason_NormalText_Allowed(t *testing.T) {
	if err := validateReason("ticket VG-1234: brute force from 1.2.3.4"); err != nil {
		t.Errorf("normal reason text should be allowed, got %v", err)
	}
}

// ─── decodeJSON ─────────────────────────────────────────────────────

func TestDecodeJSON_ValidBody_Decodes(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"input":"hello"}`)))
	var v struct {
		Input string `json:"input"`
	}
	if err := decodeJSON(r, &v); err != nil {
		t.Fatalf("decodeJSON: %v", err)
	}
	if v.Input != "hello" {
		t.Errorf("Input = %q, want hello", v.Input)
	}
}

func TestDecodeJSON_UnknownField_Rejected(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{"input":"hello","surprise":"field"}`)))
	var v struct {
		Input string `json:"input"`
	}
	if err := decodeJSON(r, &v); err == nil {
		t.Fatal("expected an error for an unknown JSON field (DisallowUnknownFields)")
	}
}

func TestDecodeJSON_MalformedBody_ReturnsError(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader([]byte(`{not json`)))
	var v map[string]any
	if err := decodeJSON(r, &v); err == nil {
		t.Fatal("expected an error for malformed JSON")
	}
}

// TestDecodeJSON_OversizedBody_RejectedWithoutPanic exercises the
// http.MaxBytesReader(nil, ...) path: decodeJSON passes a nil
// http.ResponseWriter to MaxBytesReader, and a naive implementation
// could panic when the reader tries to notify the (nil) ResponseWriter
// that the body was too large. This proves that path is safe and
// actually rejects oversized bodies rather than silently truncating
// or accepting them.
func TestDecodeJSON_OversizedBody_RejectedWithoutPanic(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("decodeJSON panicked on an oversized body: %v", rec)
		}
	}()

	big := bytes.Repeat([]byte("a"), (1<<20)+1024)
	body := append([]byte(`{"input":"`), big...)
	body = append(body, []byte(`"}`)...)

	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	var v map[string]any
	err := decodeJSON(r, &v)
	if err == nil {
		t.Fatal("expected an error for a body exceeding the 1 MiB cap")
	}
}
