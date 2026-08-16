package handlers

// White-box test for the unexported queryInt helper. Kept in package
// handlers (rather than handlers_test) specifically because queryInt has no
// exported surface of its own — every handler that uses it only reveals the
// parsed value indirectly through a live DB query, which the rest of this
// test suite avoids. Testing it directly here gives real coverage of its
// three branches (default, valid, invalid/negative) without inventing a way
// to observe it through an HTTP handler.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteJSON_SetsContentTypeStatusAndBody(t *testing.T) {
	w := httptest.NewRecorder()
	writeJSON(w, http.StatusTeapot, map[string]string{"foo": "bar"})

	if w.Code != http.StatusTeapot {
		t.Errorf("expected status %d, got %d", http.StatusTeapot, w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["foo"] != "bar" {
		t.Errorf("expected body foo=bar, got %+v", body)
	}
}

func TestDecodeJSON_ValidBody_PopulatesStruct(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte(`{"name":"alice"}`)))
	var v struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(req, &v); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if v.Name != "alice" {
		t.Errorf("expected name=alice, got %q", v.Name)
	}
}

func TestDecodeJSON_UnknownField_ReturnsError(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", bytes.NewReader([]byte(`{"name":"alice","extra":"nope"}`)))
	var v struct {
		Name string `json:"name"`
	}
	if err := decodeJSON(req, &v); err == nil {
		t.Error("expected error for unknown field (DisallowUnknownFields), got nil")
	}
}

func TestDecodeJSON_MalformedBody_ReturnsError(t *testing.T) {
	req := httptest.NewRequest("POST", "/x", strings.NewReader(`{not json`))
	var v map[string]any
	if err := decodeJSON(req, &v); err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestQueryInt_MissingParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 when param missing, got %d", got)
	}
}

func TestQueryInt_ValidParam_ReturnsParsedValue(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=17", nil)
	if got := queryInt(r, "limit", 42); got != 17 {
		t.Errorf("expected parsed value 17, got %d", got)
	}
}

func TestQueryInt_NonNumericParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=abc", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 for non-numeric param, got %d", got)
	}
}

func TestQueryInt_NegativeParam_ReturnsDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?limit=-5", nil)
	if got := queryInt(r, "limit", 42); got != 42 {
		t.Errorf("expected default 42 for negative param, got %d", got)
	}
}

func TestQueryInt_ZeroParam_ReturnsZero(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?offset=0", nil)
	if got := queryInt(r, "offset", 10); got != 0 {
		t.Errorf("expected 0 to be accepted, got %d", got)
	}
}
