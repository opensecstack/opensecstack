package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

func TestHealth_ServeHTTP_NoDB_ReportsOK(t *testing.T) {
	h := NewHealth(zerolog.Nop(), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rw.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want %q", resp["status"], "ok")
	}
	// db is nil, so no "db" key should be reported (only checked when db != nil).
	if _, ok := resp["db"]; ok {
		t.Errorf("expected no \"db\" key when db is nil, got %q", resp["db"])
	}
	if resp["version"] == "" {
		t.Error("expected non-empty version field")
	}
}

func TestHealth_ServeHTTP_ContentType(t *testing.T) {
	h := NewHealth(zerolog.Nop(), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if ct := rw.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}
