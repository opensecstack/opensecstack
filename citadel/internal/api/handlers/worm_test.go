package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
)

// TestWORM_Emit_NoDB verifies that the handler returns 500 when db is nil
// (no real DB in unit tests — integration tests cover the happy path).
func TestWORM_Emit_InvalidBody(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/worm/emit", bytes.NewBufferString("not-json"))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestWORM_Emit_MissingFields(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	body, _ := json.Marshal(map[string]string{"source": ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestWORM_Verify_InvalidFrom(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/worm/verify?from=not-a-date", nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestWORM_Verify_InvalidTo(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/worm/verify?to=bad", nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}
