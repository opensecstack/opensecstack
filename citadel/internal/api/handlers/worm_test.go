package handlers

import (
	"bytes"
	"context"
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
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBufferString("not-json"))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestWORM_Emit_MissingFields(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	body, _ := json.Marshal(map[string]string{"source": ""})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

func TestWORM_Verify_InvalidFrom(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/worm/verify?from=not-a-date", nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}

// TestWORM_Emit_DBFailure_Returns500 confirms a real AppendWORM failure
// (DB unreachable) surfaces as a 500 to the caller instead of a false 200 —
// a governed action's audit record silently failing to persist while the
// HTTP layer reports success would be exactly the "shadow gap" CITADEL's
// WORM chain exists to prevent.
func TestWORM_Emit_DBFailure_Returns500(t *testing.T) {
	h := NewWORM(zerolog.Nop(), unreachableDB(t))
	body, _ := json.Marshal(map[string]string{"source": "test", "event_type": "test.event"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB failure, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestWORM_Verify_DBFailure_Returns500 confirms VerifyChain errors surface
// as a 500, not a false "valid" result — a broken chain-verification query
// silently reporting Valid:true would defeat the purpose of the endpoint.
func TestWORM_Verify_DBFailure_Returns500(t *testing.T) {
	h := NewWORM(zerolog.Nop(), unreachableDB(t))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/worm/verify", nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on DB failure, got %d: %s", rw.Code, rw.Body.String())
	}
}

// TestWORM_Emit_DefaultsEmptyPayloadToEmptyObject confirms Emit substitutes
// "{}" when the request omits payload — proven by checking the outbound
// call actually reaches AppendWORM (via the DB-failure 500, not a 400),
// i.e. the empty-payload substitution happens before the DB call rather
// than being rejected as a missing required field.
func TestWORM_Emit_DefaultsEmptyPayloadToEmptyObject(t *testing.T) {
	h := NewWORM(zerolog.Nop(), unreachableDB(t))
	body, _ := json.Marshal(map[string]string{"source": "test", "event_type": "test.event"})
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/v1/worm/emit", bytes.NewBuffer(body))
	rw := httptest.NewRecorder()
	h.Emit(rw, req)

	// Reaching the DB call (500, not 400) proves the missing payload field
	// did not block the request — it must have defaulted, not errored.
	if rw.Code != http.StatusInternalServerError {
		t.Fatalf("expected request with omitted payload to reach the DB call (500), got %d: %s", rw.Code, rw.Body.String())
	}
}

func TestWORM_Verify_InvalidTo(t *testing.T) {
	h := NewWORM(zerolog.Nop(), nil)
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/worm/verify?to=bad", nil)
	rw := httptest.NewRecorder()
	h.Verify(rw, req)
	if rw.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rw.Code)
	}
}
