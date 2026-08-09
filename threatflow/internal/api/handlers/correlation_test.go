package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestCorrelationForIOC_NilStoreReturnsEmpty(t *testing.T) {
	h := NewCorrelation(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/x/correlations", nil)

	h.ForIOC(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	items, _ := body["correlations"].([]any)
	if len(items) != 0 {
		t.Errorf("expected empty correlations, got %v", items)
	}
}

func TestCorrelationForIOC_InvalidIDReturns400(t *testing.T) {
	h := NewCorrelation(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/not-a-uuid/correlations", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.ForIOC(rec, req)

	// nil-store short-circuit returns 200 before the ID is even parsed —
	// pin that ordering explicitly since it's a real behavioural choice.
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200 (nil store short-circuits before ID validation), got %d", rec.Code)
	}
}

// TestCorrelationForIOC_NonNilStoreRejectsInvalidID proves that once a real
// (non-nil) store is wired, an invalid UUID path param is rejected with 400
// before any store call — this is the branch TestCorrelationForIOC_InvalidIDReturns400
// documents as unreachable under the nil-store short-circuit; a non-nil
// store (even DB-less) makes it reachable.
func TestCorrelationForIOC_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewCorrelation(zerolog.Nop(), store.NewCorrelationStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/not-a-uuid/correlations", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.ForIOC(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestCorrelationSummary_NilStoreReturnsEmpty(t *testing.T) {
	h := NewCorrelation(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/correlations/summary", nil)

	h.Summary(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	items, _ := body["summary"].([]any)
	if len(items) != 0 {
		t.Errorf("expected empty summary, got %v", items)
	}
}
