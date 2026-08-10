package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

func newInventory() *Inventory {
	return NewInventory(zerolog.Nop(), nil)
}

// injectChiParam sets a chi URL param on the request context.
func injectChiParam(r *http.Request, key, value string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, value)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}

// ── List ─────────────────────────────────────────────────────────────────────

func TestInventoryList_NilDB_ReturnsEmptyList(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body: %s", rec.Code, rec.Body.String())
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	items, ok := body["items"].([]any)
	if !ok || len(items) != 0 {
		t.Errorf("expected empty items array, got %v", body["items"])
	}
	if total, _ := body["total"].(float64); total != 0 {
		t.Errorf("expected total=0, got %v", total)
	}
}

func TestInventoryList_ReturnsJSON(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	ct := rec.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", ct)
	}
}

func TestInventoryList_PaginationDefaults(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)

	if limit, _ := body["limit"].(float64); limit != 50 {
		t.Errorf("expected default limit=50, got %v", limit)
	}
	if offset, _ := body["offset"].(float64); offset != 0 {
		t.Errorf("expected default offset=0, got %v", offset)
	}
}

func TestInventoryList_CustomPagination(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory?limit=10&offset=20", nil)
	rec := httptest.NewRecorder()
	h.List(rec, req)

	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)

	if limit, _ := body["limit"].(float64); limit != 10 {
		t.Errorf("expected limit=10, got %v", limit)
	}
	if offset, _ := body["offset"].(float64); offset != 20 {
		t.Errorf("expected offset=20, got %v", offset)
	}
}

// ── GetHistory ───────────────────────────────────────────────────────────────

func TestInventoryGetHistory_InvalidID(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory/not-a-uuid/history", nil)
	req = injectChiParam(req, "id", "not-a-uuid")
	rec := httptest.NewRecorder()
	h.GetHistory(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestInventoryGetHistory_NilDB_ReturnsNotFound(t *testing.T) {
	h := newInventory()

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/inventory/550e8400-e29b-41d4-a716-446655440000/history", nil)
	req = injectChiParam(req, "id", "550e8400-e29b-41d4-a716-446655440000")
	rec := httptest.NewRecorder()
	h.GetHistory(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d; body: %s", rec.Code, rec.Body.String())
	}
}
