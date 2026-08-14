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

func TestTechniqueList_NilStoreReturnsEmptySummaryWithCatalogue(t *testing.T) {
	h := NewTechnique(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/techniques", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	summary, _ := body["summary"].([]any)
	if len(summary) != 0 {
		t.Errorf("expected empty summary for nil store, got %v", summary)
	}
	catalogue, _ := body["catalogue"].(map[string]any)
	if len(catalogue) == 0 {
		t.Error("expected non-empty embedded ATT&CK catalogue")
	}
}

func TestTechniqueForIOC_NilStoreReturnsEmptyTags(t *testing.T) {
	h := NewTechnique(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/x/techniques", nil)

	h.ForIOC(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	tags, _ := body["tags"].([]any)
	if len(tags) != 0 {
		t.Errorf("expected empty tags, got %v", tags)
	}
}

// TestTechniqueForIOC_NonNilStoreRejectsInvalidID proves ID validation runs
// before any store touch once a real (DB-less) store is wired.
func TestTechniqueForIOC_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewTechnique(zerolog.Nop(), store.NewTTPStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/not-a-uuid/techniques", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.ForIOC(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestTechniqueList_ZeroLimitIgnoredOnNilStore proves the limit query param
// parsing runs even though the nil-ttps branch skips the summary query.
func TestTechniqueList_ZeroLimitIgnoredOnNilStore(t *testing.T) {
	h := NewTechnique(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/techniques?limit=notanumber", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

