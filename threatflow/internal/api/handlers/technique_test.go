package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
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

