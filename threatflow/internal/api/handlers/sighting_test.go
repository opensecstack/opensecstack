package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestSightingRecord_PersistenceDisabledReturns503(t *testing.T) {
	h := NewSighting(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(`{}`))

	h.Record(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestSightingForIOC_NilStoreReturnsEmpty(t *testing.T) {
	h := NewSighting(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/x/sightings", nil)

	h.ForIOC(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	items, _ := body["sightings"].([]any)
	if len(items) != 0 {
		t.Errorf("expected empty sightings, got %v", items)
	}
}

func TestSightingMatch_NilIOCStoreReturns404(t *testing.T) {
	h := NewSighting(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/match?type=ip&value=1.2.3.4", nil)

	h.Match(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestValidSightingPlatform(t *testing.T) {
	cases := map[string]bool{
		"apiguard": true, "irflow": true, "manual": true,
		"": false, "unknown": false, "APIGuard": false,
	}
	for p, want := range cases {
		if got := validSightingPlatform(p); got != want {
			t.Errorf("validSightingPlatform(%q) = %v, want %v", p, got, want)
		}
	}
}
