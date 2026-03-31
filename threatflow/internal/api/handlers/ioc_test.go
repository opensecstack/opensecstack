package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"
)

func TestIOCList_ReturnsEmptyList(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	items, _ := body["items"].([]any)
	if len(items) != 0 {
		t.Errorf("expected empty items, got %d", len(items))
	}
}

func TestIOCIngest_AcceptsValidJSON(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(`{"type":"ip","value":"1.2.3.4"}`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestIOCIngest_RejectsMalformedJSON(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestIOCGet_ReturnsNotFound(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/missing-id", nil)
	// Inject chi route param
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "missing-id")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestSTIXListBundles_ReturnsEmpty(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stix/bundles", nil)

	h.ListBundles(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestSTIXIngestBundle_Accepts(t *testing.T) {
	h := NewIOC(zerolog.Nop())
	rec := httptest.NewRecorder()
	body := `{"type":"bundle","id":"bundle--1234","objects":[]}`
	req := httptest.NewRequest(http.MethodPost, "/stix/bundles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	h.IngestBundle(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d", rec.Code)
	}
}
