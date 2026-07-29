package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestAdvisoryList_ReturnsEmptyList(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/advisories", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestAdvisoryGet_ReturnsNotFound(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/advisories/missing-id", nil)

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestAdvisoryIngest_ScaffoldAcceptsValidJSONWhenPersistenceDisabled(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/advisories", strings.NewReader(`{"document":{}}`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAdvisoryIngest_RejectsMalformedJSON(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/advisories", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}
