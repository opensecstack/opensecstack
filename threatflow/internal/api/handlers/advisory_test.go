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

	"github.com/opensecstack/threatflow/internal/citadel"
	"github.com/opensecstack/threatflow/internal/csaf"
	"github.com/opensecstack/threatflow/internal/db/store"
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

// TestAdvisoryIngest_RejectsInvalidCSAFDocument proves a JSON body that reads
// fine but is not a well-formed CSAF document (no importer.Ingest DB call
// ever needed to detect this — ParseDocument fails first) is surfaced as a
// 400 with the ErrInvalidCSAF message, using a real (DB-less) importer.
func TestAdvisoryIngest_RejectsInvalidCSAFDocument(t *testing.T) {
	importer := csaf.NewImporter(store.NewAdvisoryStore(nil), store.NewStixStore(nil), zerolog.Nop())
	h := NewAdvisory(zerolog.Nop(), store.NewAdvisoryStore(nil), importer, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/advisories", strings.NewReader(`{"document":{}}`))

	h.Ingest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestAdvisoryIngest_CitadelRefuseForbids proves the MARSHAL gate blocks
// ingestion with a 403 before ever calling importer.Ingest — safe to test
// with a DB-less importer since Ingest is never reached on refusal.
func TestAdvisoryIngest_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(citadel.Decision{
			Outcome: citadel.OutcomeRefuse,
			Reasons: []string{"blocked"},
		})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	importer := csaf.NewImporter(store.NewAdvisoryStore(nil), store.NewStixStore(nil), zerolog.Nop())
	h := NewAdvisory(zerolog.Nop(), store.NewAdvisoryStore(nil), importer, c, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/advisories", strings.NewReader(`{"document":{}}`))

	h.Ingest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestAdvisoryList_InvalidLimitOffsetAreIgnored(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/advisories?limit=notanumber&offset=-5", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestAdvisoryGet_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewAdvisory(zerolog.Nop(), store.NewAdvisoryStore(nil), nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/advisories/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}
