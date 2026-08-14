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
	"github.com/opensecstack/threatflow/internal/db/store"
	"github.com/opensecstack/threatflow/internal/stix"
)

func TestIOCList_ReturnsEmptyList(t *testing.T) {
	h := NewIOC(zerolog.Nop(), nil, nil, nil, nil, nil)
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
	h := NewIOC(zerolog.Nop(), nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(`{"type":"ip","value":"1.2.3.4"}`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestIOCIngest_RejectsMalformedJSON(t *testing.T) {
	h := NewIOC(zerolog.Nop(), nil, nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")

	h.Ingest(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestIOCIngest_RejectsMissingRequiredFields proves type/value/pattern are
// all required once a real (DB-less) store is wired — reachable only after
// the store-nil scaffold short-circuit is removed.
func TestIOCIngest_RejectsMissingRequiredFields(t *testing.T) {
	cases := []string{
		`{"value":"1.2.3.4","pattern":"[ipv4-addr:value = '1.2.3.4']"}`, // missing type
		`{"type":"ipv4-addr","pattern":"[ipv4-addr:value = '1.2.3.4']"}`, // missing value
		`{"type":"ipv4-addr","value":"1.2.3.4"}`,                        // missing pattern
	}
	for _, body := range cases {
		h := NewIOC(zerolog.Nop(), store.NewIOCStore(nil), nil, nil, nil, nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(body))

		h.Ingest(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

// TestIOCIngest_CitadelRefuseForbids proves the MARSHAL gate blocks the
// upsert with a 403 before the store is ever touched.
func TestIOCIngest_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(citadel.Decision{
			Outcome: citadel.OutcomeRefuse,
			Reasons: []string{"blocked"},
		})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewIOC(zerolog.Nop(), store.NewIOCStore(nil), c, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"type":"ipv4-addr","value":"1.2.3.4","pattern":"[ipv4-addr:value = '1.2.3.4']"}`
	req := httptest.NewRequest(http.MethodPost, "/iocs", strings.NewReader(body))

	h.Ingest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestIOCGet_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewIOC(zerolog.Nop(), store.NewIOCStore(nil), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestIOCGet_ReturnsNotFound(t *testing.T) {
	h := NewIOC(zerolog.Nop(), nil, nil, nil, nil, nil)
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
	h := NewSTIX(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stix/bundles", nil)

	h.ListBundles(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestSTIXIngestBundle_Accepts(t *testing.T) {
	h := NewSTIX(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[]}`
	req := httptest.NewRequest(http.MethodPost, "/stix/bundles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	h.IngestBundle(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("want 202, got %d; body: %s", rec.Code, rec.Body.String())
	}
}

func TestSTIXIngestBundle_RejectsBadJSON(t *testing.T) {
	h := NewSTIX(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/stix/bundles", strings.NewReader(`{not json`))
	req.Header.Set("Content-Type", "application/json")

	h.IngestBundle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestSTIXIngestBundle_RejectsInvalidFeedID proves the ?feed_id query param
// is validated before the importer is ever invoked — reachable with a real
// (DB-less) importer since the check happens before any store call.
func TestSTIXIngestBundle_RejectsInvalidFeedID(t *testing.T) {
	importer := stix.NewImporter(store.NewStixStore(nil), store.NewIOCStore(nil), store.NewTTPStore(nil), nil, zerolog.Nop())
	h := NewSTIX(zerolog.Nop(), store.NewStixStore(nil), importer, nil, nil)
	rec := httptest.NewRecorder()
	body := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[]}`
	req := httptest.NewRequest(http.MethodPost, "/stix/bundles?feed_id=not-a-uuid", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	h.IngestBundle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestSTIXIngestBundle_CitadelRefuseForbids proves the MARSHAL gate blocks
// the import with a 403 before importer.Import is ever called.
func TestSTIXIngestBundle_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(citadel.Decision{
			Outcome: citadel.OutcomeRefuse,
			Reasons: []string{"blocked"},
		})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	importer := stix.NewImporter(store.NewStixStore(nil), store.NewIOCStore(nil), store.NewTTPStore(nil), nil, zerolog.Nop())
	h := NewSTIX(zerolog.Nop(), store.NewStixStore(nil), importer, c, nil)
	rec := httptest.NewRecorder()
	body := `{"type":"bundle","id":"bundle--44444444-4444-4444-4444-444444444444","spec_version":"2.1","objects":[]}`
	req := httptest.NewRequest(http.MethodPost, "/stix/bundles", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	h.IngestBundle(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSTIXGetBundle_NilStoreReturns404(t *testing.T) {
	h := NewSTIX(zerolog.Nop(), nil, nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stix/bundles/x", nil)

	h.GetBundle(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestSTIXGetBundle_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewSTIX(zerolog.Nop(), store.NewStixStore(nil), nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stix/bundles/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.GetBundle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}
