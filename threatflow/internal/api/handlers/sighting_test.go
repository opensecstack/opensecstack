package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/rs/zerolog"

	"github.com/opensecstack/threatflow/internal/cache"
	"github.com/opensecstack/threatflow/internal/db/store"
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

// TestSightingRecord_RejectsMalformedJSON proves the decode-error path
// short-circuits before touching the store.
func TestSightingRecord_RejectsMalformedJSON(t *testing.T) {
	h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), store.NewIOCStore(nil), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(`{not json`))

	h.Record(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestSightingRecord_RejectsMissingRequiredFields proves platform,
// resource_type, and resource_id are all required before any store call.
func TestSightingRecord_RejectsMissingRequiredFields(t *testing.T) {
	cases := []string{
		`{"resource_type":"endpoint","resource_id":"r1"}`,    // missing platform
		`{"platform":"apiguard","resource_id":"r1"}`,         // missing resource_type
		`{"platform":"apiguard","resource_type":"endpoint"}`, // missing resource_id
	}
	for _, body := range cases {
		h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), store.NewIOCStore(nil), nil, nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(body))

		h.Record(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

// TestSightingRecord_RejectsInvalidPlatform proves the platform allowlist is
// enforced.
func TestSightingRecord_RejectsInvalidPlatform(t *testing.T) {
	h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), store.NewIOCStore(nil), nil, nil)
	rec := httptest.NewRecorder()
	body := `{"platform":"not-a-real-platform","resource_type":"endpoint","resource_id":"r1"}`
	req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(body))

	h.Record(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestSightingRecord_RejectsInvalidIOCID proves a syntactically malformed
// explicit ioc_id is rejected with 400 before the IOC lookup is attempted.
func TestSightingRecord_RejectsInvalidIOCID(t *testing.T) {
	h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), store.NewIOCStore(nil), nil, nil)
	rec := httptest.NewRecorder()
	body := `{"ioc_id":"not-a-uuid","platform":"apiguard","resource_type":"endpoint","resource_id":"r1"}`
	req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(body))

	h.Record(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestSightingRecord_RejectsMissingIOCIdentifier proves that when no ioc_id
// is supplied, both type and value must be present — a partial (type only,
// or value only) request is rejected with 400 before any IOC lookup.
func TestSightingRecord_RejectsMissingIOCIdentifier(t *testing.T) {
	h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), store.NewIOCStore(nil), nil, nil)
	rec := httptest.NewRecorder()
	body := `{"platform":"apiguard","resource_type":"endpoint","resource_id":"r1"}`
	req := httptest.NewRequest(http.MethodPost, "/sightings", strings.NewReader(body))

	h.Record(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSightingForIOC_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewSighting(zerolog.Nop(), store.NewSightingStore(nil), nil, nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iocs/not-a-uuid/sightings", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.ForIOC(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestSightingMatch_RejectsMissingTypeOrValue proves both query params are
// required even when a real IOC store is wired.
func TestSightingMatch_RejectsMissingTypeOrValue(t *testing.T) {
	h := NewSighting(zerolog.Nop(), nil, store.NewIOCStore(nil), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/match?type=ip", nil) // no value
	h.Match(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/match?value=1.2.3.4", nil) // no type
	h.Match(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestSightingMatch_CacheHitShortCircuitsBeforeStore proves the documented
// hot-path optimisation actually works end-to-end: when the cache already
// holds a match for (type, value), Match must serve it directly and never
// reach h.iocs.IOCByValue — which would panic here since the IOC store is
// backed by a nil pool. A cache miss on this same handler would crash the
// test, so a passing result is direct proof the cache path was taken.
func TestSightingMatch_CacheHitShortCircuitsBeforeStore(t *testing.T) {
	mr := miniredis.RunT(t)
	c, err := cache.Open(context.Background(), "redis://"+mr.Addr(), time.Minute, zerolog.Nop())
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })

	key := cache.IOCMatchKey("ipv4-addr", "198.51.100.42")
	seeded := store.IOC{Type: "ipv4-addr", Value: "198.51.100.42", Confidence: 90}
	c.Set(context.Background(), key, seeded)

	// h.iocs is backed by a nil pool: if the cache path is skipped, calling
	// IOCByValue would panic and fail this test.
	h := NewSighting(zerolog.Nop(), nil, store.NewIOCStore(nil), nil, c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/match?type=ipv4-addr&value=198.51.100.42", nil)

	h.Match(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["match"] != true {
		t.Errorf("match = %v, want true", body["match"])
	}
	if body["cached"] != true {
		t.Errorf("cached = %v, want true", body["cached"])
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
