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
)

func TestFeedList_NilStoreReturnsEmpty(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/feeds", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	feeds, _ := body["feeds"].([]any)
	if len(feeds) != 0 {
		t.Errorf("expected empty feeds, got %v", feeds)
	}
}

func TestFeedCreate_PersistenceDisabledReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(`{"name":"x","feed_type":"csv"}`))

	h.Create(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestFeedGet_NilStoreReturns404(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/feeds/x", nil)

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestFeedPatch_NilStoreReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/feeds/x", strings.NewReader(`{"enabled":true}`))

	h.Patch(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestFeedDelete_NilStoreReturns503(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/feeds/x", nil)

	h.Delete(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

// TestFeedCreate_RejectsMalformedJSON proves the JSON-decode failure path is
// reachable and correctly returns 400 even with a real (DB-less) store
// wired, i.e. before any store access happens.
func TestFeedCreate_RejectsMalformedJSON(t *testing.T) {
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(`{not json`))

	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestFeedCreate_RejectsMissingNameOrFeedType proves both required fields
// are validated before any store call.
func TestFeedCreate_RejectsMissingNameOrFeedType(t *testing.T) {
	cases := []string{
		`{"feed_type":"csv"}`,
		`{"name":"x"}`,
		`{}`,
	}
	for _, body := range cases {
		h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(body))

		h.Create(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

// TestFeedCreate_RejectsInvalidFeedType proves an out-of-vocabulary
// feed_type is rejected at the handler boundary.
func TestFeedCreate_RejectsInvalidFeedType(t *testing.T) {
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(`{"name":"x","feed_type":"not-a-real-type"}`))

	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestFeedGet_NonNilStoreRejectsInvalidID proves the id-validation branch is
// reachable (and returns 400, not a store-touching panic) once a real store
// is configured.
func TestFeedGet_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/feeds/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestFeedPatch_NonNilStoreRejectsInvalidID proves ID validation runs before
// any store touch, for the mutation path too.
func TestFeedPatch_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/feeds/not-a-uuid", strings.NewReader(`{"enabled":true}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Patch(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestFeedPatch_RejectsMissingEnabledField proves a body without a boolean
// "enabled" key (or malformed JSON) is rejected with 400 before the store or
// CITADEL gate is ever consulted.
func TestFeedPatch_RejectsMissingEnabledField(t *testing.T) {
	validID := "11111111-1111-1111-1111-111111111111"
	cases := []string{`{}`, `{"enabled":null}`, `{not json`}
	for _, body := range cases {
		h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/feeds/"+validID, strings.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", validID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		h.Patch(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

// TestFeedDelete_NonNilStoreRejectsInvalidID mirrors the Get/Patch guard for
// Delete.
func TestFeedDelete_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/feeds/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Delete(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestFeedGate_NilCitadelAllows proves gate is a no-op (always allows) when
// the handler was built with no CITADEL client at all — the common case for
// most deployments.
func TestFeedGate_NilCitadelAllows(t *testing.T) {
	h := NewFeed(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", nil)

	if !h.gate(rec, req, citadel.ActionFeedCreate, "desc") {
		t.Fatal("want true when citadel is nil")
	}
}

// TestFeedGate_DisabledCitadelAllows covers the other half of the first
// branch: a non-nil client with an empty base URL (Enabled() == false).
func TestFeedGate_DisabledCitadelAllows(t *testing.T) {
	c := citadel.New(citadel.Config{}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), nil, c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", nil)

	if !h.gate(rec, req, citadel.ActionFeedCreate, "desc") {
		t.Fatal("want true when citadel is disabled")
	}
}

// TestFeedGate_ExecuteDecisionAllows proves an EXECUTE decision from MARSHAL
// lets the caller proceed without writing a response.
func TestFeedGate_ExecuteDecisionAllows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(citadel.Decision{Outcome: citadel.OutcomeExecute})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), nil, c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", nil)

	if !h.gate(rec, req, citadel.ActionFeedCreate, "desc") {
		t.Fatalf("want true for EXECUTE decision, body=%s", rec.Body.String())
	}
}

// TestFeedGate_RefuseDecisionForbids proves a REFUSE decision from MARSHAL
// blocks the mutation with a 403 and surfaces the outcome/reasons.
func TestFeedGate_RefuseDecisionForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(citadel.Decision{
			Outcome: citadel.OutcomeRefuse,
			Reasons: []string{"policy violation"},
		})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), nil, c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", nil)

	if h.gate(rec, req, citadel.ActionFeedCreate, "desc") {
		t.Fatal("want false for REFUSE decision")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	if body["outcome"] != citadel.OutcomeRefuse {
		t.Errorf("outcome = %v, want %q", body["outcome"], citadel.OutcomeRefuse)
	}
}

// TestFeedCreate_CitadelRefuseForbids proves the MARSHAL gate blocks Create
// with a 403 before the store is ever touched — safe with a DB-less store
// since h.store.Create is never reached on refusal.
func TestFeedCreate_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"outcome": "REFUSE", "reasons": []string{"blocked"}})
	}))
	defer srv.Close()

	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/feeds", strings.NewReader(`{"name":"x","feed_type":"csv"}`))

	h.Create(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestFeedPatch_CitadelRefuseForbids mirrors the Create case for Patch.
func TestFeedPatch_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"outcome": "REFUSE", "reasons": []string{"blocked"}})
	}))
	defer srv.Close()

	validID := "11111111-1111-1111-1111-111111111111"
	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/feeds/"+validID, strings.NewReader(`{"enabled":true}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", validID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Patch(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

// TestFeedDelete_CitadelRefuseForbids mirrors the Create case for Delete.
func TestFeedDelete_CitadelRefuseForbids(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"outcome": "REFUSE", "reasons": []string{"blocked"}})
	}))
	defer srv.Close()

	validID := "11111111-1111-1111-1111-111111111111"
	c := citadel.New(citadel.Config{BaseURL: srv.URL, KeyID: "k", Secret: "s"}, zerolog.Nop())
	h := NewFeed(zerolog.Nop(), store.NewFeedStore(nil), c)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/feeds/"+validID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", validID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Delete(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestValidFeedType(t *testing.T) {
	cases := map[string]bool{
		"taxii21": true, "csv": true, "misp": true, "manual": true,
		"": false, "unknown": false,
	}
	for ty, want := range cases {
		if got := validFeedType(ty); got != want {
			t.Errorf("validFeedType(%q) = %v, want %v", ty, got, want)
		}
	}
}
