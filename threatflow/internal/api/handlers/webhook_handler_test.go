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

	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestWebhookList_NilStoreReturnsEmpty(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks", nil)

	h.List(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	subs, _ := body["subscribers"].([]any)
	if len(subs) != 0 {
		t.Errorf("expected empty subscribers, got %v", subs)
	}
}

func TestWebhookCreate_PersistenceDisabledReturns503(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(`{"name":"x","url":"https://example.com"}`))

	h.Create(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

// TestWebhookCreate_RejectsMalformedJSON proves the decode-error path is
// reachable and 400s even with a real (DB-less) store wired.
func TestWebhookCreate_RejectsMalformedJSON(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(`{not json`))

	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestWebhookCreate_RejectsMissingNameOrURL proves both required fields are
// validated before any store call.
func TestWebhookCreate_RejectsMissingNameOrURL(t *testing.T) {
	cases := []string{
		`{"url":"https://example.com"}`,
		`{"name":"x"}`,
		`{}`,
	}
	for _, body := range cases {
		h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(body))

		h.Create(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

// TestWebhookCreate_RejectsInvalidPlatform proves the platform allowlist is
// enforced at the handler boundary.
func TestWebhookCreate_RejectsInvalidPlatform(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	body := `{"name":"x","url":"https://example.com","platform":"not-a-real-platform"}`
	req := httptest.NewRequest(http.MethodPost, "/webhooks", strings.NewReader(body))

	h.Create(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
}

func TestWebhookGet_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Get(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestWebhookGet_NilStoreReturns404(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks/x", nil)

	h.Get(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rec.Code)
	}
}

func TestWebhookPatch_InvalidIDReturns400(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	// Force store non-nil path is unreachable without a live pool, but
	// h.store == nil short-circuits to 503 before ID parsing — pin that.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/webhooks/x", strings.NewReader(`{"enabled":true}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Patch(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 (nil store short-circuits before ID validation), got %d", rec.Code)
	}
}

// TestWebhookPatch_NonNilStoreRejectsInvalidID proves ID validation runs
// before any store touch, once a real store is wired.
func TestWebhookPatch_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch, "/webhooks/not-a-uuid", strings.NewReader(`{"enabled":true}`))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Patch(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestWebhookPatch_RejectsMissingEnabledField proves a body without a
// boolean "enabled" key is rejected with 400 before the store is touched.
func TestWebhookPatch_RejectsMissingEnabledField(t *testing.T) {
	validID := "11111111-1111-1111-1111-111111111111"
	cases := []string{`{}`, `{"enabled":null}`, `{not json`}
	for _, body := range cases {
		h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/webhooks/"+validID, strings.NewReader(body))
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", validID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

		h.Patch(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d", body, rec.Code)
		}
	}
}

func TestWebhookDelete_NilStoreReturns503(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/webhooks/x", nil)

	h.Delete(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestWebhookDelete_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/webhooks/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Delete(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestWebhookDeliveries_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), store.NewWebhookStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks/not-a-uuid/deliveries", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.Deliveries(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestWebhookDeliveries_NilStoreReturnsEmpty(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks/x/deliveries", nil)

	h.Deliveries(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	items, _ := body["deliveries"].([]any)
	if len(items) != 0 {
		t.Errorf("expected empty deliveries, got %v", items)
	}
}

func TestWebhookStats_NilStoreReturnsEmpty(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/webhooks/stats", nil)

	h.Stats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestValidPlatform(t *testing.T) {
	cases := map[string]bool{
		"apiguard": true, "irflow": true, "nis2compass": true, "external": true,
		"": false, "unknown": false,
	}
	for p, want := range cases {
		if got := validPlatform(p); got != want {
			t.Errorf("validPlatform(%q) = %v, want %v", p, got, want)
		}
	}
}
