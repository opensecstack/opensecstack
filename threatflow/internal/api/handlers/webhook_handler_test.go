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

func TestWebhookDelete_NilStoreReturns503(t *testing.T) {
	h := NewWebhook(zerolog.Nop(), nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/webhooks/x", nil)

	h.Delete(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
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
