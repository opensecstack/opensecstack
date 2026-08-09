package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestAdvisoryList_InvalidLimitReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/advisories?limit=abc", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryList_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/advisories", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryCreate_MalformedJSONReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/advisories", bytes.NewReader([]byte("{not json")))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryCreate_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/advisories", bytes.NewReader([]byte(`{"title":"x","tlp":"green"}`)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGet_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/advisories/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGetCSAF_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/advisories/not-a-uuid/csaf", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.GetCSAF(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryPublish_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/advisories/not-a-uuid/publish", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Publish(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryWithdraw_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/advisories/not-a-uuid/withdraw", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Withdraw(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryWithdraw_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	id := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/advisories/"+id+"/withdraw", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Withdraw(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}
