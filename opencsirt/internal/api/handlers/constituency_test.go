package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestKindToNIS2(t *testing.T) {
	cases := map[string]string{
		"sector":       "out_of_scope",
		"essential":    "essential",
		"important":    "important",
		"out_of_scope": "out_of_scope",
		"":             "",
	}
	for in, want := range cases {
		if got := kindToNIS2(in); got != want {
			t.Errorf("kindToNIS2(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConstituencyList_InvalidLimitReturns400WithoutTouchingService(t *testing.T) {
	// Service left nil: the handler must reject the bad query param before
	// ever calling into it, or this test panics.
	h := &Constituency{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/constituencies?limit=not-a-number", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyCreate_MalformedJSONReturns400WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/constituencies", bytes.NewReader([]byte("{not json")))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyCreate_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	body, _ := json.Marshal(constituencyRequest{Name: "Acme", Sector: "energy"})
	req := httptest.NewRequest(http.MethodPost, "/constituencies", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyGet_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/constituencies/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyUpdate_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	req := httptest.NewRequest(http.MethodPut, "/constituencies/not-a-uuid", bytes.NewReader([]byte("{}")))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyUpdate_MalformedJSONReturns400WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	id := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPut, "/constituencies/"+id, bytes.NewReader([]byte("{not json")))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
