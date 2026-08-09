package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestIncidentList_InvalidLimitReturns400WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/incidents?limit=0", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentCreate_MalformedJSONReturns400WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/incidents", bytes.NewReader([]byte("{not json")))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentCreate_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/incidents", bytes.NewReader([]byte(`{"title":"x"}`)))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentGet_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodGet, "/incidents/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentEscalate_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/incidents/not-a-uuid/escalate", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Escalate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentEscalate_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	id := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+id+"/escalate", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Escalate(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentClose_InvalidUUIDReturns400WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	req := httptest.NewRequest(http.MethodPost, "/incidents/not-a-uuid/close", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Close(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentClose_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Incident{Service: nil}
	id := "11111111-1111-1111-1111-111111111111"
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+id+"/close", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Close(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}
