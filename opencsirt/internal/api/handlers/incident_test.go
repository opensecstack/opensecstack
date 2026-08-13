package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
	"github.com/opensecstack/opencsirt/internal/incident"
)

// unreachableIncidentPool returns a pgx pool configured against a
// syntactically valid but unreachable address (port 1 on loopback), letting
// incident.Service's real store-call and error-propagation branches
// (previously largely 0%-covered in this handler) be exercised without a
// live Postgres and without mocking db.IncidentStore, which wraps
// *pgxpool.Pool concretely and has no interface seam.
func unreachableIncidentPool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func realIncidentService(t *testing.T) *incident.Service {
	t.Helper()
	pool := unreachableIncidentPool(t)
	return incident.New(db.NewIncidentStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), zerolog.Nop())
}

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

// TestIncidentCreate_ValidationErrorReturns400WithoutTouchingStore proves
// invalid input is rejected by incident.Service's own validation before any
// store call — the Service is built with nil stores; a store call here
// would nil-pointer panic and fail the test.
func TestIncidentCreate_ValidationErrorReturns400WithoutTouchingStore(t *testing.T) {
	h := &Incident{Service: incident.New(nil, nil, nil, zerolog.Nop())}
	body, _ := json.Marshal(incidentRequest{Source: "manual", Severity: "not-a-real-severity", Title: "x"})
	req := httptest.NewRequest(http.MethodPost, "/incidents", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{Sub: uuid.New().String(), Role: auth.RoleOperator}))
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentList_StoreErrorReturns500(t *testing.T) {
	h := &Incident{Service: realIncidentService(t)}
	req := httptest.NewRequest(http.MethodGet, "/incidents", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentGet_StoreErrorMapsToStatus(t *testing.T) {
	h := &Incident{Service: realIncidentService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/incidents/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestIncidentEscalate_StoreErrorMapsToStatus(t *testing.T) {
	h := &Incident{Service: realIncidentService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+id+"/escalate", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{Sub: uuid.New().String(), Role: auth.RoleOperator}))
	w := httptest.NewRecorder()
	h.Escalate(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

// TestIncidentClose_CitadelNilSkipsGovernanceStoreErrorMapsToStatus proves
// that when h.Citadel is nil the governance check is skipped entirely (as
// documented on the Incident struct) and the handler falls straight through
// to Service.Close, whose error is mapped via mapDBError.
func TestIncidentClose_CitadelNilSkipsGovernanceStoreErrorMapsToStatus(t *testing.T) {
	h := &Incident{Service: realIncidentService(t), Citadel: nil, Logger: zerolog.Nop()}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodPost, "/incidents/"+id+"/close", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{Sub: uuid.New().String(), Role: auth.RoleOperator}))
	w := httptest.NewRecorder()
	h.Close(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}
