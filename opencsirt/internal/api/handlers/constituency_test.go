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
	"github.com/opensecstack/opencsirt/internal/constituency"
	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachableConstituencyPool returns a pgx pool configured against a
// syntactically valid but unreachable address (port 1 on loopback), letting
// constituency.Service's real store-call and error-propagation branches
// (previously largely 0%-covered in this handler) be exercised without a
// live Postgres and without mocking db.ConstituencyStore, which wraps
// *pgxpool.Pool concretely and has no interface seam.
func unreachableConstituencyPool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func realConstituencyService(t *testing.T) *constituency.Service {
	t.Helper()
	pool := unreachableConstituencyPool(t)
	return constituency.New(db.NewConstituencyStore(pool), db.NewAuditStore(pool), zerolog.Nop())
}

func constituencyAuthedRequest(req *http.Request) *http.Request {
	return req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		Sub:  uuid.New().String(),
		Role: auth.RoleOperator,
	}))
}

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

func TestConstituencyUpdate_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Constituency{Service: nil}
	id := "11111111-1111-1111-1111-111111111111"
	body, _ := json.Marshal(constituencyRequest{Name: "Acme", Sector: "energy", Kind: "essential"})
	req := httptest.NewRequest(http.MethodPut, "/constituencies/"+id, bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyList_StoreErrorReturns500(t *testing.T) {
	h := &Constituency{Service: realConstituencyService(t)}
	req := httptest.NewRequest(http.MethodGet, "/constituencies", nil)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

// TestConstituencyCreate_ValidationErrorReturns400WithoutTouchingStore
// proves invalid input (an empty Kind maps to an empty, invalid NIS2Status)
// is rejected by constituency.Service's own validation before any store
// call — the Service is built with a nil store; a store call here would
// nil-pointer panic and fail the test.
func TestConstituencyCreate_ValidationErrorReturns400WithoutTouchingStore(t *testing.T) {
	h := &Constituency{Service: constituency.New(nil, nil, zerolog.Nop())}
	body, _ := json.Marshal(constituencyRequest{Name: "Acme", Sector: "energy", Kind: ""})
	req := httptest.NewRequest(http.MethodPost, "/constituencies", bytes.NewReader(body))
	req = constituencyAuthedRequest(req)
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestConstituencyGet_StoreErrorMapsToStatus(t *testing.T) {
	h := &Constituency{Service: realConstituencyService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/constituencies/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

// TestConstituencyUpdate_StoreErrorReturns400 exercises Update's real
// store.Get call failing against an unreachable DB: since the resulting
// error is a plain connection failure (not db.ErrNotFound), it must fall
// through the errors.Is(db.ErrNotFound) check to the generic 400 branch.
func TestConstituencyUpdate_StoreErrorReturns400(t *testing.T) {
	h := &Constituency{Service: realConstituencyService(t)}
	id := uuid.New().String()
	body, _ := json.Marshal(constituencyRequest{Name: "Acme", Sector: "energy", Kind: "essential"})
	req := httptest.NewRequest(http.MethodPut, "/constituencies/"+id, bytes.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = constituencyAuthedRequest(req)
	w := httptest.NewRecorder()
	h.Update(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
