package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/opencsirt/internal/advisory"
	"github.com/opensecstack/opencsirt/internal/auth"
	"github.com/opensecstack/opencsirt/internal/db"
)

// unreachableAdvisoryPool returns a pgx pool configured against a
// syntactically valid but unreachable address (port 1 on loopback).
// pgxpool.NewWithConfig never dials eagerly, so construction always
// succeeds; the first real query then fails fast with a
// connection-refused error. This exercises advisory.Service's real
// store-call and error-propagation branches (previously 0%-covered in
// this handler) without a live Postgres and without mocking db.AdvisoryStore,
// which wraps *pgxpool.Pool concretely and has no interface seam.
func unreachableAdvisoryPool(t *testing.T) *db.Pool {
	t.Helper()
	pool, err := db.Open(context.Background(), "postgres://user:pass@127.0.0.1:1/db", 1)
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func realAdvisoryService(t *testing.T) *advisory.Service {
	t.Helper()
	pool := unreachableAdvisoryPool(t)
	return advisory.NewService(db.NewAdvisoryStore(pool), db.NewOutboxStore(pool), db.NewAuditStore(pool), advisory.NoopClient{})
}

func authedRequest(req *http.Request, role auth.Role) *http.Request {
	return req.WithContext(auth.ContextWithClaims(req.Context(), &auth.Claims{
		Sub:  uuid.New().String(),
		Role: role,
	}))
}

func TestAdvisoryList_StoreErrorReturns500(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t)}
	req := httptest.NewRequest(http.MethodGet, "/advisories", nil)
	req = authedRequest(req, auth.RoleOperator)
	w := httptest.NewRecorder()
	h.List(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryCreate_StoreErrorReturns400(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t)}
	body := []byte(`{"title":"x","tlp":"green"}`)
	req := httptest.NewRequest(http.MethodPost, "/advisories", bytes.NewReader(body))
	req = authedRequest(req, auth.RoleOperator)
	w := httptest.NewRecorder()
	h.Create(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGet_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/advisories/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGet_StoreErrorMapsToStatus(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/advisories/"+id, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, auth.RoleOperator)
	w := httptest.NewRecorder()
	h.Get(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGetCSAF_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/advisories/"+id+"/csaf", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.GetCSAF(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryGetCSAF_StoreErrorMapsToStatus(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodGet, "/advisories/"+id+"/csaf", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, auth.RoleOperator)
	w := httptest.NewRecorder()
	h.GetCSAF(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryPublish_MissingAuthReturns401WithoutTouchingService(t *testing.T) {
	h := &Advisory{Service: nil}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodPost, "/advisories/"+id+"/publish", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	w := httptest.NewRecorder()
	h.Publish(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("code = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}

// TestAdvisoryPublish_CitadelNilSkipsGovernanceStoreErrorMapsToStatus proves
// that when h.Citadel is nil the governance check is skipped entirely (as
// documented on the Advisory struct) and the handler falls straight through
// to Service.Publish, whose error is mapped via mapDBError.
func TestAdvisoryPublish_CitadelNilSkipsGovernanceStoreErrorMapsToStatus(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t), Citadel: nil, Logger: zerolog.Nop()}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodPost, "/advisories/"+id+"/publish", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, auth.RoleCSIRTLead)
	w := httptest.NewRecorder()
	h.Publish(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

func TestAdvisoryWithdraw_StoreErrorMapsToStatus(t *testing.T) {
	h := &Advisory{Service: realAdvisoryService(t)}
	id := uuid.New().String()
	req := httptest.NewRequest(http.MethodPost, "/advisories/"+id+"/withdraw", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	req = authedRequest(req, auth.RoleOperator)
	w := httptest.NewRecorder()
	h.Withdraw(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500; body=%s", w.Code, w.Body.String())
	}
}

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
