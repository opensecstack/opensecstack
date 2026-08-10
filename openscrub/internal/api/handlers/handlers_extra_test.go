package handlers_test

// Covers Health.Ready (previously 0%) and the 500-path branches of
// Rules.List/Get/Delete that newTestServer's happy-path MemoryRepo
// never exercises (MemoryRepo only ever returns ErrNotFound or nil —
// never an arbitrary error), plus Delete's bad_id / bad_reason
// validation branches.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/dataplane"
	"github.com/opensecstack/openscrub/internal/rules"
)

// erroringRepo implements rules.Repo and returns a fixed, non-
// ErrNotFound error from every method — used to force handlers down
// their 500 branches, which a MemoryRepo-backed service can never do.
type erroringRepo struct{ err error }

func (r *erroringRepo) Insert(context.Context, rules.Rule) (rules.Rule, error) { return rules.Rule{}, r.err }
func (r *erroringRepo) Get(context.Context, uuid.UUID) (rules.Rule, error)     { return rules.Rule{}, r.err }
func (r *erroringRepo) Delete(context.Context, uuid.UUID) error                { return r.err }
func (r *erroringRepo) List(context.Context, rules.Type, int, int) ([]rules.Rule, error) {
	return nil, r.err
}
func (r *erroringRepo) DeleteExpired(context.Context, time.Time) ([]rules.Rule, error) {
	return nil, r.err
}
func (r *erroringRepo) Count(context.Context) (int, error) { return 0, r.err }

func newErroringRulesHandler() *handlers.Rules {
	svc := rules.New(rules.Deps{
		Repo: &erroringRepo{err: errors.New("connection refused")},
		Plane: dataplane.NewNoopClient(), NodeName: "test", Logger: zerolog.Nop(),
	})
	return &handlers.Rules{Service: svc, Logger: zerolog.Nop()}
}

func TestRulesListInternalErrorReturns500(t *testing.T) {
	h := newErroringRulesHandler()
	rec := httptest.NewRecorder()
	h.List(rec, httptest.NewRequest(http.MethodGet, "/api/v1/rules", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "list_failed" {
		t.Fatalf("error.code = %v, want list_failed", errObj["code"])
	}
}

func TestRulesGetInternalErrorReturns500(t *testing.T) {
	h := newErroringRulesHandler()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/rules/"+uuid.New().String(), nil)
	req = withChiIDParam(req, uuid.New().String())
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRulesGetBadIDReturns400(t *testing.T) {
	h := newErroringRulesHandler()
	req := withChiIDParam(httptest.NewRequest(http.MethodGet, "/api/v1/rules/nope", nil), "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Get(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestRulesDeleteInternalErrorReturns500(t *testing.T) {
	h := newErroringRulesHandler()
	req := withChiIDParam(httptest.NewRequest(http.MethodDelete, "/api/v1/rules/x", nil), uuid.New().String())
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

func TestRulesDeleteBadIDReturns400(t *testing.T) {
	h := newErroringRulesHandler()
	req := withChiIDParam(httptest.NewRequest(http.MethodDelete, "/api/v1/rules/x", nil), "not-a-uuid")
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// TestRulesDeleteReasonTooLongReturns400 covers the 512-byte reason
// cap that guards against a giant query string reaching the WORM
// audit stream.
func TestRulesDeleteReasonTooLongReturns400(t *testing.T) {
	h := newErroringRulesHandler()
	longReason := strings.Repeat("a", 513)
	req := withChiIDParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/rules/x?reason="+longReason, nil),
		uuid.New().String())
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	errObj, _ := body["error"].(map[string]any)
	if errObj["code"] != "bad_reason" {
		t.Fatalf("error.code = %v, want bad_reason", errObj["code"])
	}
}

// TestRulesDeleteReasonWithControlCharReturns400 covers the
// control-character rejection (distinct branch from the length cap).
func TestRulesDeleteReasonWithControlCharReturns400(t *testing.T) {
	h := newErroringRulesHandler()
	req := withChiIDParam(
		httptest.NewRequest(http.MethodDelete, "/api/v1/rules/x?reason=bad%00reason", nil),
		uuid.New().String())
	rec := httptest.NewRecorder()
	h.Delete(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

// --- Health.Ready ---

type stubPinger struct{ err error }

func (p *stubPinger) Ping(context.Context) error { return p.err }

func TestHealthReadyAllHealthyReturns200(t *testing.T) {
	h := &handlers.Health{
		DB:                &stubPinger{},
		DataplaneAttached: func() bool { return true },
	}
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "ready" {
		t.Fatalf("status = %v, want ready", body["status"])
	}
}

func TestHealthReadyNoDependenciesConfiguredReturns200(t *testing.T) {
	// DB and DataplaneAttached both nil — nothing to check, so the
	// probe must default to ready (matches how dev-mode / standalone
	// deployments run with no DB configured).
	h := &handlers.Health{}
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
}

func TestHealthReadyDBPingFailureReturns503(t *testing.T) {
	h := &handlers.Health{DB: &stubPinger{err: errors.New("connection refused")}}
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["status"] != "not_ready" {
		t.Fatalf("status = %v, want not_ready", body["status"])
	}
	if body["db_ping"] != false {
		t.Fatalf("db_ping = %v, want false", body["db_ping"])
	}
}

func TestHealthReadyDataplaneDetachedReturns503(t *testing.T) {
	h := &handlers.Health{
		DB:                &stubPinger{},
		DataplaneAttached: func() bool { return false },
	}
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["reason"] != "dataplane not attached" {
		t.Fatalf("reason = %v, want 'dataplane not attached'", body["reason"])
	}
}

// TestHealthReadyDBFailureShortCircuitsDataplaneCheck proves that when
// DB ping fails, the handler does not also report on
// DataplaneAttached (the `ready &&` guard) — the response should
// reflect only the first failure it found.
func TestHealthReadyDBFailureShortCircuitsDataplaneCheck(t *testing.T) {
	calledDataplaneCheck := false
	h := &handlers.Health{
		DB: &stubPinger{err: errors.New("db down")},
		DataplaneAttached: func() bool {
			calledDataplaneCheck = true
			return true
		},
	}
	rec := httptest.NewRecorder()
	h.Ready(rec, httptest.NewRequest(http.MethodGet, "/api/v1/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if calledDataplaneCheck {
		t.Fatal("DataplaneAttached should not be evaluated once DB ping already failed")
	}
}

// withChiIDParam wires a chi RouteContext carrying {id} onto the
// request, mirroring what the chi router does at request time — the
// handlers under test read it via chi.URLParam(r, "id"), so calling
// them directly (bypassing the full router) still needs this.
func withChiIDParam(r *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
