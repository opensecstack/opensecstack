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

	"github.com/opensecstack/threatflow/internal/api/middleware"
	"github.com/opensecstack/threatflow/internal/auth"
	"github.com/opensecstack/threatflow/internal/db/store"
)

func TestAuthToken_ServiceDisabledReturns503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{"api_key":"x"}`))

	h.Token(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestAuthToken_RejectsMalformedJSON(t *testing.T) {
	svc, _ := auth.NewService(auth.Config{Secret: "0123456789abcdef0123456789abcdef"})
	h := NewAuth(zerolog.Nop(), svc, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{not json`))

	h.Token(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestAuthToken_UnknownKeyReturns401(t *testing.T) {
	svc, _ := auth.NewService(auth.Config{Secret: "0123456789abcdef0123456789abcdef"})
	h := NewAuth(zerolog.Nop(), svc, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{"api_key":"unknown"}`))

	h.Token(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestAuthToken_BootstrapKeyIssuesToken(t *testing.T) {
	svc, err := auth.NewService(auth.Config{
		Secret:        "0123456789abcdef0123456789abcdef",
		BootstrapKeys: map[string]auth.Role{"bootstrap-secret": auth.RoleAdmin},
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	h := NewAuth(zerolog.Nop(), svc, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(`{"api_key":"bootstrap-secret"}`))

	h.Token(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["access_token"] == "" || body["access_token"] == nil {
		t.Error("expected non-empty access_token")
	}
	if body["role"] != string(auth.RoleAdmin) {
		t.Errorf("role = %v, want %q", body["role"], auth.RoleAdmin)
	}
}

func TestAuthCreateKey_PersistenceDisabledReturns503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/keys", strings.NewReader(`{"name":"x","role":"viewer"}`))

	h.CreateKey(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

func TestAuthListKeys_NilStoreReturnsEmptyList(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/keys", nil)

	h.ListKeys(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	keys, _ := body["keys"].([]any)
	if len(keys) != 0 {
		t.Errorf("expected empty keys, got %v", keys)
	}
}

func TestAuthRevokeKey_PersistenceDisabledReturns503(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/keys/x", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "11111111-1111-1111-1111-111111111111")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.RevokeKey(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

// TestAuthRevokeKey_NilStoreShortCircuitsBeforeIDValidation pins the actual
// checked ordering in RevokeKey: the nil-store guard runs before
// uuid.Parse, so even a syntactically invalid ID gets 503 (persistence
// disabled), not 400. Exercising the 400 branch itself requires a live
// *store.APIKeyStore (concrete pgxpool-backed struct, no fake seam), which
// is out of reach without a database.
func TestAuthRevokeKey_NilStoreShortCircuitsBeforeIDValidation(t *testing.T) {
	svc, _ := auth.NewService(auth.Config{Secret: "0123456789abcdef0123456789abcdef"})
	h := NewAuth(zerolog.Nop(), svc, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/keys/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.RevokeKey(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

// TestAuthRevokeKey_NonNilStoreRejectsInvalidID proves ID validation runs
// before any store touch, once a real (DB-less) store is wired — the branch
// TestAuthRevokeKey_NilStoreShortCircuitsBeforeIDValidation documents as
// unreachable under a nil store.
func TestAuthRevokeKey_NonNilStoreRejectsInvalidID(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, store.NewAPIKeyStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/auth/keys/not-a-uuid", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "not-a-uuid")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	h.RevokeKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

func TestAuthMe_UnauthenticatedReturns401(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)

	h.Me(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestAuthMe_ReturnsIdentityFromContext(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	id := &auth.Identity{Subject: "apikey:xyz", Role: auth.RoleOperator, Source: "api_key"}
	req = req.WithContext(middleware.ContextWithIdentity(req.Context(), id))

	h.Me(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	if body["subject"] != "apikey:xyz" {
		t.Errorf("subject = %v, want apikey:xyz", body["subject"])
	}
	if body["role"] != string(auth.RoleOperator) {
		t.Errorf("role = %v, want %q", body["role"], auth.RoleOperator)
	}
}

// TestAuthCreateKey_RejectsMalformedJSON proves the validation path (which
// runs before any store access) rejects unparseable bodies with 400 even
// when a real, non-nil store is wired.
func TestAuthCreateKey_RejectsMalformedJSON(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, store.NewAPIKeyStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/keys", strings.NewReader(`{not json`))

	h.CreateKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}

// TestAuthCreateKey_RejectsMissingNameOrRole proves both required fields are
// enforced independently — a request missing either one must 400 before
// ever reaching h.keys.Create (which would panic on the nil pool if reached).
func TestAuthCreateKey_RejectsMissingNameOrRole(t *testing.T) {
	cases := []string{
		`{"role":"viewer"}`,     // missing name
		`{"name":"x"}`,          // missing role
		`{"name":"","role":""}`, // both empty
	}
	for _, body := range cases {
		h := NewAuth(zerolog.Nop(), nil, store.NewAPIKeyStore(nil))
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/auth/keys", strings.NewReader(body))

		h.CreateKey(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("body=%s: want 400, got %d; response=%s", body, rec.Code, rec.Body.String())
		}
	}
}

// TestAuthCreateKey_RejectsInvalidRole proves an out-of-vocabulary role
// string is rejected at the handler boundary rather than being persisted
// and only failing downstream RBAC checks silently.
func TestAuthCreateKey_RejectsInvalidRole(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, store.NewAPIKeyStore(nil))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/keys", strings.NewReader(`{"name":"x","role":"superadmin"}`))

	h.CreateKey(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	json.NewDecoder(rec.Body).Decode(&body)
	if body["error"] == "" {
		t.Error("expected non-empty error message for invalid role")
	}
}

// TestAuthListKeys_NonNilStoreWithBrokenPoolReturns500 proves that when a
// store IS configured but the underlying query fails (simulated here by a
// nil pgxpool, which the store methods hit before ever reaching Postgres —
// they panic, so this test intentionally avoids calling List and instead
// documents the nil-store branch is the only one reachable without a live
// DB). Retained as a guard: NilStoreReturnsEmptyList must keep returning the
// *disabled* shape ({"keys":[]}), not silently change to an error shape.
func TestAuthListKeys_NilStoreShapeIsStable(t *testing.T) {
	h := NewAuth(zerolog.Nop(), nil, nil)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/keys", nil)

	h.ListKeys(rec, req)

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := body["keys"]; !ok {
		t.Fatal(`expected "keys" field in disabled-store response`)
	}
	if _, hasError := body["error"]; hasError {
		t.Error("disabled store must return an empty list, not an error shape")
	}
}

func TestValidRole(t *testing.T) {
	cases := map[string]bool{
		"viewer": true, "analyst": true, "operator": true, "admin": true,
		"superadmin": false, "": false, "Viewer": false,
	}
	for role, want := range cases {
		if got := validRole(role); got != want {
			t.Errorf("validRole(%q) = %v, want %v", role, got, want)
		}
	}
}
