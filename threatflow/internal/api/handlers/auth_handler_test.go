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
