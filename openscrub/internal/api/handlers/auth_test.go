package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/opensecstack/openscrub/internal/api/handlers"
	"github.com/opensecstack/openscrub/internal/auth"
)

func newAuthHandler(t *testing.T, spec string) *handlers.Auth {
	t.Helper()
	creds := auth.NewCredentialStore("pepper", spec)
	issuer := auth.NewIssuer("test-secret", "openscrub", time.Hour)
	return handlers.NewAuth(handlers.AuthDeps{Creds: creds, Issuer: issuer, Logger: zerolog.Nop()})
}

func TestAuthEnabledFalseWhenNoCreds(t *testing.T) {
	a := newAuthHandler(t, "")
	if a.Enabled() {
		t.Fatal("Enabled() = true with an empty credential spec, want false")
	}
}

func TestAuthEnabledTrueWithCreds(t *testing.T) {
	hash := auth.HashPassword("pepper", "s3cret")
	a := newAuthHandler(t, "alice:admin:"+hash)
	if !a.Enabled() {
		t.Fatal("Enabled() = false with seeded credentials, want true")
	}
}

func TestLoginDisabledReturns503(t *testing.T) {
	a := newAuthHandler(t, "")
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "x"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	a.Login(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
}

func TestLoginBadJSON(t *testing.T) {
	hash := auth.HashPassword("pepper", "s3cret")
	a := newAuthHandler(t, "alice:admin:"+hash)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader([]byte("{not json")))
	a.Login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestLoginMissingFields(t *testing.T) {
	hash := auth.HashPassword("pepper", "s3cret")
	a := newAuthHandler(t, "alice:admin:"+hash)
	body, _ := json.Marshal(map[string]string{"username": "alice"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	a.Login(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", rec.Code)
	}
}

func TestLoginInvalidCredentials(t *testing.T) {
	hash := auth.HashPassword("pepper", "s3cret")
	a := newAuthHandler(t, "alice:admin:"+hash)
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "wrong"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	a.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestLoginSuccessReturnsToken(t *testing.T) {
	hash := auth.HashPassword("pepper", "s3cret")
	a := newAuthHandler(t, "alice:admin:"+hash)
	body, _ := json.Marshal(map[string]string{"username": "alice", "password": "s3cret"})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(body))
	a.Login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Role        string `json:"role"`
		Sub         string `json:"sub"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected non-empty access_token")
	}
	if resp.TokenType != "Bearer" {
		t.Fatalf("token_type = %q, want Bearer", resp.TokenType)
	}
	if resp.Role != "admin" {
		t.Fatalf("role = %q, want admin", resp.Role)
	}
	if resp.Sub != "alice" {
		t.Fatalf("sub = %q, want alice", resp.Sub)
	}

	// The minted token must itself verify against the same secret and
	// carry the expected claims — proves Login wires Issuer correctly,
	// not just that Mint() succeeded.
	v := auth.NewHS256Verifier([]string{"test-secret"}, "openscrub")
	claims, err := v.Verify(resp.AccessToken)
	if err != nil {
		t.Fatalf("minted token failed verification: %v", err)
	}
	if claims.Sub != "alice" || claims.Role != "admin" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestWhoamiNoClaims(t *testing.T) {
	a := newAuthHandler(t, "")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/whoami", nil)
	a.Whoami(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
}

func TestWhoamiWithClaims(t *testing.T) {
	a := newAuthHandler(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/whoami", nil)
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{
		Sub: "alice", Role: "admin", Roles: []string{"admin", "operator"}, Iss: "openscrub", Exp: 12345,
	}))
	rec := httptest.NewRecorder()
	a.Whoami(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d body=%s, want 200", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["sub"] != "alice" {
		t.Fatalf("sub = %v", resp["sub"])
	}
	if resp["role"] != "admin" {
		t.Fatalf("role = %v", resp["role"])
	}
	if resp["iss"] != "openscrub" {
		t.Fatalf("iss = %v", resp["iss"])
	}
	if _, ok := resp["roles"]; !ok {
		t.Fatal("expected roles field when Roles is non-empty")
	}
	if _, ok := resp["exp"]; !ok {
		t.Fatal("expected exp field when Exp > 0")
	}
}

func TestWhoamiOmitsOptionalFieldsWhenUnset(t *testing.T) {
	a := newAuthHandler(t, "")
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/whoami", nil)
	req = req.WithContext(auth.WithClaims(req.Context(), &auth.Claims{Sub: "bob", Role: "readonly"}))
	rec := httptest.NewRecorder()
	a.Whoami(rec, req)
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if _, ok := resp["roles"]; ok {
		t.Fatalf("did not expect roles field when Roles is empty, got %v", resp["roles"])
	}
	if _, ok := resp["iss"]; ok {
		t.Fatalf("did not expect iss field when unset, got %v", resp["iss"])
	}
	if _, ok := resp["exp"]; ok {
		t.Fatalf("did not expect exp field when Exp == 0, got %v", resp["exp"])
	}
}
