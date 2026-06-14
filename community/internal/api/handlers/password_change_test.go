package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/api/middleware"
	"github.com/opensecstack/community/internal/auth"
	"github.com/opensecstack/community/internal/config"
)

// withClaims injects auth.Claims into the request context the same way the
// Auth middleware does, so handlers can call middleware.ClaimsFrom(ctx).
func withClaims(r *http.Request, claims *auth.Claims) *http.Request {
	ctx := context.WithValue(r.Context(), middleware.ClaimsKey, claims)
	return r.WithContext(ctx)
}

func TestChangePassword_NoToken_Returns401(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	body, _ := json.Marshal(map[string]string{
		"current_password": "oldpass",
		"new_password":     "newpass123",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	// No claims injected — simulates missing/invalid JWT.
	w := httptest.NewRecorder()

	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

func TestChangePassword_ShortNewPassword_Returns422(t *testing.T) {
	d := newDepsWithBadDB(t)

	claims := &auth.Claims{Sub: "testuser", Role: "author"}
	body, _ := json.Marshal(map[string]string{
		"current_password": "oldpass",
		"new_password":     "short",
	})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, claims)

	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422 for short password, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] == "" {
		t.Error("expected non-empty error message")
	}
}

func TestChangePassword_BadJSON_Returns400(t *testing.T) {
	d := handlers.Deps{
		Cfg: &config.Config{},
	}

	claims := &auth.Claims{Sub: "testuser", Role: "author"}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/me/password", bytes.NewReader([]byte(`{bad json}`)))
	req.Header.Set("Content-Type", "application/json")
	req = withClaims(req, claims)

	w := httptest.NewRecorder()
	handlers.ChangePassword(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad JSON, got %d", w.Code)
	}
}
