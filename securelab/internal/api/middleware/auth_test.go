// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/opensecstack/securelab/internal/api/middleware"
)

const testSecret = "super-secret-key-for-tests"

// mintJWT creates a signed HS256 JWT from the provided claims map.
func mintJWT(t *testing.T, secret string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	s, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// okHandler is a trivial next handler used to confirm the middleware called through.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// ---------------------------------------------------------------------------
// Authenticate tests
// ---------------------------------------------------------------------------

func TestAuthenticate_NoAuthorizationHeader(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthenticate_HeaderNotBearer(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestAuthenticate_ValidJWT(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")

	var capturedSub, capturedRole string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSub = middleware.SubjectFromContext(r.Context())
		capturedRole = middleware.RoleFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	h := mw(next)

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "user-123",
		"role": "analyst",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if capturedSub != "user-123" {
		t.Errorf("expected sub=user-123, got %q", capturedSub)
	}
	if capturedRole != "analyst" {
		t.Errorf("expected role=analyst, got %q", capturedRole)
	}
}

func TestAuthenticate_ExpiredJWT(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "user-123",
		"role": "analyst",
		"exp":  time.Now().Add(-time.Hour).Unix(), // already expired
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for expired token, got %d", rr.Code)
	}
}

func TestAuthenticate_WrongSecret(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	tok := mintJWT(t, "different-secret", map[string]any{
		"sub":  "user-123",
		"role": "analyst",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong secret, got %d", rr.Code)
	}
}

func TestAuthenticate_MissingSubClaim(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	tok := mintJWT(t, testSecret, map[string]any{
		// no "sub"
		"role": "analyst",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing sub, got %d", rr.Code)
	}
}

func TestAuthenticate_MissingRoleClaim(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	tok := mintJWT(t, testSecret, map[string]any{
		"sub": "user-123",
		// no "role"
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing role, got %d", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// RequireRole tests
// ---------------------------------------------------------------------------

// requireRoleChain builds a handler chain: Authenticate → RequireRole → okHandler.
func requireRoleChain(secret, minRole string) http.Handler {
	return middleware.Authenticate(secret, "")(
		middleware.RequireRole(minRole)(okHandler),
	)
}

func TestRequireRole_AdminPassesAdmin(t *testing.T) {
	h := requireRoleChain(testSecret, "admin")

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "u1",
		"role": "admin",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRequireRole_ViewerFailsOperator(t *testing.T) {
	h := requireRoleChain(testSecret, "operator")

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "u1",
		"role": "viewer",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
}

func TestRequireRole_AnalystPassesAnalyst(t *testing.T) {
	h := requireRoleChain(testSecret, "analyst")

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "u1",
		"role": "analyst",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestRequireRole_NoRoleInContext(t *testing.T) {
	// Call RequireRole directly without going through Authenticate first,
	// so no role is stored in the context.
	h := middleware.RequireRole("analyst")(okHandler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when no role in context, got %d", rr.Code)
	}
}
