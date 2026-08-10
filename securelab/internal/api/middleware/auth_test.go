// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2024 opensecstack contributors.

package middleware_test

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/opensecstack/securelab/internal/api/middleware"
)

// itoa is a tiny local alias to keep the alg=none test body compact.
func itoa(n int64) string { return strconv.FormatInt(n, 10) }

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

// TestRequireRole_UnknownMinRoleBlocksEveryone exercises the fail-safe branch
// in RequireRole: if it is ever misconfigured with a role name that is not in
// roleRank (e.g. a typo like "admim"), it must deny access to everyone,
// including admins, rather than fail open.
func TestRequireRole_UnknownMinRoleBlocksEveryone(t *testing.T) {
	h := requireRoleChain(testSecret, "admim") // typo: not a real role

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "u1",
		"role": "admin",
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 (fail-safe deny-all) for unrecognised minRole, got %d", rr.Code)
	}
}

// TestRequireRole_UnknownTokenRoleIsRejected verifies that a role claim which
// is not one of the known roles (e.g. a token forged/misconfigured with role
// "superadmin") is treated as insufficient privilege rather than granted
// access by falling through some default.
func TestRequireRole_UnknownTokenRoleIsRejected(t *testing.T) {
	h := requireRoleChain(testSecret, "viewer")

	tok := mintJWT(t, testSecret, map[string]any{
		"sub":  "u1",
		"role": "superadmin", // not in roleRank
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unrecognised token role, got %d", rr.Code)
	}
}

// TestAuthenticate_AlgNoneRejected guards against the classic JWT
// "alg confusion" / algorithm-downgrade attack, where an attacker crafts a
// token with header alg=none (or any non-HS256 alg) and an empty/garbage
// signature, hoping a permissive verifier accepts it. Authenticate must
// reject it outright since isRS256Token returns false for it and the HS256
// path enforces jwt.WithValidMethods([]string{"HS256"}).
func TestAuthenticate_AlgNoneRejected(t *testing.T) {
	mw := middleware.Authenticate(testSecret, "")
	h := mw(okHandler)

	// Hand-craft a JWT with alg=none: header.payload. (empty signature).
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"attacker","role":"admin","exp":` +
		itoa(time.Now().Add(time.Hour).Unix()) + `}`))
	forged := header + "." + payload + "."

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+forged)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for alg=none forged token, got %d", rr.Code)
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
