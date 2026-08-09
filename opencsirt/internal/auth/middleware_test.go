package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestAuth(t *testing.T) *Authenticator {
	t.Helper()
	a, err := New([][]byte{[]byte(strings.Repeat("k", 32))}, "test-issuer", time.Hour, "pepper", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

func signHS256(t *testing.T, secret []byte, claims *Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func TestMiddleware_MissingBearer(t *testing.T) {
	a := newTestAuth(t)
	called := false
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
	if called {
		t.Fatal("next handler must not be called without a bearer token")
	}
}

func TestMiddleware_HS256Valid(t *testing.T) {
	a := newTestAuth(t)
	claims := &Claims{
		Sub:  "user-123",
		Role: RoleOperator,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := signHS256(t, []byte(strings.Repeat("k", 32)), claims)

	var gotClaims *Claims
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := ClaimsFrom(r.Context())
		if !ok {
			t.Fatal("claims not present in context")
		}
		gotClaims = c
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if gotClaims == nil || gotClaims.Sub != "user-123" || gotClaims.Role != RoleOperator {
		t.Fatalf("unexpected claims: %+v", gotClaims)
	}
}

func TestMiddleware_HS256InvalidToken(t *testing.T) {
	a := newTestAuth(t)
	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler must not be called for an invalid token")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

// TestMiddleware_RS256SinauthUnreachable exercises the RS256 dual-mode path:
// a token whose header declares alg=RS256 is routed to the sinauth SDK. When
// sinauth is unreachable, the middleware must fail closed with 401 rather than
// falling back to the HS256 path or letting the request through.
func TestMiddleware_RS256SinauthUnreachable(t *testing.T) {
	a := newTestAuth(t)
	// sinauth.New() dials this URL's discovery endpoint; a closed local port
	// fails fast rather than waiting out the 30s client timeout.
	a.sinauthURL = "http://127.0.0.1:1"

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT","kid":"k1"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
	fakeToken := header + "." + payload + ".sig"

	h := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("next handler must not be called when sinauth is unreachable")
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+fakeToken)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "sinauth unavailable") {
		t.Fatalf("body = %q, want it to mention sinauth unavailable", w.Body.String())
	}
}

func TestRequireRole(t *testing.T) {
	t.Run("no claims", func(t *testing.T) {
		h := RequireRole(RoleAnalyst)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next handler must not be called without claims")
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})

	t.Run("insufficient role", func(t *testing.T) {
		h := RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Fatal("next handler must not be called for insufficient role")
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := ContextWithClaims(req.Context(), &Claims{Sub: "u", Role: RoleViewer})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req.WithContext(ctx))
		if w.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", w.Code)
		}
	})

	t.Run("sufficient role", func(t *testing.T) {
		called := false
		h := RequireRole(RoleAnalyst)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		ctx := ContextWithClaims(req.Context(), &Claims{Sub: "u", Role: RoleAdmin})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req.WithContext(ctx))
		if w.Code != http.StatusOK || !called {
			t.Fatalf("status = %d, called=%v; want 200/true", w.Code, called)
		}
	})
}

func TestClaimsFrom_Absent(t *testing.T) {
	_, ok := ClaimsFrom(context.Background())
	if ok {
		t.Fatal("ClaimsFrom must return ok=false when no claims are set")
	}
}

func TestRank(t *testing.T) {
	if Rank(RoleAdmin) != 6 {
		t.Fatalf("Rank(admin) = %d, want 6", Rank(RoleAdmin))
	}
	if Rank(RoleViewer) != 1 {
		t.Fatalf("Rank(viewer) = %d, want 1", Rank(RoleViewer))
	}
	if got := Rank(Role("bogus")); got != 0 {
		t.Fatalf("Rank(bogus) = %d, want 0", got)
	}
}

func TestNewWithSinauth_RequiresSecret(t *testing.T) {
	_, err := NewWithSinauth(nil, "iss", time.Hour, "p", "", "")
	if err == nil {
		t.Fatal("expected error when no secrets are supplied")
	}
}

func TestLoadUsers_EdgeCases(t *testing.T) {
	base := []byte(strings.Repeat("k", 32))

	t.Run("wrong field count", func(t *testing.T) {
		_, err := New([][]byte{base}, "iss", time.Hour, "p", "alice:admin")
		if err == nil {
			t.Fatal("expected error for missing fields")
		}
	})

	t.Run("invalid role", func(t *testing.T) {
		_, err := New([][]byte{base}, "iss", time.Hour, "p", "alice:superuser:"+strings.Repeat("00", 32))
		if err == nil {
			t.Fatal("expected error for invalid role")
		}
	})

	t.Run("wrong hash length", func(t *testing.T) {
		_, err := New([][]byte{base}, "iss", time.Hour, "p", "alice:admin:aabb")
		if err == nil {
			t.Fatal("expected error for short sha256 hex")
		}
	})

	t.Run("blank entries are skipped, valid entries still load", func(t *testing.T) {
		hash := strings.Repeat("00", 32)
		a, err := New([][]byte{base}, "iss", time.Hour, "p", ",,alice:admin:"+hash+",, ")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, ok := a.users["alice"]; !ok {
			t.Fatal("expected alice to be loaded despite surrounding blank entries")
		}
	})
}

func TestVerify_KeyRotation(t *testing.T) {
	keyA := []byte(strings.Repeat("a", 32))
	keyB := []byte(strings.Repeat("b", 32))

	claims := &Claims{
		Sub:  "rot-user",
		Role: RoleViewer,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(keyB)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	verifier, err := New([][]byte{keyA, keyB}, "iss", time.Hour, "p", "")
	if err != nil {
		t.Fatalf("New verifier: %v", err)
	}
	got, err := verifier.Verify(signed)
	if err != nil {
		t.Fatalf("Verify with rotated key set: %v", err)
	}
	if got.Sub != "rot-user" {
		t.Fatalf("Sub = %q, want rot-user", got.Sub)
	}
}

func TestVerify_ExpiredToken(t *testing.T) {
	secret := []byte(strings.Repeat("k", 32))
	claims := &Claims{
		Sub:  "expired-user",
		Role: RoleViewer,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	a, err := New([][]byte{secret}, "iss", time.Hour, "p", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := a.Verify(signed); err == nil {
		t.Fatal("expected error verifying an expired token")
	}
}
