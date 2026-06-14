package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func mintToken(t *testing.T, secret, sub, role, iss string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  sub,
		"role": role,
		"iss":  iss,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestHS256VerifierRotation(t *testing.T) {
	v := NewHS256Verifier([]string{"primary", "next", "previous"}, "openscrub")
	for _, sec := range []string{"primary", "next", "previous"} {
		tok := mintToken(t, sec, "u1", RoleOperator, "openscrub")
		c, err := v.Verify(tok)
		if err != nil {
			t.Fatalf("secret %q: %v", sec, err)
		}
		if c.Sub != "u1" || c.Role != RoleOperator {
			t.Fatalf("claims wrong: %+v", c)
		}
	}
}

func TestHS256VerifierIssuerMismatch(t *testing.T) {
	v := NewHS256Verifier([]string{"k"}, "openscrub")
	tok := mintToken(t, "k", "u", RoleAdmin, "other")
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("expected issuer mismatch error")
	}
}

func TestRequireRoleForbids(t *testing.T) {
	mw := RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{Sub: "u", Role: RoleReadOnly}))
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d want 403", rec.Code)
	}
}

func TestRequireRoleNoClaimsReturns401(t *testing.T) {
	// The previous behaviour (auto-bypass) was a privilege-escalation
	// footgun: any handler whose middleware chain forgot the JWT
	// middleware silently received admin. RequireRole now fails closed.
	mw := RequireRole(RoleAdmin)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d want 401", rec.Code)
	}
}

func TestRequireRoleAdmits(t *testing.T) {
	mw := RequireRole(RoleAdmin, RoleOperator)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req = req.WithContext(WithClaims(req.Context(), &Claims{Sub: "u", Role: RoleOperator}))
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d want 200", rec.Code)
	}
}
