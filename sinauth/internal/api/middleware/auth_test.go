package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/token"
)

// testIssuerVerifier builds a matched Issuer/Verifier pair backed by a
// throwaway RSA key, mirroring internal/token/issuer_test.go's pattern.
func testIssuerVerifier(t *testing.T) (*token.Issuer, *token.Verifier) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := token.NewIssuer(key, "test-kid", "https://sinauth.test")
	verifier := token.NewVerifier(&key.PublicKey, "https://sinauth.test")
	return issuer, verifier
}

// fakeAdminChecker implements AdminChecker against an in-memory set, so
// these tests don't need a database.
type fakeAdminChecker map[string]bool

func (f fakeAdminChecker) IsPlatformAdmin(_ context.Context, userID string) (bool, error) {
	return f[userID], nil
}

func mustToken(t *testing.T, issuer *token.Issuer, sub string) string {
	t.Helper()
	tok, err := issuer.IssueAccessToken(sub, "test-client", []string{"openid"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	return tok
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// TestRequireAdmin_NoToken proves the exploit precondition is closed: a
// request with no bearer token at all never reaches the admin check.
func TestRequireAdmin_NoToken(t *testing.T) {
	issuer, verifier := testIssuerVerifier(t)
	_ = issuer
	admins := fakeAdminChecker{}
	h := RequireAdmin(verifier, admins)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/organizations", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestRequireAdmin_NonAdminForbidden is the core regression test for the
// vulnerability: an authenticated user with a validly-signed, unexpired
// token but no platform-admin standing must be rejected with 403, not
// allowed through the way plain BearerAuth allowed everyone through.
func TestRequireAdmin_NonAdminForbidden(t *testing.T) {
	issuer, verifier := testIssuerVerifier(t)
	admins := fakeAdminChecker{} // empty: nobody is admin
	h := RequireAdmin(verifier, admins)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+mustToken(t, issuer, "attacker-user-id"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestRequireAdmin_AdminAllowed proves a real platform admin still gets
// through to the handler.
func TestRequireAdmin_AdminAllowed(t *testing.T) {
	issuer, verifier := testIssuerVerifier(t)
	admins := fakeAdminChecker{"admin-user-id": true}
	h := RequireAdmin(verifier, admins)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+mustToken(t, issuer, "admin-user-id"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestRequireAdmin_AdminCheckerError fails closed: if the admin lookup
// itself errors (e.g. a transient DB error), the request must still be
// rejected rather than silently let through.
func TestRequireAdmin_AdminCheckerError(t *testing.T) {
	issuer, verifier := testIssuerVerifier(t)
	admins := erroringAdminChecker{}
	h := RequireAdmin(verifier, admins)(okHandler())

	req := httptest.NewRequest(http.MethodGet, "/admin/organizations", nil)
	req.Header.Set("Authorization", "Bearer "+mustToken(t, issuer, "some-user-id"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (fail-closed on error)", rec.Code, http.StatusForbidden)
	}
}

type erroringAdminChecker struct{}

func (erroringAdminChecker) IsPlatformAdmin(_ context.Context, _ string) (bool, error) {
	return false, context.DeadlineExceeded
}
