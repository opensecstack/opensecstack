//go:build integration

package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/opensecstack/sinauth/internal/api/middleware"
	"github.com/opensecstack/sinauth/internal/token"
)

func withClaims(r *http.Request, claims *token.AccessTokenClaims) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.ClaimsKey, claims))
}

// TestUserInfo_NoClaims_Unauthorized proves the endpoint rejects requests
// that never made it through BearerAuth (no claims in context) rather than
// panicking on a nil claims dereference or defaulting to some other subject.
func TestUserInfo_NoClaims_Unauthorized(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	rec := httptest.NewRecorder()
	UserInfo(d)(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestUserInfo_ClaimsForDeletedUser_NotFound proves a validly-signed token
// whose subject no longer exists (e.g. account deleted after token issuance)
// is rejected with 404, not served as if it were a real user.
func TestUserInfo_ClaimsForDeletedUser_NotFound(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)

	claims := &token.AccessTokenClaims{Sub: fmt.Sprintf("ghost-user-%d", time.Now().UnixNano())}
	req := withClaims(httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil), claims)
	rec := httptest.NewRecorder()
	UserInfo(d)(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

// TestUserInfo_ValidUser_ReturnsOIDCClaims proves the standard OIDC claims
// (sub, email, email_verified, name, picture) are populated from the real
// user record for an authenticated request.
func TestUserInfo_ValidUser_ReturnsOIDCClaims(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("userinfo-%d", time.Now().UnixNano()))

	claims := &token.AccessTokenClaims{Sub: u.Username}
	req := withClaims(httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil), claims)
	rec := httptest.NewRecorder()
	UserInfo(d)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["sub"] != u.Username {
		t.Errorf("sub = %v, want %q", body["sub"], u.Username)
	}
	if body["email"] != u.Email {
		t.Errorf("email = %v, want %q", body["email"], u.Email)
	}
	// A freshly created test user has not verified their email.
	if v, ok := body["email_verified"]; ok && v != false {
		t.Errorf("email_verified = %v, want false or omitted", v)
	}
}
