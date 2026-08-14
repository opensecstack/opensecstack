//go:build integration

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func doRevokeRequest(t *testing.T, d Deps, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Revoke(d)(rec, req)
	return rec
}

// TestRevoke_MissingToken_InvalidRequest proves the required "token"
// parameter (RFC 7009 §2.1) is enforced.
func TestRevoke_MissingToken_InvalidRequest(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	rec := doRevokeRequest(t, d, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRevoke_MalformedBody_InvalidRequest proves a body that fails
// url.ParseQuery is rejected with 400 rather than panicking or 500ing.
func TestRevoke_MalformedBody_InvalidRequest(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	// "%zz" is not a valid percent-encoding escape.
	rec := doRevokeRequest(t, d, "token=%zz")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestRevoke_ValidRefreshToken_RevokesAndReturns200 proves a real refresh
// token is actually marked revoked in the store, not just acknowledged.
func TestRevoke_ValidRefreshToken_RevokesAndReturns200(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("revoke-valid-%d", time.Now().UnixNano()))

	raw := fmt.Sprintf("refresh-revoke-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	rec := doRevokeRequest(t, d, "token="+raw)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Consuming the token must now fail — it has been revoked.
	_, _, _, err := d.TokenStore.ConsumeRefreshToken(context.Background(), raw)
	if err == nil {
		t.Fatal("ConsumeRefreshToken succeeded after Revoke — token was not actually revoked")
	}
}

// TestRevoke_UnknownToken_StillReturns200 proves RFC 7009 §2.2 idempotency
// and non-disclosure: the authorization server must return HTTP 200 for a
// revocation request even when the token was never issued at all — it must
// not leak, via a distinct status code or error body, whether the token
// exists. Revoke's current best-effort "ignore the store error" design gets
// this right; this test locks that behavior in against regression.
func TestRevoke_UnknownToken_StillReturns200(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	rec := doRevokeRequest(t, d, fmt.Sprintf("token=never-issued-%d", time.Now().UnixNano()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (RFC 7009 requires 200 even for unknown tokens); body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestRevoke_AlreadyRevokedToken_StillReturns200 proves revocation is
// idempotent: revoking the same token twice does not error out on the
// second call.
func TestRevoke_AlreadyRevokedToken_StillReturns200(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("revoke-twice-%d", time.Now().UnixNano()))

	raw := fmt.Sprintf("refresh-revoke-twice-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	first := doRevokeRequest(t, d, "token="+raw)
	if first.Code != http.StatusOK {
		t.Fatalf("first revoke status = %d, want %d", first.Code, http.StatusOK)
	}
	second := doRevokeRequest(t, d, "token="+raw)
	if second.Code != http.StatusOK {
		t.Fatalf("second revoke status = %d, want %d (idempotency)", second.Code, http.StatusOK)
	}
}
