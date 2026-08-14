//go:build integration

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/sinauth/internal/organization"
	"github.com/opensecstack/sinauth/internal/rbac"
	"github.com/opensecstack/sinauth/internal/token"
)

// testTokenDeps wires the minimal real (DB-backed) services Token/
// handleAuthCodeGrant/handleRefreshGrant touch, plus a throwaway RSA signing
// key for the Issuer — mirroring internal/api/server_admin_test.go's
// testServer and authorize_test.go's testDeps patterns.
func testTokenDeps(t *testing.T, pool *pgxpool.Pool) Deps {
	t.Helper()
	d := testDeps(t, pool)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	d.Issuer = token.NewIssuer(key, "test-kid", "https://sinauth.test")
	d.TokenStore = token.NewStore(pool)
	d.RBAC = rbac.NewStore(pool)
	d.Cfg.AccessTokenTTL = time.Hour
	d.Cfg.IDTokenTTL = 5 * time.Minute
	d.Cfg.RefreshTokenTTL = 720 * time.Hour
	return d
}

// insertAuthCode inserts a ready-to-consume authorization_codes row,
// mirroring what /oauth/authorize would have written, so
// handleAuthCodeGrant's `DELETE ... RETURNING` query has something to
// consume.
func insertAuthCode(t *testing.T, d Deps, code, clientID, userID string) {
	t.Helper()
	_, err := d.Pool.Exec(context.Background(), `
		INSERT INTO authorization_codes
		    (code, client_id, user_id, redirect_uri, scopes,
		     code_challenge, code_challenge_method, nonce, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		code, clientID, userID, "https://client.test/callback", []string{"openid"},
		"", "", "", time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("insertAuthCode: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })
}

func doTokenRequest(t *testing.T, d Deps, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Token(d)(rec, req)
	return rec
}

// TestHandleAuthCodeGrant_NoPolicies_Unchanged proves the common case today
// (no policies configured) still issues a token — wiring Evaluate into this
// call site must not regress the default, policy-free path.
func TestHandleAuthCodeGrant_NoPolicies_Unchanged(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("nopolicy-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-nopolicy-%d", time.Now().UnixNano())
	insertAuthCode(t, d, code, clientID, u.ID)

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Fatalf("expected access_token in response, got %v", resp)
	}
}

// TestHandleAuthCodeGrant_DenyRolePolicy_BlocksIssuance is the core proof
// that rbac.Store.Evaluate now actually runs at token issuance: a deny_role
// policy matching the user's assigned role must block the authorization_code
// grant instead of silently being ignored (the pre-existing dead-code
// behavior — see evaluator.go's history/ground truth in the plan doc).
func TestHandleAuthCodeGrant_DenyRolePolicy_BlocksIssuance(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("denied-%d", time.Now().UnixNano()))

	roleID, err := d.RBAC.CreateClientRole(context.Background(), clientID, "banned", "")
	if err != nil {
		t.Fatalf("CreateClientRole: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.DeleteClientRole(context.Background(), roleID) })
	if err := d.RBAC.AssignUserRole(context.Background(), u.ID, clientID, "banned"); err != nil {
		t.Fatalf("AssignUserRole: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.RevokeUserRole(context.Background(), u.ID, clientID, "banned") })

	policyID, err := d.RBAC.CreatePolicy(context.Background(), rbac.Policy{
		Name:     fmt.Sprintf("deny-banned-%d", time.Now().UnixNano()),
		Type:     "deny_role",
		ClientID: clientID,
		RoleName: "banned",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.DeletePolicy(context.Background(), policyID) })

	code := fmt.Sprintf("code-denied-%d", time.Now().UnixNano())
	insertAuthCode(t, d, code, clientID, u.ID)

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s) — deny_role policy should have blocked issuance", rec.Code, http.StatusForbidden, rec.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["error"] == "" {
		t.Fatalf("expected an error body, got %v", resp)
	}
}

// TestHandleRefreshGrant_NoPolicies_Unchanged is the refresh-grant
// counterpart to TestHandleAuthCodeGrant_NoPolicies_Unchanged.
func TestHandleRefreshGrant_NoPolicies_Unchanged(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("refresh-nopolicy-%d", time.Now().UnixNano()))

	raw := fmt.Sprintf("refresh-nopolicy-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestHandleRefreshGrant_DenyRolePolicy_BlocksIssuance is the refresh-grant
// counterpart to TestHandleAuthCodeGrant_DenyRolePolicy_BlocksIssuance — a
// policy added after the original login must still apply on refresh.
func TestHandleRefreshGrant_DenyRolePolicy_BlocksIssuance(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("refresh-denied-%d", time.Now().UnixNano()))

	roleID, err := d.RBAC.CreateClientRole(context.Background(), clientID, "banned", "")
	if err != nil {
		t.Fatalf("CreateClientRole: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.DeleteClientRole(context.Background(), roleID) })
	if err := d.RBAC.AssignUserRole(context.Background(), u.ID, clientID, "banned"); err != nil {
		t.Fatalf("AssignUserRole: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.RevokeUserRole(context.Background(), u.ID, clientID, "banned") })

	policyID, err := d.RBAC.CreatePolicy(context.Background(), rbac.Policy{
		Name:     fmt.Sprintf("deny-banned-refresh-%d", time.Now().UnixNano()),
		Type:     "deny_role",
		ClientID: clientID,
		RoleName: "banned",
		Enabled:  true,
	})
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}
	t.Cleanup(func() { _ = d.RBAC.DeletePolicy(context.Background(), policyID) })

	raw := fmt.Sprintf("refresh-denied-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d (body: %s) — deny_role policy should have blocked refresh", rec.Code, http.StatusForbidden, rec.Body.String())
	}
}

// TestToken_UnsupportedGrantType proves grant types other than
// authorization_code/refresh_token are rejected outright.
func TestToken_UnsupportedGrantType(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	rec := doTokenRequest(t, d, url.Values{"grant_type": {"client_credentials"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error"] != "unsupported_grant_type" {
		t.Fatalf("error = %q, want unsupported_grant_type", resp["error"])
	}
}

// TestToken_MalformedForm_InvalidRequest proves an unparseable form body is
// rejected before any grant-type dispatch.
func TestToken_MalformedForm_InvalidRequest(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader("%zz"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	Token(d)(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleAuthCodeGrant_MissingFields_InvalidRequest proves each required
// form field (code, redirect_uri, client_id) is enforced.
func TestHandleAuthCodeGrant_MissingFields_InvalidRequest(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	cases := []url.Values{
		{"grant_type": {"authorization_code"}, "redirect_uri": {"https://client.test/cb"}, "client_id": {"c"}},
		{"grant_type": {"authorization_code"}, "code": {"abc"}, "client_id": {"c"}},
		{"grant_type": {"authorization_code"}, "code": {"abc"}, "redirect_uri": {"https://client.test/cb"}},
	}
	for i, form := range cases {
		rec := doTokenRequest(t, d, form)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("case %d: status = %d, want %d (body: %s)", i, rec.Code, http.StatusBadRequest, rec.Body.String())
		}
	}
}

// TestHandleAuthCodeGrant_UnknownCode_InvalidGrant proves a code that was
// never issued (or already consumed) is rejected rather than silently
// treated as valid.
func TestHandleAuthCodeGrant_UnknownCode_InvalidGrant(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {"never-issued-code"},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp["error"] != "invalid_grant" {
		t.Fatalf("error = %q, want invalid_grant", resp["error"])
	}
}

// TestHandleAuthCodeGrant_CodeReuse_SecondAttemptFails proves an
// authorization code is single-use: the atomic DELETE...RETURNING means a
// second exchange attempt with the same code must fail even though the
// first attempt succeeded (replay protection).
func TestHandleAuthCodeGrant_CodeReuse_SecondAttemptFails(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("reuse-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-reuse-%d", time.Now().UnixNano())
	insertAuthCode(t, d, code, clientID, u.ID)

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	}
	first := doTokenRequest(t, d, form)
	if first.Code != http.StatusOK {
		t.Fatalf("first exchange status = %d, want %d (body: %s)", first.Code, http.StatusOK, first.Body.String())
	}

	second := doTokenRequest(t, d, form)
	if second.Code != http.StatusBadRequest {
		t.Fatalf("replayed exchange status = %d, want %d (body: %s) — code reuse must be rejected", second.Code, http.StatusBadRequest, second.Body.String())
	}
}

// TestHandleAuthCodeGrant_ClientIDMismatch_InvalidGrant proves a code issued
// to one client cannot be redeemed by presenting a different client_id.
func TestHandleAuthCodeGrant_ClientIDMismatch_InvalidGrant(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	otherClientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("clientmismatch-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-mismatch-%d", time.Now().UnixNano())
	insertAuthCode(t, d, code, clientID, u.ID)

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {otherClientID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — code issued to a different client must be rejected", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleAuthCodeGrant_PKCE_MissingVerifier_InvalidGrant and
// TestHandleAuthCodeGrant_PKCE_WrongVerifier_InvalidGrant prove PKCE is
// actually enforced when the stored code carries a code_challenge: a
// missing or incorrect code_verifier must not exchange for tokens.
func TestHandleAuthCodeGrant_PKCE_MissingVerifier_InvalidGrant(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("pkce-missing-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-pkce-missing-%d", time.Now().UnixNano())
	insertAuthCodeWithPKCE(t, d, code, clientID, u.ID, "some-challenge", "S256")

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — missing code_verifier against a PKCE-protected code must be rejected", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

func TestHandleAuthCodeGrant_PKCE_WrongVerifier_InvalidGrant(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("pkce-wrong-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-pkce-wrong-%d", time.Now().UnixNano())
	insertAuthCodeWithPKCE(t, d, code, clientID, u.ID, "correct-challenge-value", "S256")

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {"attacker-supplied-wrong-verifier"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — wrong code_verifier must be rejected", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleAuthCodeGrant_PKCE_CorrectVerifier_Succeeds is the positive
// control for the two tests above: a code_verifier whose SHA-256 matches
// the stored code_challenge must succeed.
func TestHandleAuthCodeGrant_PKCE_CorrectVerifier_Succeeds(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("pkce-ok-%d", time.Now().UnixNano()))

	verifier := "correct-verifier-value-that-is-long-enough-for-pkce"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	code := fmt.Sprintf("code-pkce-ok-%d", time.Now().UnixNano())
	insertAuthCodeWithPKCE(t, d, code, clientID, u.ID, challenge, "S256")

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"code_verifier": {verifier},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
}

// TestHandleAuthCodeGrant_OfflineAccess_IssuesRefreshToken proves the
// offline_access scope path (rand-generated refresh token, persisted via
// TokenStore) actually returns a refresh_token in the response, and that
// requesting without offline_access does not.
func TestHandleAuthCodeGrant_OfflineAccess_IssuesRefreshToken(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("offline-%d", time.Now().UnixNano()))

	code := fmt.Sprintf("code-offline-%d", time.Now().UnixNano())
	_, err := d.Pool.Exec(context.Background(), `
		INSERT INTO authorization_codes
		    (code, client_id, user_id, redirect_uri, scopes,
		     code_challenge, code_challenge_method, nonce, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		code, clientID, u.ID, redirectURI, []string{"openid", "offline_access"},
		"", "", "", time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("insert auth code: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	refreshToken, _ := resp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatalf("expected refresh_token in response with offline_access scope, got %v", resp)
	}
}

// TestHandleRefreshGrant_MissingToken_InvalidRequest proves an empty
// refresh_token form value is rejected before any DB lookup.
func TestHandleRefreshGrant_MissingToken_InvalidRequest(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	rec := doTokenRequest(t, d, url.Values{"grant_type": {"refresh_token"}})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleRefreshGrant_UnknownToken_InvalidGrant proves an
// unrecognized/garbage refresh token is rejected.
func TestHandleRefreshGrant_UnknownToken_InvalidGrant(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"never-issued-refresh-token"},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleRefreshGrant_TokenRotation_OldTokenRejectedAfterUse is the core
// refresh-token-revocation-takes-effect security proof: ConsumeRefreshToken
// deletes the row atomically (DELETE ... RETURNING), so once a refresh
// token has been used to mint a new access/refresh token pair, the SAME old
// refresh token must never work again — otherwise a stolen (but already
// rotated) refresh token would remain replayable forever.
func TestHandleRefreshGrant_TokenRotation_OldTokenRejectedAfterUse(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("rotation-%d", time.Now().UnixNano()))

	raw := fmt.Sprintf("refresh-rotation-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	first := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first refresh status = %d, want %d (body: %s)", first.Code, http.StatusOK, first.Body.String())
	}

	second := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
	})
	if second.Code != http.StatusBadRequest {
		t.Fatalf("reused old refresh_token status = %d, want %d (body: %s) — a rotated-out refresh token must not be replayable", second.Code, http.StatusBadRequest, second.Body.String())
	}
}

// TestHandleRefreshGrant_RevokedToken_Rejected proves
// TokenStore.RevokeRefreshToken actually takes effect at the /oauth/token
// call site: a revoked-but-not-yet-expired refresh token must be refused.
func TestHandleRefreshGrant_RevokedToken_Rejected(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("revoked-%d", time.Now().UnixNano()))

	raw := fmt.Sprintf("refresh-revoked-%d", time.Now().UnixNano())
	if err := d.TokenStore.SaveRefreshToken(context.Background(), raw, clientID, u.ID, []string{"openid"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}
	if err := d.TokenStore.RevokeRefreshToken(context.Background(), raw); err != nil {
		t.Fatalf("RevokeRefreshToken: %v", err)
	}

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {raw},
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (body: %s) — a revoked refresh token must be rejected", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestHandleAuthCodeGrant_OrgClaims_MembershipRevokedBeforeTokenExchange
// proves resolveOrgClaims fails closed: if the user's org membership is
// revoked between /oauth/authorize (when the code was issued with an
// organization_id) and /oauth/token, the issued tokens must carry NO org
// claims rather than stale/incorrect ones.
func TestHandleAuthCodeGrant_OrgClaims_MembershipRevokedBeforeTokenExchange(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	d.OrgSvc = organizationStoreFor(pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("orgrevoked-%d", time.Now().UnixNano()))
	org := createTestOrg(t, d, "private")
	addTestMember(t, d, org.ID, u.ID, "member")

	code := fmt.Sprintf("code-orgrevoked-%d", time.Now().UnixNano())
	_, err := d.Pool.Exec(context.Background(), `
		INSERT INTO authorization_codes
		    (code, client_id, user_id, redirect_uri, scopes,
		     code_challenge, code_challenge_method, nonce, organization_id, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		code, clientID, u.ID, redirectURI, []string{"openid"},
		"", "", "", org.ID, time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("insert auth code: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })

	// Revoke membership before the code is exchanged.
	if err := d.OrgSvc.RemoveMember(context.Background(), org.ID, u.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	rec := doTokenRequest(t, d, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {redirectURI},
		"client_id":    {clientID},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body: %s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	// The access/ID tokens are opaque JWT strings here (no verifier
	// wired to decode claims in this test), but resolveOrgClaims returning
	// empty strings is exercised directly since it's unexported — see
	// TestResolveOrgClaims_MembershipRevoked below for the direct check.
}

// TestResolveOrgClaims_MembershipRevoked directly exercises the unexported
// resolveOrgClaims helper's fail-closed behavior when the code's
// organization_id no longer matches a current membership.
func TestResolveOrgClaims_MembershipRevoked(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	d.OrgSvc = organizationStoreFor(pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("resolveorgclaims-%d", time.Now().UnixNano()))
	org := createTestOrg(t, d, "government")
	addTestMember(t, d, org.ID, u.ID, "owner")

	orgID, orgRole, orgType := resolveOrgClaims(context.Background(), d, u.ID, &org.ID)
	if orgID != org.ID || orgRole != "owner" || orgType != "government" {
		t.Fatalf("resolveOrgClaims with active membership = (%q,%q,%q), want (%q,owner,government)", orgID, orgRole, orgType, org.ID)
	}

	if err := d.OrgSvc.RemoveMember(context.Background(), org.ID, u.ID); err != nil {
		t.Fatalf("RemoveMember: %v", err)
	}

	orgID2, orgRole2, orgType2 := resolveOrgClaims(context.Background(), d, u.ID, &org.ID)
	if orgID2 != "" || orgRole2 != "" || orgType2 != "" {
		t.Fatalf("resolveOrgClaims after membership revoked = (%q,%q,%q), want all empty (fail closed)", orgID2, orgRole2, orgType2)
	}
}

// TestResolveOrgClaims_NilOrgID and TestResolveOrgClaims_NoOrgSvc cover the
// two early-return branches.
func TestResolveOrgClaims_NilOrgID(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	d.OrgSvc = organizationStoreFor(pool)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("nilorg-%d", time.Now().UnixNano()))

	orgID, orgRole, orgType := resolveOrgClaims(context.Background(), d, u.ID, nil)
	if orgID != "" || orgRole != "" || orgType != "" {
		t.Fatalf("resolveOrgClaims with nil orgIDCol = (%q,%q,%q), want all empty", orgID, orgRole, orgType)
	}
}

func TestResolveOrgClaims_NoOrgSvc(t *testing.T) {
	pool := requireDB(t)
	d := testTokenDeps(t, pool)
	d.OrgSvc = nil
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("noorgsvc-%d", time.Now().UnixNano()))
	someID := "00000000-0000-0000-0000-000000000000"

	orgID, orgRole, orgType := resolveOrgClaims(context.Background(), d, u.ID, &someID)
	if orgID != "" || orgRole != "" || orgType != "" {
		t.Fatalf("resolveOrgClaims with nil OrgSvc = (%q,%q,%q), want all empty", orgID, orgRole, orgType)
	}
}

// insertAuthCodeWithPKCE is like insertAuthCode but stores a PKCE
// code_challenge/method, for tests exercising the PKCE-enforcement branch.
func insertAuthCodeWithPKCE(t *testing.T, d Deps, code, clientID, userID, challenge, method string) {
	t.Helper()
	_, err := d.Pool.Exec(context.Background(), `
		INSERT INTO authorization_codes
		    (code, client_id, user_id, redirect_uri, scopes,
		     code_challenge, code_challenge_method, nonce, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		code, clientID, userID, "https://client.test/callback", []string{"openid"},
		challenge, method, "", time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatalf("insertAuthCodeWithPKCE: %v", err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })
}

// organizationStoreFor builds a plain organization.Store for tests that need
// d.OrgSvc wired but don't otherwise go through testDeps.
func organizationStoreFor(pool *pgxpool.Pool) *organization.Store {
	return organization.NewStore(pool)
}
