//go:build integration

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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
