//go:build integration

package handlers

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// TestIssueAuthCode_InsertsRetrievableRow proves issueAuthCode both returns
// a code and actually persists it with the exact fields callers (AuthorizePOST)
// rely on, including a nil organization_id for the pure-individual flow.
func TestIssueAuthCode_InsertsRetrievableRow(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("authcode-%d", time.Now().UnixNano()))

	scopes := []string{"openid", "profile"}
	code, err := issueAuthCode(context.Background(), d, clientID, u.ID, redirectURI, scopes,
		"challenge-abc", "S256", "nonce-xyz", nil)
	if err != nil {
		t.Fatalf("issueAuthCode: %v", err)
	}
	if code == "" {
		t.Fatal("issueAuthCode returned empty code")
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })

	var (
		gotClientID, gotUserID, gotRedirect, gotChallenge, gotMethod, gotNonce string
		gotScopes                                                              []string
		gotOrgID                                                               *string
		used                                                                   bool
	)
	err = pool.QueryRow(context.Background(),
		`SELECT client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, organization_id, used
		 FROM authorization_codes WHERE code=$1`, code,
	).Scan(&gotClientID, &gotUserID, &gotRedirect, &gotScopes, &gotChallenge, &gotMethod, &gotNonce, &gotOrgID, &used)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}

	if gotClientID != clientID {
		t.Errorf("client_id = %q, want %q", gotClientID, clientID)
	}
	if gotUserID != u.ID {
		t.Errorf("user_id = %q, want %q", gotUserID, u.ID)
	}
	if gotRedirect != redirectURI {
		t.Errorf("redirect_uri = %q, want %q", gotRedirect, redirectURI)
	}
	if len(gotScopes) != 2 || gotScopes[0] != "openid" || gotScopes[1] != "profile" {
		t.Errorf("scopes = %v, want [openid profile]", gotScopes)
	}
	if gotChallenge != "challenge-abc" {
		t.Errorf("code_challenge = %q, want challenge-abc", gotChallenge)
	}
	if gotMethod != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", gotMethod)
	}
	if gotNonce != "nonce-xyz" {
		t.Errorf("nonce = %q, want nonce-xyz", gotNonce)
	}
	if gotOrgID != nil {
		t.Errorf("organization_id = %v, want nil for pure-individual flow", *gotOrgID)
	}
	if used {
		t.Error("newly issued code must not start as used")
	}
}

// TestIssueAuthCode_UniqueAcrossCalls proves two codes issued back-to-back
// for the same client/user do not collide — a collision would let one
// authorization silently overwrite (and hijack) another in-flight one.
func TestIssueAuthCode_UniqueAcrossCalls(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("authcode-uniq-%d", time.Now().UnixNano()))

	code1, err := issueAuthCode(context.Background(), d, clientID, u.ID, redirectURI, []string{"openid"}, "", "", "", nil)
	if err != nil {
		t.Fatalf("issueAuthCode (1): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code1) })

	code2, err := issueAuthCode(context.Background(), d, clientID, u.ID, redirectURI, []string{"openid"}, "", "", "", nil)
	if err != nil {
		t.Fatalf("issueAuthCode (2): %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code2) })

	if code1 == code2 {
		t.Fatalf("issueAuthCode returned the same code twice: %q", code1)
	}
}

// TestIssueAuthCode_WithOrganizationID_Persists proves the ADR 005 v1.1
// organization-scoped path stores the organization_id, not just the
// individual-flow (nil) path.
func TestIssueAuthCode_WithOrganizationID_Persists(t *testing.T) {
	pool := requireDB(t)
	d := testDeps(t, pool)
	redirectURI := "https://client.test/callback"
	clientID := createTestOAuthClient(t, d, redirectURI)
	u := createTestAuthorizeUser(t, d, fmt.Sprintf("authcode-org-%d", time.Now().UnixNano()))
	org := createTestOrg(t, d, "private")
	addTestMember(t, d, org.ID, u.ID, "member")

	orgID := org.ID
	code, err := issueAuthCode(context.Background(), d, clientID, u.ID, redirectURI, []string{"openid"}, "", "", "", &orgID)
	if err != nil {
		t.Fatalf("issueAuthCode: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM authorization_codes WHERE code=$1`, code) })

	var gotOrgID string
	err = pool.QueryRow(context.Background(),
		`SELECT organization_id::text FROM authorization_codes WHERE code=$1`, code,
	).Scan(&gotOrgID)
	if err != nil {
		t.Fatalf("query inserted row: %v", err)
	}
	if gotOrgID != org.ID {
		t.Errorf("organization_id = %q, want %q", gotOrgID, org.ID)
	}
}
