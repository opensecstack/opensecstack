package token

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// testIssuer builds an Issuer backed by a throwaway RSA key, purely for
// exercising claim shape — no verification round-trip is needed for these
// tests.
func testIssuer(t *testing.T) *Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return NewIssuer(key, "test-kid", "https://sinauth.test")
}

// rawClaims decodes a JWT's payload segment into a generic map, without
// verifying the signature, so we can assert on which keys are present —
// this is what distinguishes "empty string" from "key absent entirely".
func rawClaims(t *testing.T, jwtToken string) map[string]any {
	t.Helper()
	parts := strings.Split(jwtToken, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed JWT: expected 3 segments, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	return claims
}

func TestIssueIDToken_OrgClaimsOmittedWhenEmpty(t *testing.T) {
	i := testIssuer(t)
	tok, err := i.IssueIDToken("alice", "client-1", "nonce-1", "alice@example.com", "Alice", "", true, "", "", "", time.Hour)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims := rawClaims(t, tok)
	for _, key := range []string{"org_id", "org_role", "org_type"} {
		if _, present := claims[key]; present {
			t.Errorf("expected %q to be absent from ID token claims when unset, got %v", key, claims[key])
		}
	}
}

func TestIssueIDToken_OrgClaimsPresentWhenSet(t *testing.T) {
	i := testIssuer(t)
	tok, err := i.IssueIDToken("alice", "client-1", "nonce-1", "alice@example.com", "Alice", "",
		true, "org-123", "admin", "government", time.Hour)
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	claims := rawClaims(t, tok)
	if claims["org_id"] != "org-123" {
		t.Errorf("org_id = %v, want org-123", claims["org_id"])
	}
	if claims["org_role"] != "admin" {
		t.Errorf("org_role = %v, want admin", claims["org_role"])
	}
	if claims["org_type"] != "government" {
		t.Errorf("org_type = %v, want government", claims["org_type"])
	}
}

func TestIssueAccessTokenWithRoles_OrgClaimsOmittedWhenEmpty(t *testing.T) {
	i := testIssuer(t)
	tok, err := i.IssueAccessTokenWithRoles("alice", "client-1", []string{"openid"}, []string{"member"}, "", "", "", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessTokenWithRoles: %v", err)
	}
	claims := rawClaims(t, tok)
	for _, key := range []string{"org_id", "org_role", "org_type"} {
		if _, present := claims[key]; present {
			t.Errorf("expected %q to be absent from access token claims when unset, got %v", key, claims[key])
		}
	}
}

func TestIssueAccessTokenWithRoles_OrgClaimsPresentWhenSet(t *testing.T) {
	i := testIssuer(t)
	tok, err := i.IssueAccessTokenWithRoles("alice", "client-1", []string{"openid"}, []string{"member"},
		"org-123", "owner", "private", time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessTokenWithRoles: %v", err)
	}
	claims := rawClaims(t, tok)
	if claims["org_id"] != "org-123" {
		t.Errorf("org_id = %v, want org-123", claims["org_id"])
	}
	if claims["org_role"] != "owner" {
		t.Errorf("org_role = %v, want owner", claims["org_role"])
	}
	if claims["org_type"] != "private" {
		t.Errorf("org_type = %v, want private", claims["org_type"])
	}
}
