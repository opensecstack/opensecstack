package federation

import (
	"context"
	"strings"
	"testing"
)

// TestAuthenticateLDAP_InvalidURLFailsToDial proves a malformed LDAP URL is
// rejected with a wrapped dial error rather than panicking or hanging.
func TestAuthenticateLDAP_InvalidURLFailsToDial(t *testing.T) {
	p := &Provider{LDAPUrl: "not-a-valid-ldap-url"}

	_, err := AuthenticateLDAP(context.Background(), p, "user", "pass")
	if err == nil {
		t.Fatal("AuthenticateLDAP: expected error for invalid LDAP URL, got nil")
	}
	if !strings.Contains(err.Error(), "ldap dial") {
		t.Errorf("AuthenticateLDAP error = %q, want it to mention the dial failure", err.Error())
	}
}

// TestAuthenticateLDAP_UnreachableServerFailsToDial proves an unreachable
// (but well-formed) LDAP server also surfaces as a dial error, not a hang
// or panic further down the auth path.
func TestAuthenticateLDAP_UnreachableServerFailsToDial(t *testing.T) {
	p := &Provider{LDAPUrl: "ldap://127.0.0.1:1"} // nothing listens on port 1

	_, err := AuthenticateLDAP(context.Background(), p, "user", "pass")
	if err == nil {
		t.Fatal("AuthenticateLDAP: expected error for unreachable LDAP server, got nil")
	}
}
