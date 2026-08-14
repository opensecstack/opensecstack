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

// TestAuthenticateLDAP_EmptyPasswordRejectedBeforeDial is a regression test
// for a real LDAP authentication-bypass class of bug: RFC 4513 §5.1.2 defines
// a simple bind with a non-empty DN and an *empty* password as an
// "unauthenticated bind", which many directory servers accept as success
// without checking any credential. If AuthenticateLDAP ever forwarded an
// empty password straight to conn.Bind, an attacker could authenticate as
// any username that resolves to a directory entry with no password at all.
//
// The LDAP URL here points at nothing (port 1, guaranteed closed), so if the
// empty-password guard were removed this test would instead fail with a
// dial/connection error rather than the expected "empty password" error —
// making the regression obvious.
func TestAuthenticateLDAP_EmptyPasswordRejectedBeforeDial(t *testing.T) {
	p := &Provider{LDAPUrl: "ldap://127.0.0.1:1"}

	_, err := AuthenticateLDAP(context.Background(), p, "victim", "")
	if err == nil {
		t.Fatal("AuthenticateLDAP: expected error for empty password, got nil (authentication bypass risk)")
	}
	if !strings.Contains(err.Error(), "empty password") {
		t.Errorf("AuthenticateLDAP error = %q, want it to mention the empty-password rejection (proves guard fired before any network dial)", err.Error())
	}
}
