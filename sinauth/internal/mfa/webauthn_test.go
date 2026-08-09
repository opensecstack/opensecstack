package mfa

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// TestWAUser_ImplementsWebAuthnUserInterface locks in that WAUser correctly
// surfaces its fields through the webauthn.User interface methods, which is
// what the go-webauthn library relies on during registration/assertion.
func TestWAUser_ImplementsWebAuthnUserInterface(t *testing.T) {
	creds := []webauthn.Credential{{ID: []byte("cred-1")}}
	u := &WAUser{
		ID:          []byte("user-id-bytes"),
		Name:        "alice",
		DisplayName: "Alice A.",
		Credentials: creds,
	}

	if string(u.WebAuthnID()) != "user-id-bytes" {
		t.Errorf("WebAuthnID() = %q, want user-id-bytes", u.WebAuthnID())
	}
	if u.WebAuthnName() != "alice" {
		t.Errorf("WebAuthnName() = %q, want alice", u.WebAuthnName())
	}
	if u.WebAuthnDisplayName() != "Alice A." {
		t.Errorf("WebAuthnDisplayName() = %q, want Alice A.", u.WebAuthnDisplayName())
	}
	if u.WebAuthnIcon() != "" {
		t.Errorf("WebAuthnIcon() = %q, want empty string", u.WebAuthnIcon())
	}
	got := u.WebAuthnCredentials()
	if len(got) != 1 || string(got[0].ID) != "cred-1" {
		t.Errorf("WebAuthnCredentials() = %v, want the single cred-1 credential", got)
	}
}
