//go:build integration

package mfa

import (
	"context"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestLoadWAUser_NoCredentials(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-load-nocreds")

	u, err := LoadWAUser(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("LoadWAUser: %v", err)
	}
	if u.Name != "wa-load-nocreds" {
		t.Errorf("Name = %q, want wa-load-nocreds", u.Name)
	}
	if len(u.Credentials) != 0 {
		t.Errorf("expected zero credentials, got %d", len(u.Credentials))
	}
}

func TestLoadWAUser_UnknownUser(t *testing.T) {
	pool := requireDB(t)
	_, err := LoadWAUser(context.Background(), pool, "00000000-0000-0000-0000-000000000000")
	if err == nil {
		t.Fatal("LoadWAUser: expected error for unknown user id, got nil")
	}
}

func TestSaveCredentialAndLoadWAUser_RoundTrips(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-save-roundtrip")

	cred := &webauthn.Credential{
		ID:        []byte("cred-id-1"),
		PublicKey: []byte("pubkey-bytes"),
		Transport: []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Flags: webauthn.CredentialFlags{
			BackupEligible: true,
			BackupState:    false,
		},
		// A real authenticator always reports a 16-byte AAGUID (all-zero is
		// valid and common for platform authenticators), which is what
		// SaveCredential's INSERT expects for the NOT NULL aaguid column.
		Authenticator: webauthn.Authenticator{AAGUID: make([]byte, 16)},
	}
	if err := SaveCredential(context.Background(), pool, userID, "my-key", cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webauthn_credentials WHERE credential_id=$1`, cred.ID)
	})

	u, err := LoadWAUser(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("LoadWAUser: %v", err)
	}
	if len(u.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(u.Credentials))
	}
	got := u.Credentials[0]
	if string(got.ID) != "cred-id-1" {
		t.Errorf("credential ID = %q, want cred-id-1", got.ID)
	}
	if string(got.PublicKey) != "pubkey-bytes" {
		t.Errorf("PublicKey = %q, want pubkey-bytes", got.PublicKey)
	}
	if !got.Flags.BackupEligible {
		t.Error("expected BackupEligible to round-trip as true")
	}
	if len(got.Transport) != 2 {
		t.Errorf("expected 2 transports to round-trip, got %d", len(got.Transport))
	}
}

// TestUpdateCredential_PersistsSignCount proves the sign counter used for
// WebAuthn clone-detection is actually persisted after a successful
// assertion — a WebAuthn authenticator's sign_count must strictly increase
// on each use, and the relying party is expected to reject any assertion
// where the reported count doesn't increase (a sign of a cloned
// authenticator). If UpdateCredential silently no-op'd, that protection
// would be defeated because the stored count would never move.
func TestUpdateCredential_PersistsSignCount(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-update-signcount")

	cred := &webauthn.Credential{
		ID:            []byte("cred-signcount-1"),
		PublicKey:     []byte("pubkey-bytes"),
		Authenticator: webauthn.Authenticator{SignCount: 1, AAGUID: make([]byte, 16)},
	}
	if err := SaveCredential(context.Background(), pool, userID, "counter-key", cred); err != nil {
		t.Fatalf("SaveCredential: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webauthn_credentials WHERE credential_id=$1`, cred.ID)
	})

	cred.Authenticator.SignCount = 42
	UpdateCredential(context.Background(), pool, cred)

	u, err := LoadWAUser(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("LoadWAUser: %v", err)
	}
	if len(u.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(u.Credentials))
	}
	if u.Credentials[0].Authenticator.SignCount != 42 {
		t.Errorf("SignCount after UpdateCredential = %d, want 42", u.Credentials[0].Authenticator.SignCount)
	}
}

func TestStoreAndLoadAndDeleteWASession(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-session-roundtrip")

	sd := &webauthn.SessionData{
		Challenge: "challenge-abc",
		UserID:    []byte(userID),
	}
	if err := StoreWASession(context.Background(), pool, userID, sd); err != nil {
		t.Fatalf("StoreWASession: %v", err)
	}

	got, err := LoadAndDeleteWASession(context.Background(), pool, userID)
	if err != nil {
		t.Fatalf("LoadAndDeleteWASession: %v", err)
	}
	if got.Challenge != "challenge-abc" {
		t.Errorf("Challenge = %q, want challenge-abc", got.Challenge)
	}
}

// TestLoadAndDeleteWASession_IsOneTimeUse is a replay-protection test: a
// WebAuthn session/challenge must not be consumable twice. Challenges exist
// specifically to prevent replay of a captured assertion; if the same
// challenge could be loaded (and thus matched against) more than once, an
// attacker who intercepted one ceremony's response could potentially reuse
// session state for a second attempt.
func TestLoadAndDeleteWASession_IsOneTimeUse(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-session-onetime")

	sd := &webauthn.SessionData{Challenge: "challenge-onetime"}
	if err := StoreWASession(context.Background(), pool, userID, sd); err != nil {
		t.Fatalf("StoreWASession: %v", err)
	}

	if _, err := LoadAndDeleteWASession(context.Background(), pool, userID); err != nil {
		t.Fatalf("LoadAndDeleteWASession (1st): %v", err)
	}
	if _, err := LoadAndDeleteWASession(context.Background(), pool, userID); err == nil {
		t.Fatal("LoadAndDeleteWASession (2nd): expected error — session must be single-use")
	}
}

func TestLoadAndDeleteWASession_NoActiveSession(t *testing.T) {
	pool := requireDB(t)
	userID := createTestUser(t, pool, "wa-session-none")

	if _, err := LoadAndDeleteWASession(context.Background(), pool, userID); err == nil {
		t.Fatal("LoadAndDeleteWASession: expected error when no session exists, got nil")
	}
}
