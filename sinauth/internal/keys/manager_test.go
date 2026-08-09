package keys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerate_GeneratesAndPersistsNewKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	m := New("kid-1")
	if err := m.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}
	if m.PrivateKey() == nil {
		t.Fatal("PrivateKey() = nil after generating a new key")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected key file to be persisted at %s: %v", path, err)
	}
}

func TestLoadOrGenerate_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	m1 := New("kid-1")
	if err := m1.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate (generate): %v", err)
	}
	firstKey := m1.PrivateKey()

	m2 := New("kid-1")
	if err := m2.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate (load): %v", err)
	}
	secondKey := m2.PrivateKey()

	if !firstKey.Equal(secondKey) {
		t.Error("expected the second Manager to load the same key material persisted by the first, got a different key")
	}
}

func TestLoadOrGenerate_RejectsMalformedPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	if err := os.WriteFile(path, []byte("not a pem file at all"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := New("kid-1")
	err := m.LoadOrGenerate(path)
	if err == nil {
		t.Fatal("LoadOrGenerate: expected error for malformed PEM content, got nil")
	}
}

func TestLoadOrGenerate_RejectsUnsupportedPEMType(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")
	// A syntactically valid PEM block, but not a private key type this code
	// path understands.
	pemBlock := "-----BEGIN CERTIFICATE-----\nMA==\n-----END CERTIFICATE-----\n"
	if err := os.WriteFile(path, []byte(pemBlock), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := New("kid-1")
	err := m.LoadOrGenerate(path)
	if err == nil {
		t.Fatal("LoadOrGenerate: expected error for unsupported PEM block type, got nil")
	}
}

func TestManager_PublicKeyMatchesPrivateKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	m := New("kid-1")
	if err := m.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	if !m.PublicKey().Equal(&m.PrivateKey().PublicKey) {
		t.Error("PublicKey() does not match PrivateKey().PublicKey")
	}
}

func TestManager_KeyID(t *testing.T) {
	m := New("my-key-id")
	if got := m.KeyID(); got != "my-key-id" {
		t.Errorf("KeyID() = %q, want my-key-id", got)
	}
}
