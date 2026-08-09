package keygen

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRun_WritesKeyFileAndPrintsPublicKey(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer

	if err := Run([]string{"-out", dir, "-label", "mykey"}, &out); err != nil {
		t.Fatalf("Run: %v", err)
	}

	keyPath := filepath.Join(dir, "mykey.key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}

	priv, err := hex.DecodeString(string(data))
	if err != nil {
		t.Fatalf("decoding hex private key: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key size = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	// The printed public key must match the public half of the written private key.
	pub := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	wantPubHex := hex.EncodeToString(pub)
	if !strings.Contains(out.String(), wantPubHex) {
		t.Errorf("stdout does not contain expected public key %q; got: %s", wantPubHex, out.String())
	}
	if !strings.Contains(out.String(), keyPath) {
		t.Errorf("stdout does not mention key path %q; got: %s", keyPath, out.String())
	}
	if !strings.Contains(out.String(), `"key_id": "mykey"`) {
		t.Errorf("stdout does not mention key_id %q; got: %s", "mykey", out.String())
	}
}

func TestRun_DefaultsOutAndLabel(t *testing.T) {
	dir := t.TempDir()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(wd) }()

	var out bytes.Buffer
	if err := Run(nil, &out); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "citadel.key")); err != nil {
		t.Errorf("expected default key file citadel.key to exist: %v", err)
	}
}

func TestRun_RefusesToOverwriteExistingKey(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer

	if err := Run([]string{"-out", dir, "-label", "dup"}, &out); err != nil {
		t.Fatalf("first Run: %v", err)
	}

	// Capture the original private key contents so we can confirm they were
	// not clobbered by the second (refused) Run.
	keyPath := filepath.Join(dir, "dup.key")
	original, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file: %v", err)
	}

	out.Reset()
	err = Run([]string{"-out", dir, "-label", "dup"}, &out)
	if err == nil {
		t.Fatal("expected second Run with the same label to fail (refuse to overwrite)")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("expected 'already exists' error, got: %v", err)
	}

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key file after failed overwrite: %v", err)
	}
	if !bytes.Equal(original, after) {
		t.Error("private key file contents changed after a refused overwrite attempt")
	}
}

func TestRun_InvalidFlag(t *testing.T) {
	var out bytes.Buffer
	if err := Run([]string{"-bogus-flag"}, &out); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}
