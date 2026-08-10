package handlers

// White-box tests for generateAPIKey — it has no exported surface (only
// CreateAPIKey, which requires a live DB, calls it), so it is tested here
// directly in package handlers. Security-relevant: this is the ID-generation
// path for long-lived API credentials.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateAPIKey_RawHasExpectedPrefix(t *testing.T) {
	raw, _, _, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(raw, "sin_") {
		t.Errorf("expected raw key to start with 'sin_', got %q", raw)
	}
}

func TestGenerateAPIKey_PrefixIsFirst12CharsOfRaw(t *testing.T) {
	raw, prefix, _, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(prefix) != 12 {
		t.Fatalf("expected prefix to be 12 chars, got %d: %q", len(prefix), prefix)
	}
	if raw[:12] != prefix {
		t.Errorf("expected prefix %q to equal raw[:12] %q", prefix, raw[:12])
	}
}

func TestGenerateAPIKey_HashMatchesSHA256OfRaw(t *testing.T) {
	raw, _, hash, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	sum := sha256.Sum256([]byte(raw))
	want := hex.EncodeToString(sum[:])
	if hash != want {
		t.Errorf("hash does not match sha256(raw): got %q, want %q", hash, want)
	}
}

func TestGenerateAPIKey_HashDoesNotLeakRawKey(t *testing.T) {
	raw, _, hash, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// The stored hash must never simply contain the raw secret as a
	// substring (e.g. a no-op "hash" that just encodes the raw bytes).
	if strings.Contains(hash, raw) {
		t.Error("hash must not contain the raw key material")
	}
}

func TestGenerateAPIKey_SuccessiveCallsProduceDistinctKeys(t *testing.T) {
	raw1, prefix1, hash1, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	raw2, prefix2, hash2, err := generateAPIKey()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if raw1 == raw2 {
		t.Error("expected two successive generateAPIKey calls to produce different raw keys (random source broken?)")
	}
	if prefix1 == prefix2 {
		t.Error("expected two successive generateAPIKey calls to produce different prefixes")
	}
	if hash1 == hash2 {
		t.Error("expected two successive generateAPIKey calls to produce different hashes")
	}
}
