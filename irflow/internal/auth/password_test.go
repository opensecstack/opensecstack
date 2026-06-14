package auth

import (
	"strings"
	"testing"
)

const testPepperFull = "irflow-test-pepper-plenty-of-entropy-32b"

func TestNewHasher_ReturnsUsableHasher(t *testing.T) {
	h, err := NewHasher(Config{Pepper: testPepperFull})
	if err != nil {
		t.Fatalf("NewHasher: %v", err)
	}
	encoded, err := h.Hash("api-key-example")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Errorf("encoded = %q, want canonical PHC format", encoded)
	}
	ok, err := h.Verify("api-key-example", encoded)
	if err != nil || !ok {
		t.Errorf("Verify = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestNewHasher_RejectsMissingPepper(t *testing.T) {
	_, err := NewHasher(Config{})
	if err == nil {
		t.Fatal("expected error when Pepper is empty")
	}
	if !strings.Contains(err.Error(), "pepper") {
		t.Errorf("err = %v, want mention of pepper", err)
	}
}

func TestNewHasher_RejectsShortPepper(t *testing.T) {
	_, err := NewHasher(Config{Pepper: "only-9-bs"})
	if err == nil {
		t.Fatal("expected error when Pepper is too short")
	}
}
