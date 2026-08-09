package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
)

func challengeFor(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestVerifyS256_MatchingPair(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := challengeFor(verifier)

	if err := VerifyS256(verifier, challenge); err != nil {
		t.Fatalf("VerifyS256: unexpected error for matching pair: %v", err)
	}
}

func TestVerifyS256_MismatchedVerifier(t *testing.T) {
	challenge := challengeFor("correct-verifier")

	err := VerifyS256("wrong-verifier", challenge)
	if err == nil {
		t.Fatal("VerifyS256: expected error for mismatched verifier, got nil")
	}
	if !errors.Is(err, ErrPKCEMismatch) {
		t.Errorf("VerifyS256: err = %v, want ErrPKCEMismatch", err)
	}
}

func TestVerifyS256_EmptyChallenge(t *testing.T) {
	err := VerifyS256("some-verifier", "")
	if !errors.Is(err, ErrPKCEMismatch) {
		t.Errorf("VerifyS256: err = %v, want ErrPKCEMismatch", err)
	}
}

func TestVerifyS256_EmptyVerifier(t *testing.T) {
	challenge := challengeFor("")
	// An empty verifier still has a well-defined SHA-256 hash; if the stored
	// challenge matches that hash, verification must succeed (empty string
	// is not special-cased away).
	if err := VerifyS256("", challenge); err != nil {
		t.Fatalf("VerifyS256: unexpected error for empty verifier matching its own challenge: %v", err)
	}
}

// TestVerifyS256_RejectsPaddedChallenge proves that a challenge encoded
// with standard (padded) base64 instead of RFC 7636's required unpadded
// base64url is rejected — accepting it would let a client under-specify
// the "S256" transform and enable challenge/verifier confusion.
func TestVerifyS256_RejectsPaddedChallenge(t *testing.T) {
	verifier := "a-verifier-value"
	h := sha256.Sum256([]byte(verifier))
	padded := base64.URLEncoding.EncodeToString(h[:]) // padded, unlike RawURLEncoding

	err := VerifyS256(verifier, padded)
	if err == nil {
		t.Fatal("VerifyS256: expected error for padded challenge encoding, got nil")
	}
}
