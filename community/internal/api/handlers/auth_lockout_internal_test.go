package handlers

// White-box tests for the login-lockout bookkeeping (recordFailure,
// clearFailures, isLockedOut) and password hashing helpers (bcryptHash,
// bcryptVerify). These have no exported surface — Login only exercises them
// indirectly through a DB-backed handler — so they are tested directly here.
// This is security-relevant: it is the brute-force protection for login.

import (
	"testing"
)

func TestIsLockedOut_NoFailures_ReturnsFalse(t *testing.T) {
	username := "user-no-failures-" + t.Name()
	if isLockedOut(username) {
		t.Error("expected user with no recorded failures to not be locked out")
	}
}

func TestIsLockedOut_BelowThreshold_ReturnsFalse(t *testing.T) {
	username := "user-below-threshold-" + t.Name()
	t.Cleanup(func() { clearFailures(username) })

	for i := 0; i < lockoutMaxFails-1; i++ {
		recordFailure(username)
	}
	if isLockedOut(username) {
		t.Errorf("expected user with %d failures (below threshold %d) to not be locked out", lockoutMaxFails-1, lockoutMaxFails)
	}
}

func TestIsLockedOut_AtThreshold_ReturnsTrue(t *testing.T) {
	username := "user-at-threshold-" + t.Name()
	t.Cleanup(func() { clearFailures(username) })

	for i := 0; i < lockoutMaxFails; i++ {
		recordFailure(username)
	}
	if !isLockedOut(username) {
		t.Errorf("expected user with %d failures (== threshold %d) to be locked out", lockoutMaxFails, lockoutMaxFails)
	}
}

func TestIsLockedOut_AboveThreshold_ReturnsTrue(t *testing.T) {
	username := "user-above-threshold-" + t.Name()
	t.Cleanup(func() { clearFailures(username) })

	for i := 0; i < lockoutMaxFails+3; i++ {
		recordFailure(username)
	}
	if !isLockedOut(username) {
		t.Error("expected user with failures above threshold to be locked out")
	}
}

func TestClearFailures_ResetsLockout(t *testing.T) {
	username := "user-clear-failures-" + t.Name()
	for i := 0; i < lockoutMaxFails; i++ {
		recordFailure(username)
	}
	if !isLockedOut(username) {
		t.Fatal("setup failed: expected user to be locked out before clearing")
	}

	clearFailures(username)

	if isLockedOut(username) {
		t.Error("expected clearFailures to reset lockout state")
	}
}

func TestClearFailures_DifferentUserUnaffected(t *testing.T) {
	victim := "user-clear-victim-" + t.Name()
	other := "user-clear-other-" + t.Name()
	t.Cleanup(func() { clearFailures(victim); clearFailures(other) })

	for i := 0; i < lockoutMaxFails; i++ {
		recordFailure(victim)
		recordFailure(other)
	}

	clearFailures(victim)

	if isLockedOut(victim) {
		t.Error("expected victim's lockout to be cleared")
	}
	if !isLockedOut(other) {
		t.Error("clearFailures for one username must not affect a different username's lockout state")
	}
}

func TestBcryptHash_ProducesVerifiableHash(t *testing.T) {
	hash, err := bcryptHash("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}
	if hash == "correct-horse-battery-staple" {
		t.Fatal("bcryptHash must not return the plaintext password unchanged")
	}
	if !bcryptVerify("correct-horse-battery-staple", hash) {
		t.Error("expected bcryptVerify to accept the correct password against its own hash")
	}
}

func TestBcryptVerify_WrongPassword_ReturnsFalse(t *testing.T) {
	hash, err := bcryptHash("the-real-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bcryptVerify("a-wrong-guess", hash) {
		t.Error("expected bcryptVerify to reject an incorrect password")
	}
}

func TestBcryptVerify_MalformedHash_ReturnsFalseNotPanic(t *testing.T) {
	if bcryptVerify("anything", "not-a-real-bcrypt-hash") {
		t.Error("expected bcryptVerify to return false for a malformed hash, not true")
	}
}

func TestBcryptHash_DifferentCallsProduceDifferentSalts(t *testing.T) {
	h1, err := bcryptHash("same-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h2, err := bcryptHash("same-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Error("expected bcryptHash to salt each call differently, even for the same password")
	}
	// Both hashes must still verify against the same password.
	if !bcryptVerify("same-password", h1) || !bcryptVerify("same-password", h2) {
		t.Error("both independently-salted hashes must verify the original password")
	}
}
