package auth

import (
	"strings"
	"testing"
)

func TestHashPassword_ProducesVerifiableHash(t *testing.T) {
	pepper := []byte("test-pepper")
	encoded, err := HashPassword("s3cr3t!", pepper)
	if err != nil {
		t.Fatalf("HashPassword: unexpected error: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=") {
		t.Fatalf("HashPassword: unexpected format: %q", encoded)
	}
	ok, err := VerifyPassword(encoded, "s3cr3t!", pepper)
	if err != nil {
		t.Fatalf("VerifyPassword: unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyPassword: correct password did not verify")
	}
}

func TestHashPassword_UniqueSaltPerCall(t *testing.T) {
	pepper := []byte("pepper")
	h1, err := HashPassword("same-password", pepper)
	if err != nil {
		t.Fatalf("HashPassword #1: %v", err)
	}
	h2, err := HashPassword("same-password", pepper)
	if err != nil {
		t.Fatalf("HashPassword #2: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("HashPassword: two hashes of the same password must differ (random salt), got identical: %q", h1)
	}
}

func TestVerifyPassword_WrongPasswordFails(t *testing.T) {
	pepper := []byte("pepper")
	encoded, err := HashPassword("correct-horse", pepper)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword(encoded, "wrong-horse", pepper)
	if err != nil {
		t.Fatalf("VerifyPassword: unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("VerifyPassword: wrong password verified as correct")
	}
}

func TestVerifyPassword_WrongPepperFails(t *testing.T) {
	encoded, err := HashPassword("pw", []byte("pepper-a"))
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword(encoded, "pw", []byte("pepper-b"))
	if err != nil {
		t.Fatalf("VerifyPassword: unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("VerifyPassword: mismatched pepper verified as correct")
	}
}

func TestVerifyPassword_MalformedHashReturnsError(t *testing.T) {
	cases := []struct {
		name    string
		encoded string
	}{
		{"empty string", ""},
		{"not PHC at all", "not-a-hash"},
		{"wrong variant", "$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad version", "$argon2id$v=1$m=65536,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad params", "$argon2id$v=19$m=x,t=3,p=4$c2FsdA$aGFzaA"},
		{"bad salt b64", "$argon2id$v=19$m=65536,t=3,p=4$!!!!$aGFzaA"},
		{"bad hash b64", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$!!!!"},
		{"too few segments", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := VerifyPassword(tc.encoded, "pw", []byte("pepper"))
			if err == nil {
				t.Fatalf("VerifyPassword(%q): want error, got nil (ok=%v)", tc.encoded, ok)
			}
			if ok {
				t.Fatalf("VerifyPassword(%q): want ok=false on error, got true", tc.encoded)
			}
		})
	}
}

func TestVerifyPassword_EmptyPepperFallsBackToPlaintext(t *testing.T) {
	// peppered() falls back to raw plaintext when pepper is empty, so
	// hashing and verifying with a nil pepper must still round-trip.
	encoded, err := HashPassword("no-pepper-pw", nil)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	ok, err := VerifyPassword(encoded, "no-pepper-pw", nil)
	if err != nil {
		t.Fatalf("VerifyPassword: %v", err)
	}
	if !ok {
		t.Fatalf("VerifyPassword: empty-pepper round trip failed")
	}
}

func TestVerifyPasswordWithFallback(t *testing.T) {
	primary := []byte("primary-pepper")
	previous := []byte("previous-pepper")

	t.Run("primary matches", func(t *testing.T) {
		encoded, err := HashPassword("pw", primary)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		verified, needsRehash, err := VerifyPasswordWithFallback(encoded, "pw", primary, previous)
		if err != nil || !verified || needsRehash {
			t.Fatalf("got verified=%v needsRehash=%v err=%v, want true false nil", verified, needsRehash, err)
		}
	})

	t.Run("primary mismatch, previous matches -> needsRehash", func(t *testing.T) {
		encoded, err := HashPassword("pw", previous)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		verified, needsRehash, err := VerifyPasswordWithFallback(encoded, "pw", primary, previous)
		if err != nil || !verified || !needsRehash {
			t.Fatalf("got verified=%v needsRehash=%v err=%v, want true true nil", verified, needsRehash, err)
		}
	})

	t.Run("both mismatch", func(t *testing.T) {
		encoded, err := HashPassword("pw", []byte("some-other-pepper"))
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		verified, needsRehash, err := VerifyPasswordWithFallback(encoded, "pw", primary, previous)
		if err != nil || verified || needsRehash {
			t.Fatalf("got verified=%v needsRehash=%v err=%v, want false false nil", verified, needsRehash, err)
		}
	})

	t.Run("empty previous collapses to plain verify", func(t *testing.T) {
		encoded, err := HashPassword("pw", primary)
		if err != nil {
			t.Fatalf("HashPassword: %v", err)
		}
		verified, needsRehash, err := VerifyPasswordWithFallback(encoded, "pw", primary, nil)
		if err != nil || !verified || needsRehash {
			t.Fatalf("got verified=%v needsRehash=%v err=%v, want true false nil", verified, needsRehash, err)
		}
	})

	t.Run("malformed hash propagates error", func(t *testing.T) {
		verified, needsRehash, err := VerifyPasswordWithFallback("garbage", "pw", primary, previous)
		if err == nil || verified || needsRehash {
			t.Fatalf("got verified=%v needsRehash=%v err=%v, want false false non-nil", verified, needsRehash, err)
		}
	})
}

func TestNeedsRehash(t *testing.T) {
	pepper := []byte("pepper")
	current, err := HashPassword("pw", pepper)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if NeedsRehash(current) {
		t.Fatalf("NeedsRehash: freshly-hashed value at current params reported as needing rehash")
	}

	weak := "$argon2id$v=19$m=1024,t=1,p=1$c2FsdHlzYWx0$aGFzaHZhbHVlaGFzaHZhbHVl"
	if !NeedsRehash(weak) {
		t.Fatalf("NeedsRehash: weak params not flagged")
	}

	if !NeedsRehash("not-a-valid-hash") {
		t.Fatalf("NeedsRehash: malformed hash should be flagged true")
	}
}
