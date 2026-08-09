package middleware

import (
	"testing"
	"time"
)

func TestHashToken(t *testing.T) {
	h1 := HashToken("token-a")
	h2 := HashToken("token-a")
	h3 := HashToken("token-b")

	if h1 != h2 {
		t.Errorf("HashToken should be deterministic: %q != %q", h1, h2)
	}
	if h1 == h3 {
		t.Errorf("HashToken should differ for different inputs: %q == %q", h1, h3)
	}
	// SHA-256 hex encoding is always 64 chars.
	if len(h1) != 64 {
		t.Errorf("HashToken length = %d, want 64", len(h1))
	}
}

func TestTokenDenylist_AddAndIsDenied(t *testing.T) {
	d := NewTokenDenylist()
	defer d.Stop()

	hash := HashToken("some-raw-token")

	if d.IsDenied(hash) {
		t.Fatal("token should not be denied before Add")
	}

	d.Add(hash, time.Now().Add(time.Hour))

	if !d.IsDenied(hash) {
		t.Fatal("token should be denied after Add with future expiry")
	}
}

func TestTokenDenylist_AddPastExpiryIsNoOp(t *testing.T) {
	d := NewTokenDenylist()
	defer d.Stop()

	hash := HashToken("expired-token")
	d.Add(hash, time.Now().Add(-time.Hour))

	if d.IsDenied(hash) {
		t.Fatal("token added with a past expiry should not be considered denied")
	}
}

func TestTokenDenylist_IsDeniedFalseAfterExpiry(t *testing.T) {
	d := NewTokenDenylist()
	defer d.Stop()

	hash := HashToken("soon-expired-token")
	// Insert directly with an expiry in the very near future.
	d.Add(hash, time.Now().Add(20*time.Millisecond))

	if !d.IsDenied(hash) {
		t.Fatal("token should be denied immediately after Add")
	}

	time.Sleep(40 * time.Millisecond)

	if d.IsDenied(hash) {
		t.Fatal("token should no longer be denied once its expiry has passed")
	}
}

func TestTokenDenylist_UnknownTokenNotDenied(t *testing.T) {
	d := NewTokenDenylist()
	defer d.Stop()

	if d.IsDenied(HashToken("never-added")) {
		t.Fatal("unknown token should not be denied")
	}
}

func TestTokenDenylist_StopIsIdempotent(t *testing.T) {
	d := NewTokenDenylist()
	d.Stop()
	// Calling Stop a second time must not panic (sync.Once guards close()).
	d.Stop()
}
