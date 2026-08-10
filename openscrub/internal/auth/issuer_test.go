package auth

import (
	"strings"
	"testing"
	"time"
)

func TestCredentialStoreVerify(t *testing.T) {
	pepper := "p"
	hash := HashPassword(pepper, "s3cret")
	store := NewCredentialStore(pepper, "alice:operator:"+hash)
	if store.Empty() {
		t.Fatal("store unexpectedly empty")
	}
	if _, err := store.Verify("alice", "s3cret"); err != nil {
		t.Fatalf("verify alice: %v", err)
	}
	if _, err := store.Verify("alice", "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if _, err := store.Verify("ghost", "anything"); err == nil {
		t.Fatal("unknown user accepted")
	}
}

func TestCredentialStoreSkipsMalformedEntries(t *testing.T) {
	store := NewCredentialStore("p", "garbage,,alice:operator:"+HashPassword("p", "x"))
	if _, err := store.Verify("alice", "x"); err != nil {
		t.Fatalf("verify alice: %v", err)
	}
}

func TestIssuerMintRoundtripsViaVerifier(t *testing.T) {
	iss := NewIssuer("topsecret", "openscrub", 5*time.Minute)
	tok, exp, err := iss.Mint("alice", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !exp.After(time.Now()) {
		t.Fatalf("expiry not in future: %v", exp)
	}
	v := NewHS256Verifier([]string{"topsecret"}, "openscrub")
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.Sub != "alice" || c.Role != RoleOperator {
		t.Fatalf("claims wrong: %+v", c)
	}
}

func TestIssuerRefusesEmptySecret(t *testing.T) {
	iss := NewIssuer("", "openscrub", time.Hour)
	_, _, err := iss.Mint("u", "role")
	if err == nil || !strings.Contains(err.Error(), "no secret") {
		t.Fatalf("expected no-secret error, got %v", err)
	}
}

// TestNewIssuerDefaultsTTLWhenNonPositive proves the documented
// "ttl<=0 -> 1h" fallback: a caller passing a zero or negative TTL
// (e.g. an unset env-var parsed as 0) still gets a token that expires
// in the future, not an immediately-expired one.
func TestNewIssuerDefaultsTTLWhenNonPositive(t *testing.T) {
	for _, ttl := range []time.Duration{0, -time.Minute} {
		iss := NewIssuer("s", "openscrub", ttl)
		_, exp, err := iss.Mint("u", RoleAdmin)
		if err != nil {
			t.Fatalf("ttl=%v: Mint: %v", ttl, err)
		}
		// Must be close to now+1h, not now+ttl (which would be in the
		// past or exactly now).
		wantMin := time.Now().Add(55 * time.Minute)
		if exp.Before(wantMin) {
			t.Fatalf("ttl=%v: exp=%v, want >= %v (1h default)", ttl, exp, wantMin)
		}
	}
}

// TestCredentialStoreVerifyRejectsMalformedStoredHash proves a
// corrupt (non-hex) hash in the credential store fails closed rather
// than panicking on hex.DecodeString or comparing garbage bytes.
func TestCredentialStoreVerifyRejectsMalformedStoredHash(t *testing.T) {
	store := NewCredentialStore("p", "alice:operator:not-valid-hex!!")
	if _, err := store.Verify("alice", "whatever"); err == nil {
		t.Fatal("expected error for malformed stored hash")
	}
}
