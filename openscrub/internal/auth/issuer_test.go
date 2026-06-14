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
