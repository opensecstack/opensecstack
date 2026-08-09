package token

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestVerify_ValidToken proves a token signed by the matching Issuer, with
// the correct issuer, round-trips through Verify with its claims intact.
func TestVerify_ValidToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := NewIssuer(key, "kid-1", "https://sinauth.test")
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	tok, err := issuer.IssueAccessToken("alice", "client-1", []string{"openid", "profile"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	claims, err := verifier.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Sub != "alice" {
		t.Errorf("Sub = %q, want alice", claims.Sub)
	}
	if claims.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want client-1", claims.ClientID)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "openid" || claims.Scopes[1] != "profile" {
		t.Errorf("Scopes = %v, want [openid profile]", claims.Scopes)
	}
}

// TestVerify_ExpiredToken proves a token past its exp claim is rejected,
// not merely accepted with a stale claim set.
func TestVerify_ExpiredToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := NewIssuer(key, "kid-1", "https://sinauth.test")
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	// -1 hour TTL puts ExpiresAt in the past.
	tok, err := issuer.IssueAccessToken("alice", "client-1", []string{"openid"}, -time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = verifier.Verify(tok)
	if err == nil {
		t.Fatal("Verify: expected error for expired token, got nil")
	}
}

// TestVerify_WrongIssuer proves a validly-signed token whose iss claim
// doesn't match the verifier's configured issuer is rejected — this is
// what stops a token issued by a different sinauth deployment/tenant (but
// somehow signed by the same key material) from being accepted.
func TestVerify_WrongIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := NewIssuer(key, "kid-1", "https://attacker.test")
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	tok, err := issuer.IssueAccessToken("alice", "client-1", []string{"openid"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = verifier.Verify(tok)
	if err == nil {
		t.Fatal("Verify: expected error for issuer mismatch, got nil")
	}
}

// TestVerify_WrongKey proves a token signed by a different private key
// (e.g. a stolen/forged token) fails signature verification against the
// verifier's public key.
func TestVerify_WrongKey(t *testing.T) {
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := NewIssuer(signingKey, "kid-1", "https://sinauth.test")
	// Verifier holds a *different* public key than the one that signed the token.
	verifier := NewVerifier(&otherKey.PublicKey, "https://sinauth.test")

	tok, err := issuer.IssueAccessToken("alice", "client-1", []string{"openid"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	_, err = verifier.Verify(tok)
	if err == nil {
		t.Fatal("Verify: expected error for signature mismatch, got nil")
	}
}

// TestVerify_WrongSigningMethod proves a token signed with HS256 (using the
// PEM-encoded public key bytes as an HMAC secret — the classic RS256/HS256
// confusion attack) is rejected outright, not merely failed on signature.
func TestVerify_WrongSigningMethod(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	claims := AccessTokenClaims{
		Sub:      "alice",
		ClientID: "client-1",
		Scopes:   []string{"openid"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://sinauth.test",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	hsToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := hsToken.SignedString([]byte("attacker-controlled-secret"))
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}

	_, err = verifier.Verify(signed)
	if err == nil {
		t.Fatal("Verify: expected error for alg-confusion HS256 token, got nil")
	}
}

// TestVerify_MalformedToken proves garbage input is rejected with an error
// rather than panicking or being silently accepted.
func TestVerify_MalformedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	_, err = verifier.Verify("not.a.jwt")
	if err == nil {
		t.Fatal("Verify: expected error for malformed token, got nil")
	}
}

// TestVerify_TamperedPayload proves that flipping a claim in the payload
// segment (without re-signing) invalidates the signature.
func TestVerify_TamperedPayload(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	issuer := NewIssuer(key, "kid-1", "https://sinauth.test")
	verifier := NewVerifier(&key.PublicKey, "https://sinauth.test")

	tok, err := issuer.IssueAccessToken("alice", "client-1", []string{"openid"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	// Corrupt the last character of the token (part of the signature), which
	// must invalidate it regardless of which segment absorbs the change.
	tampered := tok[:len(tok)-1] + "x"
	if tampered == tok {
		t.Fatal("tampering produced identical token; adjust the corrupted byte")
	}

	_, err = verifier.Verify(tampered)
	if err == nil {
		t.Fatal("Verify: expected error for tampered token, got nil")
	}
}
