package keys

import (
	"encoding/base64"
	"math/big"
	"path/filepath"
	"testing"
)

func TestBuildJWKS_MatchesManagerKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.pem")

	m := New("kid-42")
	if err := m.LoadOrGenerate(path); err != nil {
		t.Fatalf("LoadOrGenerate: %v", err)
	}

	jwks := m.BuildJWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("BuildJWKS().Keys has %d entries, want 1", len(jwks.Keys))
	}
	jwk := jwks.Keys[0]

	if jwk.Kty != "RSA" {
		t.Errorf("Kty = %q, want RSA", jwk.Kty)
	}
	if jwk.Use != "sig" {
		t.Errorf("Use = %q, want sig", jwk.Use)
	}
	if jwk.Alg != "RS256" {
		t.Errorf("Alg = %q, want RS256", jwk.Alg)
	}
	if jwk.Kid != "kid-42" {
		t.Errorf("Kid = %q, want kid-42", jwk.Kid)
	}

	// The published modulus/exponent must decode to exactly the manager's
	// actual public key — this is the field a JWKS consumer verifies
	// signatures against, so a mismatch here would silently break every
	// client's token verification.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		t.Fatalf("decode N: %v", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	pub := m.PublicKey()
	if n.Cmp(pub.N) != 0 {
		t.Error("decoded N does not match the manager's public key modulus")
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		t.Fatalf("decode E: %v", err)
	}
	e := new(big.Int).SetBytes(eBytes)
	if e.Int64() != int64(pub.E) {
		t.Errorf("decoded E = %d, want %d", e.Int64(), pub.E)
	}
}
