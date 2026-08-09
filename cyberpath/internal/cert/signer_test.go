package cert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func pkcs8PEM(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func openSSHPEM(t *testing.T, priv ed25519.PrivateKey) string {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("ssh.MarshalPrivateKey: %v", err)
	}
	return string(pem.EncodeToMemory(block))
}

func TestNewSigner_EmptyKeyGeneratesEphemeral(t *testing.T) {
	s1, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner(\"\"): %v", err)
	}
	s2, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner(\"\"): %v", err)
	}
	if s1.KeyID() == s2.KeyID() {
		t.Fatalf("two ephemeral signers produced the same KeyID %q; expected independent random keys", s1.KeyID())
	}
	sig := s1.Sign([]byte("payload"))
	if !s1.Verify([]byte("payload"), sig) {
		t.Fatalf("ephemeral signer: self-signed payload did not verify")
	}
}

func TestNewSigner_FromPKCS8(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner(pkcs8PEM(t, priv))
	if err != nil {
		t.Fatalf("NewSigner(pkcs8): %v", err)
	}
	sig := s.Sign([]byte("hello"))
	if !ed25519.Verify(pub, []byte("hello"), mustHexDecode(t, sig)) {
		t.Fatalf("signature produced by Signer does not verify against the original public key")
	}
}

func TestNewSigner_FromOpenSSH(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner(openSSHPEM(t, priv))
	if err != nil {
		t.Fatalf("NewSigner(openssh): %v", err)
	}
	sig := s.Sign([]byte("hello"))
	if !ed25519.Verify(pub, []byte("hello"), mustHexDecode(t, sig)) {
		t.Fatalf("signature produced by Signer does not verify against the original public key")
	}
}

func TestNewSigner_RejectsNoPEMBlock(t *testing.T) {
	if _, err := NewSigner("not a pem block"); err == nil {
		t.Fatalf("NewSigner: want error for input with no PEM block")
	}
}

func TestNewSigner_RejectsUnsupportedPEMType(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte("irrelevant")})
	if _, err := NewSigner(string(block)); err == nil {
		t.Fatalf("NewSigner: want error for unsupported PEM block type")
	}
}

func TestNewSigner_RejectsMalformedPKCS8(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not valid der")})
	if _, err := NewSigner(string(block)); err == nil {
		t.Fatalf("NewSigner: want error for malformed PKCS#8 DER")
	}
}

func TestNewSigner_RejectsNonEd25519PKCS8(t *testing.T) {
	// x509 test fixture: an RSA-ish DER would fail differently; simplest
	// deterministic non-ed25519 key is an ECDSA P-256 key.
	privDER := generateECDSAPKCS8(t)
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if _, err := NewSigner(string(block)); err == nil {
		t.Fatalf("NewSigner: want error for non-Ed25519 PKCS#8 key")
	}
}

func TestNewSigner_RejectsMalformedOpenSSH(t *testing.T) {
	block := pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: []byte("not a valid openssh blob")})
	if _, err := NewSigner(string(block)); err == nil {
		t.Fatalf("NewSigner: want error for malformed OpenSSH key")
	}
}

func TestSigner_Sign_ReturnsHexEncoded128Chars(t *testing.T) {
	s, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig := s.Sign([]byte("payload"))
	if len(sig) != 128 {
		t.Fatalf("Sign: got hex length %d, want 128 (64-byte Ed25519 sig)", len(sig))
	}
}

func TestSigner_KeyID_StableAndDerivedFromPublicKey(t *testing.T) {
	s, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	id1 := s.KeyID()
	id2 := s.KeyID()
	if id1 != id2 {
		t.Fatalf("KeyID: not stable across calls: %q vs %q", id1, id2)
	}
	if len(id1) != 16 { // 8 bytes hex-encoded
		t.Fatalf("KeyID: got length %d, want 16", len(id1))
	}
}

func TestSigner_Verify_RejectsTamperedPayload(t *testing.T) {
	s, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	sig := s.Sign([]byte("original"))
	if s.Verify([]byte("tampered"), sig) {
		t.Fatalf("Verify: tampered payload verified as valid")
	}
}

func TestSigner_Verify_RejectsWrongSigner(t *testing.T) {
	s1, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner s1: %v", err)
	}
	s2, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner s2: %v", err)
	}
	sig := s1.Sign([]byte("payload"))
	if s2.Verify([]byte("payload"), sig) {
		t.Fatalf("Verify: signature from s1 verified as valid under s2's public key")
	}
}

func TestSigner_Verify_RejectsMalformedHexSignature(t *testing.T) {
	s, err := NewSigner("")
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.Verify([]byte("payload"), "not-hex!!") {
		t.Fatalf("Verify: malformed hex signature reported as valid")
	}
}

func mustHexDecode(t *testing.T, hexStr string) []byte {
	t.Helper()
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	return b
}

func generateECDSAPKCS8(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey (ecdsa): %v", err)
	}
	return der
}
