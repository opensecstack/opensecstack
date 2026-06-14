// Package cert provides Ed25519 signing for CyberPath certifications.
//
// The Signer wraps an Ed25519 private key and exposes Sign / Verify /
// KeyID. NewSigner accepts a PEM-encoded PKCS#8 or OpenSSH private key;
// when keyPEM is empty it generates an ephemeral key suitable for dev/test.
package cert

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Signer holds an Ed25519 private key and the derived public key.
type Signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// NewSigner parses a PEM-encoded Ed25519 private key.
//
// Supported PEM block types:
//   - "PRIVATE KEY"        — PKCS#8 (openssl genpkey -algorithm ed25519)
//   - "OPENSSH PRIVATE KEY" — OpenSSH format (ssh-keygen -t ed25519)
//
// When keyPEM is empty, an ephemeral key is generated. This is intentional
// for development; production deployments should provide a stable key via
// CYBERPATH_CERT_SIGNING_KEY_PEM.
func NewSigner(keyPEM string) (*Signer, error) {
	if keyPEM == "" {
		return generateEphemeral()
	}
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("cert/signer: no PEM block found in keyPEM")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return fromPKCS8(block.Bytes)
	case "OPENSSH PRIVATE KEY":
		return fromOpenSSH(block.Bytes)
	default:
		return nil, fmt.Errorf("cert/signer: unsupported PEM block type %q", block.Type)
	}
}

// Sign signs payload with the Ed25519 private key and returns the signature
// as a lowercase hex string (128 hex characters for Ed25519).
func (s *Signer) Sign(payload []byte) string {
	sig := ed25519.Sign(s.priv, payload)
	return hex.EncodeToString(sig)
}

// KeyID returns the first 8 bytes of the SHA-256 hash of the raw public key,
// hex-encoded. Used in CITADEL event field "signed_by": "ed25519:<keyid>".
func (s *Signer) KeyID() string {
	sum := sha256.Sum256(s.pub)
	return hex.EncodeToString(sum[:8])
}

// Verify checks a hex-encoded Ed25519 signature against payload.
// Returns true only when the hex decodes cleanly and the signature is valid.
func (s *Signer) Verify(payload []byte, hexSig string) bool {
	sig, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	return ed25519.Verify(s.pub, payload, sig)
}

// ── helpers ────────────────────────────────────────────────────────────────────

func generateEphemeral() (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cert/signer: generate ephemeral key: %w", err)
	}
	return &Signer{priv: priv, pub: pub}, nil
}

func fromPKCS8(der []byte) (*Signer, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("cert/signer: parse PKCS#8: %w", err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cert/signer: PKCS#8 key is not Ed25519 (got %T)", key)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cert/signer: could not derive Ed25519 public key")
	}
	return &Signer{priv: priv, pub: pub}, nil
}

func fromOpenSSH(pemBytes []byte) (*Signer, error) {
	// ssh.ParseRawPrivateKey accepts the full PEM bytes (including header),
	// but here we already have the raw DER. Reconstruct the PEM wrapper so
	// we can use the ssh package's parser without duplicating its logic.
	wrapped := pem.EncodeToMemory(&pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: pemBytes,
	})
	rawKey, err := ssh.ParseRawPrivateKey(wrapped)
	if err != nil {
		return nil, fmt.Errorf("cert/signer: parse OpenSSH key: %w", err)
	}
	priv, ok := rawKey.(*ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("cert/signer: OpenSSH key is not Ed25519 (got %T)", rawKey)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("cert/signer: could not derive Ed25519 public key")
	}
	return &Signer{priv: *priv, pub: pub}, nil
}
