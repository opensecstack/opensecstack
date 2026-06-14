package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

// ErrPKCEMismatch is returned when the code_verifier does not match the stored code_challenge.
var ErrPKCEMismatch = errors.New("pkce: code_verifier does not match code_challenge")

// VerifyS256 checks that SHA-256(verifier) == challenge, where challenge is
// base64url-encoded without padding (as required by RFC 7636 S256 method).
func VerifyS256(verifier, challenge string) error {
	h := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(h[:])
	if computed != challenge {
		return ErrPKCEMismatch
	}
	return nil
}
