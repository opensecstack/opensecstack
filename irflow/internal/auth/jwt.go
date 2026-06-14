// Package auth provides HS256 JWT issuance/verification, role-based access
// control, and chi middleware for protecting IRFlow API routes.
//
// Tokens carry three claims in addition to the standard ones:
//
//	sub   — user ID (opaque string, stable across sessions)
//	role  — one of the Role* constants in this package
//	email — user email (optional, for audit logging)
//
// Tokens are signed with HMAC-SHA256 using a secret shared between IRFlow
// and the token issuer (typically an external SSO; for local dev use the
// `irflow auth issue` CLI which signs with the same secret).
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Sentinel errors.
var (
	ErrMissingSecret    = errors.New("auth: signing secret is not configured")
	ErrMalformedToken   = errors.New("auth: token is malformed")
	ErrUnsupportedAlg   = errors.New("auth: token algorithm is not HS256")
	ErrInvalidSignature = errors.New("auth: token signature is invalid")
	ErrTokenExpired     = errors.New("auth: token is expired")
	ErrTokenNotYetValid = errors.New("auth: token is not yet valid")
)

// Claims is the typed JWT payload IRFlow issues and expects.
type Claims struct {
	Subject   string `json:"sub"`
	Role      string `json:"role"`
	Email     string `json:"email,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	Audience  string `json:"aud,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
}

// Valid reports whether the timing claims are within now's bounds.
func (c Claims) Valid(now time.Time) error {
	if c.ExpiresAt != 0 && now.Unix() >= c.ExpiresAt {
		return ErrTokenExpired
	}
	if c.NotBefore != 0 && now.Unix() < c.NotBefore {
		return ErrTokenNotYetValid
	}
	return nil
}

// Issue returns a signed HS256 JWT for the given claims. IssuedAt is set to
// now if zero. ExpiresAt is set to now+ttl if zero and ttl > 0.
func Issue(secret string, claims Claims, ttl time.Duration) (string, error) {
	if secret == "" {
		return "", ErrMissingSecret
	}
	now := time.Now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 && ttl > 0 {
		claims.ExpiresAt = now.Add(ttl).Unix()
	}

	header := `{"alg":"HS256","typ":"JWT"}`
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("auth: marshalling claims: %w", err)
	}

	encHeader := b64url(header)
	encPayload := b64url(string(payloadBytes))
	signingInput := encHeader + "." + encPayload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return signingInput + "." + sig, nil
}

// Verify parses, signature-checks, and time-checks the token. It returns the
// claims only on full success.
func Verify(secret, token string) (*Claims, error) {
	if secret == "" {
		return nil, ErrMissingSecret
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var hdr struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, ErrMalformedToken
	}
	if hdr.Alg != "HS256" {
		return nil, ErrUnsupportedAlg
	}

	signingInput := parts[0] + "." + parts[1]
	expected := hmac.New(sha256.New, []byte(secret))
	expected.Write([]byte(signingInput))
	expectedSig := expected.Sum(nil)

	actualSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidSignature
	}
	if !hmac.Equal(actualSig, expectedSig) {
		return nil, ErrInvalidSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformedToken
	}
	var claims Claims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrMalformedToken
	}
	if err := claims.Valid(time.Now()); err != nil {
		return nil, err
	}
	return &claims, nil
}

func b64url(s string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}
