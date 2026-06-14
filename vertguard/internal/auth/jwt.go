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

// Claims is the minimal JWT claim set VertGuard verifies.
type Claims struct {
	Sub  string `json:"sub"`
	Role string `json:"role"`
	Iss  string `json:"iss"`
	Exp  int64  `json:"exp"`
	Iat  int64  `json:"iat,omitempty"`
	Jti  string `json:"jti,omitempty"`
}

// Sentinel errors returned by Verify.
var (
	ErrTokenEmpty     = errors.New("auth: token is empty")
	ErrTokenMalformed = errors.New("auth: token malformed")
	ErrAlgUnsupported = errors.New("auth: only HS256 supported")
	ErrSignatureBad   = errors.New("auth: signature mismatch")
	ErrTokenExpired   = errors.New("auth: token expired")
	ErrIssuerBad      = errors.New("auth: issuer mismatch")
	ErrRoleUnknown    = errors.New("auth: role not recognised")
)

// Metrics is the optional metrics sink for the Verifier. The package
// stays prom-free; build adapters in internal/metrics.
//
// IncSecretUsed is called once per successful HMAC match with the slot
// name corresponding to the secret position: "primary", "next", or
// "previous".
type Metrics interface {
	IncSecretUsed(slot string)
}

// secretSlots maps an index in the secrets slice to a stable slot name
// for metric labelling. The Verifier preserves the slot identity passed
// at construction time; NewVerifierMulti uses positional defaults.
var defaultSlotNames = []string{"primary", "next", "previous"}

// Verifier validates HS256 JWTs against one or more shared secrets.
// Multiple secrets enable zero-downtime rotation: the issuer can flip
// to a new secret while the verifier still accepts tokens minted with
// the old one.
type Verifier struct {
	secrets [][]byte
	slots   []string // parallel to secrets; slot label for metrics
	issuer  string
	now     func() time.Time
	metrics Metrics
}

// NewVerifier creates a single-secret Verifier. Kept for backwards
// compatibility; use NewVerifierMulti to enable rotation.
func NewVerifier(secret, issuer string) *Verifier {
	v := &Verifier{
		issuer: issuer,
		now:    time.Now,
	}
	if secret != "" {
		v.secrets = [][]byte{[]byte(secret)}
		v.slots = []string{"primary"}
	}
	return v
}

// NewVerifierMulti accepts secrets in priority order (primary, next,
// previous). Empty strings are filtered. Panics if the resulting slice
// is empty — a verifier with zero secrets would silently accept any
// signature comparison and is never desired.
func NewVerifierMulti(secrets []string, issuer string) *Verifier {
	v := &Verifier{
		issuer: issuer,
		now:    time.Now,
	}
	for i, s := range secrets {
		if s == "" {
			continue
		}
		v.secrets = append(v.secrets, []byte(s))
		slot := fmt.Sprintf("slot_%d", i)
		if i < len(defaultSlotNames) {
			slot = defaultSlotNames[i]
		}
		v.slots = append(v.slots, slot)
	}
	if len(v.secrets) == 0 {
		panic("auth: NewVerifierMulti requires at least one non-empty secret")
	}
	return v
}

// SetMetrics installs an optional metrics sink. Method-style to keep
// the constructor signatures stable.
func (v *Verifier) SetMetrics(m Metrics) {
	v.metrics = m
}

// Verify parses + validates a token and returns the claims.
// Callers should check the returned Role against their RBAC policy.
func (v *Verifier) Verify(token string) (*Claims, error) {
	if token == "" {
		return nil, ErrTokenEmpty
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}

	// Header
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header b64: %v", ErrTokenMalformed, err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header json: %v", ErrTokenMalformed, err)
	}
	if header.Alg != "HS256" {
		return nil, ErrAlgUnsupported
	}

	// Signature — try each configured secret in priority order. First
	// match wins. Constant-time comparison preserved per attempt.
	signedInput := parts[0] + "." + parts[1]
	expectedSig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: sig b64: %v", ErrTokenMalformed, err)
	}

	matchedIdx := -1
	for i, secret := range v.secrets {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(signedInput))
		computedSig := mac.Sum(nil)
		if hmac.Equal(expectedSig, computedSig) {
			matchedIdx = i
			break
		}
	}
	if matchedIdx < 0 {
		return nil, ErrSignatureBad
	}

	// Claims
	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: claims b64: %v", ErrTokenMalformed, err)
	}
	var c Claims
	if err := json.Unmarshal(claimsJSON, &c); err != nil {
		return nil, fmt.Errorf("%w: claims json: %v", ErrTokenMalformed, err)
	}

	// Policy
	if c.Exp > 0 && v.now().Unix() >= c.Exp {
		return nil, ErrTokenExpired
	}
	if v.issuer != "" && c.Iss != v.issuer {
		return nil, ErrIssuerBad
	}
	if !IsKnownRole(c.Role) {
		return nil, ErrRoleUnknown
	}

	if v.metrics != nil {
		v.metrics.IncSecretUsed(v.slots[matchedIdx])
	}

	return &c, nil
}
