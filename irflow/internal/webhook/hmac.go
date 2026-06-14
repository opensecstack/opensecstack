// Package webhook provides HMAC-SHA256 signature verification and typed
// payload definitions for inbound IRFlow webhooks from APIGuard, CITADEL,
// and ThreatFlow.
//
// # Signing scheme
//
// The sender computes:
//
//	signed_payload = timestamp + "." + body
//	signature      = hex(HMAC-SHA256(secret, signed_payload))
//
// and attaches two headers:
//
//	X-Irflow-Signature: sha256=<signature>
//	X-Irflow-Timestamp: <unix-seconds>
//
// The timestamp is mixed into the HMAC input to prevent replay attacks —
// captured requests cannot be resent later because the timestamp would be
// outside the verifier's clock-skew tolerance.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Header names. These are the canonical (http.Header.Get-safe) forms.
const (
	HeaderSignature = "X-Irflow-Signature"
	HeaderTimestamp = "X-Irflow-Timestamp"
	HeaderEventID   = "X-Irflow-Event-Id"
	SignaturePrefix = "sha256="
)

// DefaultClockSkew is the acceptance window for X-Irflow-Timestamp.
const DefaultClockSkew = 5 * time.Minute

// Sentinel errors returned by Verifier.
var (
	ErrEmptySecret      = errors.New("webhook: secret is not configured")
	ErrMissingSignature = errors.New("webhook: missing X-Irflow-Signature header")
	ErrMissingTimestamp = errors.New("webhook: missing X-Irflow-Timestamp header")
	ErrInvalidTimestamp = errors.New("webhook: invalid X-Irflow-Timestamp value")
	ErrStaleTimestamp   = errors.New("webhook: X-Irflow-Timestamp outside allowed clock skew")
	ErrInvalidSignature = errors.New("webhook: signature does not match")
)

// Verifier validates HMAC-SHA256 signatures for a single source/secret pair.
// A Verifier is safe for concurrent use.
type Verifier struct {
	secret    []byte
	clockSkew time.Duration
	now       func() time.Time
}

// NewVerifier constructs a Verifier. If skew is 0, DefaultClockSkew is used.
// Returns ErrEmptySecret if the secret is empty — fail-closed configuration.
func NewVerifier(secret string, skew time.Duration) (*Verifier, error) {
	if secret == "" {
		return nil, ErrEmptySecret
	}
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	return &Verifier{
		secret:    []byte(secret),
		clockSkew: skew,
		now:       time.Now,
	}, nil
}

// Verify validates the signature and timestamp against the body.
func (v *Verifier) Verify(body []byte, signatureHeader, timestampHeader string) error {
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	if timestampHeader == "" {
		return ErrMissingTimestamp
	}

	sigHex := strings.TrimPrefix(signatureHeader, SignaturePrefix)
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return ErrInvalidSignature
	}

	tsSec, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return ErrInvalidTimestamp
	}
	ts := time.Unix(tsSec, 0)
	if delta := v.now().Sub(ts); delta > v.clockSkew || delta < -v.clockSkew {
		return ErrStaleTimestamp
	}

	signedPayload := timestampHeader + "." + string(body)
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(signedPayload))
	expected := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expected) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign produces the signature header value a sender would attach. Useful in
// tests and when IRFlow itself dispatches webhooks to downstream callers.
// Returns "sha256=<hex>".
func Sign(secret string, timestamp int64, body []byte) string {
	tsStr := strconv.FormatInt(timestamp, 10)
	signedPayload := tsStr + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signedPayload))
	return SignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
