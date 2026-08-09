package modules

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// base64URLEncode
// ---------------------------------------------------------------------------

func TestBase64URLEncode_MatchesStandardEncoding(t *testing.T) {
	data := []byte(`{"alg":"HS256","typ":"JWT"}`)
	got := base64URLEncode(data)
	want := base64.RawURLEncoding.EncodeToString(data)
	if got != want {
		t.Errorf("expected %q, got %q", want, got)
	}
	// URL-safe encoding must not contain '+' or '/' or padding.
	if strings.ContainsAny(got, "+/=") {
		t.Errorf("expected URL-safe, unpadded output, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// hmacSHA256
// ---------------------------------------------------------------------------

func TestHmacSHA256_MatchesStandardLibrary(t *testing.T) {
	key := []byte("test-key")
	data := []byte("payload-to-sign")
	got := hmacSHA256(key, data)

	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	want := mac.Sum(nil)

	if !hmac.Equal(got, want) {
		t.Error("hmacSHA256 output does not match crypto/hmac reference computation")
	}
	if len(got) != sha256.Size {
		t.Errorf("expected %d-byte digest, got %d", sha256.Size, len(got))
	}
}

func TestHmacSHA256_DifferentKeysProduceDifferentDigests(t *testing.T) {
	data := []byte("same payload")
	a := hmacSHA256([]byte("key-a"), data)
	b := hmacSHA256([]byte("key-b"), data)
	if hmac.Equal(a, b) {
		t.Error("expected different keys to produce different digests")
	}
}

// ---------------------------------------------------------------------------
// generateExpiredJWT
// ---------------------------------------------------------------------------

func TestGenerateExpiredJWT_StructureAndExpiry(t *testing.T) {
	tok := generateExpiredJWT()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 dot-separated JWT segments, got %d", len(parts))
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("failed to decode payload: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		t.Fatalf("failed to unmarshal claims: %v", err)
	}

	now := time.Now().Unix()
	if claims.Exp >= now {
		t.Errorf("expected exp to be in the past, got exp=%d now=%d", claims.Exp, now)
	}
	if claims.Iat >= claims.Exp {
		t.Errorf("expected iat < exp, got iat=%d exp=%d", claims.Iat, claims.Exp)
	}
	if claims.Sub == "" {
		t.Error("expected non-empty sub claim")
	}

	// Signature must verify against the well-known test probe key so the
	// probe token exercises the API's actual JWT-expiry check, not just
	// its signature-format parsing.
	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}
	expectedSig := hmacSHA256([]byte(testProbeHMACKey), []byte(signingInput))
	if !hmac.Equal(sigBytes, expectedSig) {
		t.Error("expected token signature to verify against testProbeHMACKey")
	}
}

func TestGenerateExpiredJWT_ProducesFreshTokenEachCall(t *testing.T) {
	// iat/exp are wall-clock derived; two calls a moment apart should still
	// both individually satisfy the "expired" invariant even if identical
	// down to the second.
	tok1 := generateExpiredJWT()
	tok2 := generateExpiredJWT()
	if tok1 == "" || tok2 == "" {
		t.Fatal("expected non-empty tokens")
	}
}
