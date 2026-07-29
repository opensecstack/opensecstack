package marshal

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCanonicalPayloadMatchesSDKFixture(t *testing.T) {
	// Mirrors sdk/go/citadel/sign_test.go's fixtureKerkese — the two
	// CanonicalPayload implementations must produce byte-identical output
	// for the same input, or a producer-signed Kerkese would never verify.
	k := Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		ProjectID:      "apiguard",
		ExecutionID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Action:         KerkeseAction{Type: "API_SCAN_INITIATE", ChangeID: "chg-1"},
		Actor:          KerkeseActor{UserID: "101", Role: "operator"},
		Verifier:       KerkeseVerifier{UserID: "202", Role: "admin"},
		SoD:            KerkeseSoD{OperatorUserID: "101", VerifierUserID: "202"},
	}

	const want = "v1|00000000-0000-0000-0000-000000000001|API_SCAN_INITIATE|chg-1|101|operator|202|admin|101|202|2026-07-26T12:00:00Z"
	if got := CanonicalPayload(k); got != want {
		t.Fatalf("CanonicalPayload = %q, want %q (must match sdk/go/citadel.CanonicalPayload)", got, want)
	}
}

func TestVerifySignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := "v1|test-payload"
	sig := ed25519.Sign(priv, []byte(payload))
	sigHex := hex.EncodeToString(sig)

	if !VerifySignature(pub, payload, sigHex) {
		t.Error("VerifySignature should accept a valid signature")
	}
	if VerifySignature(pub, "v1|tampered-payload", sigHex) {
		t.Error("VerifySignature should reject a signature over a different payload")
	}
	if VerifySignature(pub, payload, hex.EncodeToString(make([]byte, ed25519.SignatureSize))) {
		t.Error("VerifySignature should reject a garbage signature")
	}
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if VerifySignature(otherPub, payload, sigHex) {
		t.Error("VerifySignature should reject a signature verified against the wrong public key")
	}
}

func TestVerifySignatureRejectsMalformedInput(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	if VerifySignature(pub, "payload", "not-hex-at-all!!") {
		t.Error("VerifySignature should reject non-hex signatures without panicking")
	}
	if VerifySignature(nil, "payload", hex.EncodeToString(make([]byte, ed25519.SignatureSize))) {
		t.Error("VerifySignature should reject a nil public key")
	}
}
