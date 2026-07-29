package citadel

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixtureKerkese() Kerkese {
	return Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC),
		ProjectID:      "apiguard",
		ExecutionID:    uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Action:         KerkeseAction{Type: "API_SCAN_INITIATE", ChangeID: "chg-1"},
		Actor:          KerkeseActor{UserID: "101", Role: "operator"},
		Verifier:       KerkeseVerifier{UserID: "202", Role: "admin"},
		SoD:            KerkeseSoD{OperatorUserID: "101", VerifierUserID: "202"},
	}
}

func TestCanonicalPayloadDeterministic(t *testing.T) {
	k := fixtureKerkese()
	p1 := CanonicalPayload(k)
	p2 := CanonicalPayload(k)
	if p1 != p2 {
		t.Fatalf("CanonicalPayload is not deterministic: %q != %q", p1, p2)
	}

	const want = "v1|00000000-0000-0000-0000-000000000001|API_SCAN_INITIATE|chg-1|101|operator|202|admin|101|202|2026-07-26T12:00:00Z"
	if p1 != want {
		t.Fatalf("CanonicalPayload = %q, want %q", p1, want)
	}
}

func TestCanonicalPayloadChangesWithFields(t *testing.T) {
	base := fixtureKerkese()
	modified := base
	modified.Action.Type = "API_SCAN_DELETE"

	if CanonicalPayload(base) == CanonicalPayload(modified) {
		t.Fatalf("CanonicalPayload did not change when action.type changed")
	}
}

func TestSignRoundTrip(t *testing.T) {
	opPub, opPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating operator key: %v", err)
	}
	vfPub, vfPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating verifier key: %v", err)
	}

	k := fixtureKerkese()
	if err := Sign(&k, opPriv, vfPriv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if k.SigOperator == "" || k.SigVerifier == "" {
		t.Fatalf("Sign did not populate signatures: %+v", k)
	}

	payload := []byte(CanonicalPayload(k))
	opSig, err := hex.DecodeString(k.SigOperator)
	if err != nil {
		t.Fatalf("decoding operator sig: %v", err)
	}
	vfSig, err := hex.DecodeString(k.SigVerifier)
	if err != nil {
		t.Fatalf("decoding verifier sig: %v", err)
	}

	if !ed25519.Verify(opPub, payload, opSig) {
		t.Errorf("operator signature does not verify against operator public key")
	}
	if !ed25519.Verify(vfPub, payload, vfSig) {
		t.Errorf("verifier signature does not verify against verifier public key")
	}
	// Cross-check: operator's signature must NOT verify against the
	// verifier's key, or vice versa — otherwise the two roles aren't
	// actually cryptographically distinct.
	if ed25519.Verify(vfPub, payload, opSig) {
		t.Errorf("operator signature unexpectedly verifies against verifier public key")
	}
}

func TestSignRejectsMissingTimestamp(t *testing.T) {
	_, opPriv, _ := ed25519.GenerateKey(nil)
	_, vfPriv, _ := ed25519.GenerateKey(nil)

	k := fixtureKerkese()
	k.TsUTC = time.Time{}
	if err := Sign(&k, opPriv, vfPriv); err == nil {
		t.Fatalf("Sign should reject a Kerkese with a zero TsUTC")
	}
}
