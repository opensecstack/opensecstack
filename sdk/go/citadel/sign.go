package citadel

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"
)

// CanonicalPayload builds the deterministic, fixed-field string that both
// the Operator and the Verifier sign, and that CITADEL re-derives on the
// server side to verify SigOperator/SigVerifier. It is intentionally NOT
// full-JSON canonicalization (key ordering / whitespace canonicalization is
// a recurring source of cross-implementation signature bugs); it is a
// pipe-joined string over a small, enumerable set of fields.
//
// Format (version-tagged so the scheme can evolve without ambiguity):
//
//	v1|{execution_id}|{action.type}|{action.change_id}|{actor.user_id}|{actor.role}|{verifier.user_id}|{verifier.role}|{sod.operator_user_id}|{sod.verifier_user_id}|{ts_utc RFC3339}
//
// citadel/internal/marshal/sig.go MUST produce byte-identical output for the
// same Kerkese — see sdk/go/citadel/sign_test.go and
// citadel/internal/marshal/sig_test.go, which cross-check both
// implementations against the same fixtures.
func CanonicalPayload(k Kerkese) string {
	return "v1|" +
		k.ExecutionID.String() + "|" +
		k.Action.Type + "|" +
		k.Action.ChangeID + "|" +
		k.Actor.UserID + "|" +
		k.Actor.Role + "|" +
		k.Verifier.UserID + "|" +
		k.Verifier.Role + "|" +
		k.SoD.OperatorUserID + "|" +
		k.SoD.VerifierUserID + "|" +
		k.TsUTC.UTC().Format(time.RFC3339)
}

// Sign computes CanonicalPayload(*k) and signs it with both the operator's
// and the verifier's Ed25519 private keys, setting k.SigOperator and
// k.SigVerifier (hex-encoded). k.TsUTC must already be set before calling
// Sign — the timestamp is part of the signed payload, so signing before the
// final timestamp is assigned would produce a signature that fails
// verification.
func Sign(k *Kerkese, operatorPriv, verifierPriv ed25519.PrivateKey) error {
	if len(operatorPriv) != ed25519.PrivateKeySize {
		return fmt.Errorf("citadel: Sign: operator private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(operatorPriv))
	}
	if len(verifierPriv) != ed25519.PrivateKeySize {
		return fmt.Errorf("citadel: Sign: verifier private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(verifierPriv))
	}
	if k.TsUTC.IsZero() {
		return fmt.Errorf("citadel: Sign: Kerkese.TsUTC must be set before signing")
	}

	payload := []byte(CanonicalPayload(*k))
	k.SigOperator = hex.EncodeToString(ed25519.Sign(operatorPriv, payload))
	k.SigVerifier = hex.EncodeToString(ed25519.Sign(verifierPriv, payload))
	return nil
}
