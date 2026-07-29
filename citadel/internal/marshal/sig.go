package marshal

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"
)

// CanonicalPayload builds the deterministic string that Gate 1/Gate 3
// verify SigOperator/SigVerifier against. This MUST stay byte-identical to
// sdk/go/citadel.CanonicalPayload — see sig_test.go's fixtures, which are
// shared (by value) with sdk/go/citadel/sign_test.go's fixtures.
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

// VerifySignature checks that sigHex (hex-encoded Ed25519 signature) is a
// valid signature over payload by pub. Returns false (never panics) on any
// malformed input — a malformed signature is a verification failure, not an
// error condition the caller needs to distinguish.
func VerifySignature(pub ed25519.PublicKey, payload, sigHex string) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, []byte(payload), sig)
}
