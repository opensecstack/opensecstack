//! Ed25519 signing over the canonical Kerkese payload, matching
//! `citadel/internal/marshal/sig.go`'s `CanonicalPayload`/`VerifySignature`
//! and `sdk/go/citadel/sign.go`'s `Sign` byte-for-byte. Gate 1 (AuthN) and
//! Gate 3 (NDS) check `sig_operator`/`sig_verifier` against this exact
//! scheme when `CITADEL_CITADEL_ENFORCE_SIGNATURES` is on.
//!
//! This is the same convention Runix's own `capability-manager` crate
//! documents and uses (see that crate's `lib.rs` doc comment): plain
//! version-tagged, pipe-joined string concatenation, not canonical-JSON
//! signing — deliberately, to avoid cross-implementation key-ordering/
//! whitespace footguns. Ed25519, hex-encoded signatures, no base64/PEM.

use alloc::format;
use alloc::string::String;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::kerkese::Kerkese;

/// Canonical-form version prefix, matching `sig.go`'s `"v1|"`.
const CANONICAL_VERSION: &str = "v1";

/// Error returned by [`sign`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignError {
    /// `ts_utc` was empty — matches Go's `Sign` rejecting a zero `TsUTC`
    /// (see `sdk/go/citadel/sign.go`'s `TestSignRejectsMissingTimestamp`).
    MissingTimestamp,
}

/// Builds the exact deterministic string Gate 1/Gate 3 verify
/// `sig_operator`/`sig_verifier` against:
///
/// ```text
/// v1|{execution_id}|{action.type}|{action.change_id}|{actor.user_id}|{actor.role}|{verifier.user_id}|{verifier.role}|{sod.operator_user_id}|{sod.verifier_user_id}|{ts_utc}
/// ```
///
/// Byte-for-byte match of `citadel/internal/marshal/sig.go`'s
/// `CanonicalPayload` / `sdk/go/citadel/sign.go`'s `CanonicalPayload` — see
/// this crate's known-answer tests, which reproduce
/// `sig_test.go::TestCanonicalPayloadMatchesSDKFixture`'s exact fixture and
/// expected output.
pub fn canonical_payload(k: &Kerkese) -> String {
    format!(
        "{v}|{exec}|{atype}|{achg}|{auid}|{arole}|{vuid}|{vrole}|{souid}|{svuid}|{ts}",
        v = CANONICAL_VERSION,
        exec = k.execution_id,
        atype = k.action.action_type,
        achg = k.action.change_id,
        auid = k.actor.user_id,
        arole = k.actor.role,
        vuid = k.verifier.user_id,
        vrole = k.verifier.role,
        souid = k.sod.operator_user_id,
        svuid = k.sod.verifier_user_id,
        ts = k.ts_utc,
    )
}

/// Computes [`canonical_payload`] and signs it with both the Operator's and
/// the Verifier's Ed25519 private keys, setting `k.sig_operator` and
/// `k.sig_verifier` (hex-encoded). `k.ts_utc` must already be set (non-empty)
/// before calling — the timestamp is part of the signed payload, so signing
/// before it's finalized would produce a signature that fails verification.
///
/// Matches `sdk/go/citadel/sign.go`'s `Sign`.
pub fn sign(
    k: &mut Kerkese,
    operator: &SigningKey,
    verifier: &SigningKey,
) -> Result<(), SignError> {
    if k.ts_utc.is_empty() {
        return Err(SignError::MissingTimestamp);
    }

    let payload = canonical_payload(k);
    let op_sig: Signature = operator.sign(payload.as_bytes());
    let vf_sig: Signature = verifier.sign(payload.as_bytes());

    k.sig_operator = hex::encode(op_sig.to_bytes());
    k.sig_verifier = hex::encode(vf_sig.to_bytes());
    Ok(())
}

/// Checks that `sig_hex` (a hex-encoded Ed25519 signature) is a valid
/// signature over `payload` by `pub_key`. Returns `false` (never panics or
/// errors) on any malformed input — matching
/// `citadel/internal/marshal/sig.go`'s `VerifySignature`, whose doc comment
/// is explicit that a malformed signature is a verification failure, not a
/// distinct error condition.
pub fn verify_signature(pub_key: &VerifyingKey, payload: &str, sig_hex: &str) -> bool {
    let Ok(sig_bytes) = hex::decode(sig_hex) else {
        return false;
    };
    let Ok(sig_bytes): Result<[u8; 64], _> = sig_bytes.try_into() else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_bytes);
    pub_key.verify(payload.as_bytes(), &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kerkese::{KerkeseAction, KerkeseActor, KerkeseEvidence, KerkeseSoD, KerkeseVerifier};
    use crate::uuid::Uuid;
    use alloc::string::ToString;
    use ed25519_dalek::SigningKey;
    use rand_core::OsRng;

    fn fixture() -> Kerkese {
        // Byte-for-byte the same fixture as
        // citadel/internal/marshal/sig_test.go::TestCanonicalPayloadMatchesSDKFixture
        // and sdk/go/citadel/sign_test.go::fixtureKerkese.
        Kerkese {
            kerkese_version: "1.0".to_string(),
            ts_utc: "2026-07-26T12:00:00Z".to_string(),
            project_id: "apiguard".to_string(),
            execution_id: Uuid::parse("00000000-0000-0000-0000-000000000001").unwrap(),
            action: KerkeseAction {
                action_type: "API_SCAN_INITIATE".to_string(),
                change_id: "chg-1".to_string(),
                ..Default::default()
            },
            actor: KerkeseActor {
                user_id: "101".to_string(),
                role: "operator".to_string(),
                ..Default::default()
            },
            verifier: KerkeseVerifier {
                user_id: "202".to_string(),
                role: "admin".to_string(),
                ..Default::default()
            },
            evidence: KerkeseEvidence::default(),
            sod: KerkeseSoD {
                operator_user_id: "101".to_string(),
                verifier_user_id: "202".to_string(),
            },
            dry_run: false,
            emergency: false,
            emergency_justification: alloc::string::String::new(),
            sig_operator: alloc::string::String::new(),
            sig_verifier: alloc::string::String::new(),
            actor_token: alloc::string::String::new(),
            verifier_token: alloc::string::String::new(),
        }
    }

    /// Known-answer test: reproduces
    /// `sig_test.go::TestCanonicalPayloadMatchesSDKFixture`'s exact expected
    /// string. If this ever fails, this crate's canonical form has drifted
    /// from the Go side and Operator/Verifier signatures built here would be
    /// rejected by real MARSHAL Gate 1/Gate 3 checks.
    #[test]
    fn canonical_payload_matches_go_fixture() {
        let k = fixture();
        let want = "v1|00000000-0000-0000-0000-000000000001|API_SCAN_INITIATE|chg-1|101|operator|202|admin|101|202|2026-07-26T12:00:00Z";
        assert_eq!(canonical_payload(&k), want);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let mut csprng = OsRng;
        let op_key = SigningKey::generate(&mut csprng);
        let vf_key = SigningKey::generate(&mut csprng);

        let mut k = fixture();
        sign(&mut k, &op_key, &vf_key).expect("sign");
        assert!(!k.sig_operator.is_empty());
        assert!(!k.sig_verifier.is_empty());

        let payload = canonical_payload(&k);
        assert!(verify_signature(&op_key.verifying_key(), &payload, &k.sig_operator));
        assert!(verify_signature(&vf_key.verifying_key(), &payload, &k.sig_verifier));

        // Cross-check: operator's signature must NOT verify against the
        // verifier's key, or vice versa (same check as sign_test.go's
        // TestSignRoundTrip).
        assert!(!verify_signature(&vf_key.verifying_key(), &payload, &k.sig_operator));
        assert!(!verify_signature(&op_key.verifying_key(), &payload, &k.sig_verifier));
    }

    #[test]
    fn sign_rejects_missing_timestamp() {
        let mut csprng = OsRng;
        let op_key = SigningKey::generate(&mut csprng);
        let vf_key = SigningKey::generate(&mut csprng);

        let mut k = fixture();
        k.ts_utc = alloc::string::String::new();
        assert_eq!(sign(&mut k, &op_key, &vf_key), Err(SignError::MissingTimestamp));
    }

    #[test]
    fn verify_signature_rejects_malformed_input() {
        let mut csprng = OsRng;
        let key = SigningKey::generate(&mut csprng);
        let pub_key = key.verifying_key();

        assert!(!verify_signature(&pub_key, "payload", "not-hex-at-all!!"));
        assert!(!verify_signature(&pub_key, "payload", "deadbeef")); // too short
        assert!(!verify_signature(&pub_key, "payload", &"00".repeat(64))); // garbage, valid length
    }
}
