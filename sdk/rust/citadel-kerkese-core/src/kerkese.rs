//! The Kerkese envelope, matching `citadel/internal/marshal/types.go`'s
//! `Kerkese` struct field-for-field (see that file's doc comment: "Field
//! names mirror apiguard/internal/citadel/types.go exactly").
//!
//! One deliberate deviation from the Go struct, called out explicitly
//! (see [`Kerkese::ts_utc`]): `ts_utc` is carried as an already-formatted
//! RFC3339 UTC string rather than a parsed timestamp type, so this crate
//! doesn't need a no_std-compatible clock/calendar library just to
//! round-trip a JSON field. The caller (which, for a no_std kernel host,
//! already has to source wall-clock time from somewhere host-specific) is
//! responsible for formatting it correctly — [`Kerkese::ts_utc`]'s docs spell
//! out the exact required shape.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::uuid::Uuid;

/// The full Kerkese governance request envelope.
///
/// Field-for-field match of `citadel/internal/marshal/types.go`'s `Kerkese`
/// struct (JSON v2.0 shape — the version that added `evidence`, `sod`,
/// `dry_run`, `emergency*`, `sig_operator`/`sig_verifier`, and
/// `actor_token`/`verifier_token` on top of the older v1 shape documented in
/// `docs/kerkese-spec.md`, which is stale relative to the real Go struct —
/// see this crate's top-level report for the specific fields that drifted).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Kerkese {
    pub kerkese_version: String,

    /// RFC3339 UTC timestamp, e.g. `"2026-07-26T12:00:00Z"` — i.e. exactly
    /// what Go's `time.Time.UTC().Format(time.RFC3339)` produces for a
    /// whole-second timestamp (no fractional seconds, `Z` suffix, not
    /// `+00:00`). [`crate::sign::canonical_payload`] uses this string
    /// verbatim, so it MUST already be normalized this way — this crate does
    /// not parse or reformat it.
    pub ts_utc: String,

    pub project_id: String,
    pub execution_id: Uuid,
    pub action: KerkeseAction,
    pub actor: KerkeseActor,
    pub verifier: KerkeseVerifier,
    pub evidence: KerkeseEvidence,
    pub sod: KerkeseSoD,

    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub emergency: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub emergency_justification: String,

    /// Hex-encoded Ed25519 signature over
    /// [`crate::sign::canonical_payload`], produced by the Operator. See
    /// `sig_operator` in `types.go` and [`crate::sign::sign`].
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_operator: String,
    /// As [`Kerkese::sig_operator`], but produced by the Verifier.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sig_verifier: String,

    /// sinauth-issued RS256 bearer token proving the Operator's identity.
    /// This crate does not verify or introspect it — it is opaque,
    /// server-verified evidence passed through as-is.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub actor_token: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub verifier_token: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KerkeseAction {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub change_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub incident_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub root_cause: String,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "corrective_action")]
    pub corrective_act: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KerkeseActor {
    /// The sinauth subject — a UUID string, per `types.go`'s doc comment on
    /// `KerkeseActor.UserID` ("UserID is the sinauth subject (UUID
    /// string)"). Deliberately a plain `String` here, not [`Uuid`]: unlike
    /// `execution_id`/`worm_entry_id`, `types.go` types this field `string`,
    /// not `uuid.UUID` — matching the Go field type exactly, not "what it
    /// semantically is", per the task's instruction to match the real Go
    /// types rather than guess.
    pub user_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KerkeseVerifier {
    pub user_id: String,
    pub role: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub email: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KerkeseEvidence {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub change_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<EvidenceArtifact>,
    #[serde(default, skip_serializing_if = "String::is_empty", rename = "drill_reference")]
    pub drill_ref: String,
    /// `map[string]any` on the Go side. Represented as arbitrary JSON here
    /// rather than typed — `types.go` itself types it `any`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EvidenceArtifact {
    pub hash: String,
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub label: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct KerkeseSoD {
    pub operator_user_id: String,
    pub verifier_user_id: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn fixture() -> Kerkese {
        // Mirrors citadel/internal/marshal/sig_test.go's `TestCanonicalPayloadMatchesSDKFixture`
        // fixture (and sdk/go/citadel/sign_test.go's identical `fixtureKerkese`).
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
            emergency_justification: String::new(),
            sig_operator: String::new(),
            sig_verifier: String::new(),
            actor_token: String::new(),
            verifier_token: String::new(),
        }
    }

    #[test]
    fn round_trips_through_json() {
        let k = fixture();
        let json = serde_json::to_vec(&k).expect("serialize");
        let back: Kerkese = serde_json::from_slice(&json).expect("deserialize");
        assert_eq!(k, back);
    }

    #[test]
    fn optional_fields_are_omitted_when_empty() {
        let k = fixture();
        let json = serde_json::to_string(&k).expect("serialize");
        assert!(!json.contains("sig_operator"));
        assert!(!json.contains("dry_run"));
        assert!(!json.contains("emergency"));
        assert!(!json.contains("actor_token"));
    }

    #[test]
    fn action_type_field_is_renamed_to_type() {
        let k = fixture();
        let json = serde_json::to_string(&k).expect("serialize");
        assert!(json.contains("\"type\":\"API_SCAN_INITIATE\""));
    }
}
