//! MARSHAL's response to a submitted Kerkese, matching
//! `citadel/internal/marshal/types.go`'s `Decision`/`GateResult` structs and
//! the `Outcome*`/`Gate*` string constants defined alongside them.

use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::uuid::Uuid;

/// `outcome` — matches `types.go`'s `OutcomeExecute`/`OutcomeRefuse`/
/// `OutcomeHardStop` constants (`"EXECUTE"`/`"REFUSE"`/`"HARD_STOP"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome {
    Execute,
    Refuse,
    HardStop,
}

impl Outcome {
    /// `true` for [`Outcome::Refuse`] and [`Outcome::HardStop`] — i.e.
    /// "the caller must not proceed with the action". Mirrors
    /// `handlers/marshal.go`'s HTTP status mapping (both outcomes map to
    /// `403 Forbidden`).
    pub fn is_blocked(&self) -> bool {
        !matches!(self, Outcome::Execute)
    }
}

/// A single gate's `status` — matches `types.go`'s `GatePass`/`GateFail`/
/// `GateWarn`/`GateHardStop` constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GateStatus {
    Pass,
    Fail,
    Warn,
    HardStop,
}

/// One gate's evaluation result within a [`Decision`]. Matches `types.go`'s
/// `GateResult`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateResult {
    pub gate: i32,
    pub name: String,
    pub status: GateStatus,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    pub latency_ms: f64,
}

/// MARSHAL's decision for a submitted Kerkese. Matches `types.go`'s
/// `Decision`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub outcome: Outcome,
    pub execution_id: Uuid,
    /// `types.go` types this `*uuid.UUID` (a pointer, so JSON `null`/absent
    /// when Gate 5 (WORM) didn't run — e.g. `dry_run`). Note:
    /// `docs/kerkese-spec.md`'s worked example shows `"worm_entry_id":
    /// "wo_0000017234"`, a non-UUID string shape — that doc appears stale
    /// relative to the real Go struct. This crate follows `types.go` (the
    /// authoritative source per this task's instructions), not the doc's
    /// example; flagged explicitly rather than silently picking one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worm_entry_id: Option<Uuid>,
    pub gates: Vec<GateResult>,
    pub reasons: Vec<String>,
    /// RFC3339 UTC timestamp string — see [`crate::Kerkese::ts_utc`]'s doc
    /// comment for why this crate carries timestamps as pre-formatted
    /// strings rather than a parsed type.
    pub ts_utc: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub dry_run: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;

    #[test]
    fn parses_execute_decision_from_kerkese_spec_shape() {
        // Adapted from docs/kerkese-spec.md's "Decision response" example,
        // with worm_entry_id as a UUID (per types.go) rather than the doc's
        // "wo_..." string, since that field is documented above as stale.
        let json = r#"{
            "execution_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98",
            "outcome":      "EXECUTE",
            "dry_run":      false,
            "ts_utc":       "2026-04-19T10:12:03Z",
            "gates": [
                { "gate": 1, "name": "AuthN", "status": "PASS", "latency_ms": 0.84 },
                { "gate": 2, "name": "AuthZ", "status": "PASS", "latency_ms": 0.21 },
                { "gate": 3, "name": "NDS",   "status": "PASS", "latency_ms": 1.12 },
                { "gate": 4, "name": "AUGUR", "status": "PASS", "latency_ms": 1.43 },
                { "gate": 5, "name": "WORM",  "status": "PASS", "latency_ms": 4.22 }
            ],
            "reasons": [],
            "worm_entry_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a99"
        }"#;

        let d: Decision = serde_json::from_str(json).expect("decode decision");
        assert_eq!(d.outcome, Outcome::Execute);
        assert!(!d.outcome.is_blocked());
        assert_eq!(d.gates.len(), 5);
        assert_eq!(d.gates[0].status, GateStatus::Pass);
        assert!(d.worm_entry_id.is_some());
        assert!(d.reasons.is_empty());
    }

    #[test]
    fn refuse_and_hard_stop_are_blocked() {
        assert!(Outcome::Refuse.is_blocked());
        assert!(Outcome::HardStop.is_blocked());
        assert!(!Outcome::Execute.is_blocked());
    }

    #[test]
    fn outcome_serializes_to_screaming_snake_case() {
        assert_eq!(serde_json::to_string(&Outcome::HardStop).unwrap(), "\"HARD_STOP\"");
        assert_eq!(serde_json::to_string(&Outcome::Refuse).unwrap(), "\"REFUSE\"");
    }

    #[test]
    fn worm_entry_id_absent_when_none() {
        let d = Decision {
            outcome: Outcome::Refuse,
            execution_id: Uuid::from_bytes([1; 16]),
            worm_entry_id: None,
            gates: vec![],
            reasons: vec!["gate2: rbac deny".to_string()],
            ts_utc: "2026-04-19T10:12:03Z".to_string(),
            dry_run: true,
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(!json.contains("worm_entry_id"));
    }
}
