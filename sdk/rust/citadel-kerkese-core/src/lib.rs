//! `no_std` + `alloc` core for building, signing, and submitting CITADEL
//! MARSHAL Kerkese requests — for hosts that can't pull in Tokio/reqwest
//! (a `no_std`, freestanding kernel target being the motivating case; see
//! [opensecstack/opensecstack#34](https://github.com/opensecstack/opensecstack/issues/34)).
//!
//! This is deliberately **additive**, not a replacement for
//! [`opensecstack::citadel::CITADELClient`](../../../src/citadel/mod.rs) —
//! that client is an async, Tokio+reqwest WORM *event-delivery* client
//! (`send_event`/`get_events`/`verify_chain`); it does not submit Kerkeses
//! for MARSHAL evaluation at all, and (being `std`+Tokio) can't compile for
//! a freestanding kernel target regardless. This crate is a separate,
//! narrower thing: Kerkese envelope construction + Ed25519 signing +
//! Decision parsing, with zero networking of its own.
//!
//! # Design: no I/O in this crate
//!
//! Following the same split Substrate's `sp-runtime-interface`/`sp-io` use
//! for the analogous problem (a deterministic `no_std` core that needs a
//! host-provided I/O primitive): this crate declares [`KerkeseTransport`],
//! the *shape* of "submit these bytes, get a Decision's bytes back" —
//! it never implements HTTP/TLS/sockets. A caller supplies the real
//! transport: Runix's kernel directly (over whatever kernel-mode network
//! stack it has), or a hosted async process (wrapping `reqwest` and
//! blocking on it inside `submit`).
//!
//! # Timestamps are caller-formatted strings, not a parsed type
//!
//! [`Kerkese::ts_utc`] and [`Decision::ts_utc`] are plain `String`s, already
//! in RFC3339 UTC form (e.g. `"2026-07-26T12:00:00Z"`) — see
//! [`Kerkese::ts_utc`]'s doc comment. This crate does not depend on any
//! clock/calendar library; a no_std freestanding kernel already has to
//! source wall-clock time from somewhere host-specific, so asking the
//! caller to format it is strictly less machinery than vendoring a second
//! no_std time implementation here.
//!
//! # What's verified vs. guessed
//!
//! The Kerkese/Decision JSON shape and the Ed25519 canonicalization scheme
//! are matched against `citadel/internal/marshal/types.go` and
//! `citadel/internal/marshal/sig.go` directly (see doc comments on
//! [`kerkese::Kerkese`], [`decision::Decision`], and
//! [`sign::canonical_payload`] for the specific fields/lines), and the
//! signing scheme is cross-checked with a known-answer test reproducing
//! `citadel/internal/marshal/sig_test.go`'s exact fixture and expected
//! output (see `sign::tests::canonical_payload_matches_go_fixture`). The one
//! explicit, flagged deviation is `worm_entry_id`'s shape — see
//! [`decision::Decision::worm_entry_id`]'s doc comment for the
//! doc-vs-code discrepancy found while writing this crate.

#![no_std]

extern crate alloc;

pub mod decision;
pub mod error;
pub mod kerkese;
pub mod sign;
pub mod transport;
pub mod uuid;

pub use decision::{Decision, GateResult, GateStatus, Outcome};
pub use error::KerkeseError;
pub use kerkese::{EvidenceArtifact, Kerkese, KerkeseAction, KerkeseActor, KerkeseEvidence, KerkeseSoD, KerkeseVerifier};
pub use sign::{canonical_payload, sign, verify_signature, SignError};
pub use transport::{KerkeseTransport, TransportError};
pub use uuid::Uuid;

use alloc::vec::Vec;

/// Serializes `kerkese` to JSON, hands it to `transport`, and parses the
/// response as a [`Decision`].
///
/// This is the one place this crate calls into the caller-supplied
/// [`KerkeseTransport`] — everything else in this crate (envelope
/// construction, signing, decision parsing) is pure and I/O-free.
pub fn submit_kerkese<T: KerkeseTransport>(
    transport: &T,
    kerkese: &Kerkese,
) -> Result<Decision, KerkeseError> {
    let body: Vec<u8> =
        serde_json::to_vec(kerkese).map_err(|e| KerkeseError::Encode(alloc::format!("{e}")))?;
    let response = transport.submit(&body).map_err(KerkeseError::Transport)?;
    serde_json::from_slice(&response).map_err(|e| KerkeseError::Decode(alloc::format!("{e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec::Vec;

    /// A fake in-memory transport for testing `submit_kerkese` without any
    /// real networking — exactly the kind of thing a unit test is expected
    /// to supply in place of a real `KerkeseTransport`.
    struct FakeTransport {
        response: Vec<u8>,
    }

    impl KerkeseTransport for FakeTransport {
        fn submit(&self, _envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
            Ok(self.response.clone())
        }
    }

    fn fixture_kerkese() -> Kerkese {
        Kerkese {
            kerkese_version: "1.0".to_string(),
            ts_utc: "2026-07-26T12:00:00Z".to_string(),
            project_id: "apiguard".to_string(),
            execution_id: Uuid::from_bytes([0; 16]),
            action: KerkeseAction {
                action_type: "API_SCAN_INITIATE".to_string(),
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

    #[test]
    fn submit_kerkese_round_trips_through_fake_transport() {
        let decision_json = r#"{
            "execution_id": "00000000-0000-0000-0000-000000000000",
            "outcome": "EXECUTE",
            "gates": [],
            "reasons": [],
            "ts_utc": "2026-07-26T12:00:01Z"
        }"#;
        let transport = FakeTransport {
            response: decision_json.as_bytes().to_vec(),
        };

        let decision = submit_kerkese(&transport, &fixture_kerkese()).expect("submit");
        assert_eq!(decision.outcome, Outcome::Execute);
    }

    #[test]
    fn submit_kerkese_surfaces_transport_error() {
        struct FailingTransport;
        impl KerkeseTransport for FailingTransport {
            fn submit(&self, _envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
                Err(TransportError::Unreachable("no route".to_string()))
            }
        }

        let err = submit_kerkese(&FailingTransport, &fixture_kerkese()).unwrap_err();
        assert_eq!(
            err,
            KerkeseError::Transport(TransportError::Unreachable("no route".to_string()))
        );
    }

    #[test]
    fn submit_kerkese_surfaces_decode_error_on_garbage_response() {
        let transport = FakeTransport {
            response: b"not json".to_vec(),
        };
        let err = submit_kerkese(&transport, &fixture_kerkese()).unwrap_err();
        assert!(matches!(err, KerkeseError::Decode(_)));
    }
}
