//! Webhook support — HMAC-SHA256 signature verification and event parsing.
//!
//! # Receiving webhooks
//!
//! All opensecstack platforms (`APIGuard`, NIS2 Compass, CITADEL) sign webhook
//! payloads with an HMAC-SHA256 digest delivered via the
//! `X-APIGuard-Signature` or `X-Citadel-Signature` HTTP header, in the
//! format `"sha256=<hex_digest>"`.
//!
//! ## Axum example
//!
//! ```ignore
//! use axum::{extract::State, routing::post, Router};
//! use axum::http::HeaderMap;
//! use bytes::Bytes;
//! use opensecstack::webhook::{parse_event, verify_signature, EVENT_APIGUARD_SCAN_COMPLETED};
//!
//! #[tokio::main]
//! async fn main() {
//!     let app = Router::new()
//!         .route("/webhooks", post(webhook_handler))
//!         .with_state("my-webhook-secret".to_string());
//!
//!     axum::serve(
//!         tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap(),
//!         app,
//!     )
//!     .await
//!     .unwrap();
//! }
//!
//! async fn webhook_handler(
//!     State(secret): State<String>,
//!     headers: HeaderMap,
//!     body: Bytes,
//! ) -> axum::http::StatusCode {
//!     let sig = headers
//!         .get("x-apiguard-signature")
//!         .or_else(|| headers.get("x-citadel-signature"))
//!         .and_then(|v| v.to_str().ok())
//!         .unwrap_or("");
//!
//!     if verify_signature(&body, sig, &secret).is_err() {
//!         return axum::http::StatusCode::BAD_REQUEST;
//!     }
//!
//!     match parse_event(&body) {
//!         Ok(event) => {
//!             match event.event_type.as_str() {
//!                 EVENT_APIGUARD_SCAN_COMPLETED => println!("scan done: {}", event.id),
//!                 _ => {}
//!             }
//!             axum::http::StatusCode::OK
//!         }
//!         Err(_) => axum::http::StatusCode::UNPROCESSABLE_ENTITY,
//!     }
//! }
//! ```

use crate::error::{Error, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Event type constants
// ---------------------------------------------------------------------------

/// Emitted when an `APIGuard` scan finishes successfully.
pub const EVENT_APIGUARD_SCAN_COMPLETED: &str = "apiguard.scan.completed";

/// Emitted when an `APIGuard` scan fails (parse error, unreachable target, etc.).
pub const EVENT_APIGUARD_SCAN_FAILED: &str = "apiguard.scan.failed";

/// Emitted immediately when a critical-severity finding is detected.
pub const EVENT_APIGUARD_FINDING_CRITICAL: &str = "apiguard.finding.critical";

/// Emitted when a NIS2 Compass control status changes.
pub const EVENT_NIS2COMPASS_CONTROL_UPDATED: &str = "nis2compass.control.updated";

/// Emitted when all controls in a NIS2 Compass assessment reach a terminal status.
pub const EVENT_NIS2COMPASS_ASSESSMENT_COMPLETED: &str = "nis2compass.assessment.completed";

/// Emitted immediately on any CITADEL HARD STOP outcome.
pub const EVENT_CITADEL_HARD_STOP: &str = "citadel.hard_stop";

/// Emitted when CITADEL VIGIL transitions to RED.
pub const EVENT_CITADEL_VIGIL_RED: &str = "citadel.vigil_red";

/// Emitted when CITADEL VIGIL transitions to AMBER.
pub const EVENT_CITADEL_VIGIL_AMBER: &str = "citadel.vigil_amber";

// ---------------------------------------------------------------------------
// Event envelope
// ---------------------------------------------------------------------------

/// The common envelope wrapping all incoming platform webhook events.
///
/// The `payload` field contains event-specific data and can be further
/// deserialised with `serde_json::from_value`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WebhookEvent {
    /// Unique event identifier, e.g. `"evt_01HX..."`.
    pub id: String,

    /// One of the `EVENT_*` constants defined in this module.
    pub event_type: String,

    /// Platform that emitted the event: `"apiguard"`, `"nis2compass"`, or `"citadel"`.
    pub source: String,

    /// UTC timestamp of when the event was created on the platform.
    pub timestamp: DateTime<Utc>,

    /// Event-specific data. Use `serde_json::from_value(event.payload.clone())`
    /// to deserialise into a typed struct.
    pub payload: serde_json::Value,

    /// The raw `"sha256=<hex>"` signature that was present in the JSON
    /// envelope (may differ from the transport-layer header).
    #[serde(default)]
    pub signature: String,
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Verify the HMAC-SHA256 signature of a webhook request body.
///
/// # Arguments
///
/// * `body`      – Raw request body bytes (before any decoding).
/// * `signature` – Value of the `X-APIGuard-Signature` or
///   `X-Citadel-Signature` header.  Must be in the form
///   `"sha256=<hex_digest>"`.
/// * `secret`    – The shared webhook secret configured on the platform.
///
/// # Errors
///
/// Returns [`Error::UnexpectedResponse`] if the `signature` string does not
/// start with `"sha256="`, or [`Error::Api`] with status 401 and code
/// `"INVALID_SIGNATURE"` if the HMAC does not match.
///
/// # Constant-time comparison
///
/// The hex strings are compared byte-by-byte with a bitwise-OR accumulator
/// so that the comparison time does not reveal how many bytes match.
pub fn verify_signature(body: &[u8], signature: &str, secret: &str) -> Result<()> {
    type HmacSha256 = Hmac<Sha256>;

    let sig_hex = signature.strip_prefix("sha256=").ok_or_else(|| {
        Error::UnexpectedResponse(
            "webhook signature must be in the format 'sha256=<hex_digest>'".to_string(),
        )
    })?;

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|e| Error::UnexpectedResponse(e.to_string()))?;
    mac.update(body);
    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison — fold XOR of every byte pair.
    let mismatch = sig_hex.len() != expected.len()
        || sig_hex
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            != 0;

    if mismatch {
        return Err(Error::Api {
            status: 401,
            code: "INVALID_SIGNATURE".to_string(),
            message: "webhook HMAC-SHA256 signature verification failed".to_string(),
        });
    }

    Ok(())
}

/// Parse a [`WebhookEvent`] from raw JSON bytes.
///
/// Call this only *after* [`verify_signature`] succeeds so that you are
/// always working with authenticated data.
///
/// # Errors
///
/// Returns [`Error::Json`] if the body is not valid JSON or the envelope
/// is missing required fields.
pub fn parse_event(body: &[u8]) -> Result<WebhookEvent> {
    serde_json::from_slice(body).map_err(Error::Json)
}
