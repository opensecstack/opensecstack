//! Tests for the webhook signature verification and event parsing utilities.

use hmac::{Hmac, Mac};
use opensecstack::webhook::{
    parse_event, verify_signature, WebhookEvent, EVENT_APIGUARD_SCAN_COMPLETED,
    EVENT_CITADEL_HARD_STOP,
};
use sha2::Sha256;

// ---------------------------------------------------------------------------
// Helper — produce a "sha256=<hex>" signature for a body + secret pair
// ---------------------------------------------------------------------------

fn sign(body: &[u8], secret: &str) -> String {
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

// ---------------------------------------------------------------------------
// 1. verify_signature — valid signature succeeds
// ---------------------------------------------------------------------------

#[test]
fn test_verify_signature_valid() {
    let secret = "test-webhook-secret";
    let body = br#"{"id":"evt_001","event_type":"apiguard.scan.completed"}"#;
    let sig = sign(body, secret);

    verify_signature(body, &sig, secret)
        .expect("valid signature should not return an error");
}

// ---------------------------------------------------------------------------
// 2. verify_signature — wrong secret returns an error
// ---------------------------------------------------------------------------

#[test]
fn test_verify_signature_invalid_secret() {
    let body = br#"{"id":"evt_002","event_type":"apiguard.scan.failed"}"#;
    let sig = sign(body, "correct-secret");

    let result = verify_signature(body, &sig, "wrong-secret");
    assert!(result.is_err(), "wrong secret should return Err");

    let err_str = result.unwrap_err().to_string();
    assert!(
        err_str.contains("INVALID_SIGNATURE") || err_str.contains("401"),
        "unexpected error message: {err_str}"
    );
}

#[test]
fn test_verify_signature_tampered_body() {
    let secret = "tamper-secret";
    let original = br#"{"id":"evt_003","event_type":"citadel.hard_stop"}"#;
    let sig = sign(original, secret);

    let tampered = br#"{"id":"evt_003","event_type":"citadel.vigil_red"}"#;
    let result = verify_signature(tampered, &sig, secret);
    assert!(result.is_err(), "tampered body should not verify");
}

#[test]
fn test_verify_signature_missing_prefix() {
    let body = br#"{"id":"evt_004"}"#;
    // Provide raw hex without "sha256=" prefix.
    let raw_hex = {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(b"s").unwrap();
        mac.update(body);
        hex::encode(mac.finalize().into_bytes())
    };
    let result = verify_signature(body, &raw_hex, "s");
    assert!(result.is_err(), "signature without 'sha256=' prefix should fail");
}

// ---------------------------------------------------------------------------
// 3. parse_event — valid JSON deserialises correctly
// ---------------------------------------------------------------------------

#[test]
fn test_parse_event_valid() {
    let body = serde_json::json!({
        "id": "evt_parse_001",
        "event_type": EVENT_APIGUARD_SCAN_COMPLETED,
        "source": "apiguard",
        "timestamp": "2026-03-30T14:05:00Z",
        "payload": {
            "scan_id": "scan-abc",
            "target": "https://api.example.com",
            "status": "completed"
        },
        "signature": "sha256=abc123"
    });

    let raw = serde_json::to_vec(&body).unwrap();
    let event: WebhookEvent = parse_event(&raw).expect("should parse valid event");

    assert_eq!(event.id, "evt_parse_001");
    assert_eq!(event.event_type, EVENT_APIGUARD_SCAN_COMPLETED);
    assert_eq!(event.source, "apiguard");
    assert_eq!(event.payload["scan_id"], "scan-abc");
}

#[test]
fn test_parse_event_invalid_json() {
    let bad = b"not json at all {{{";
    let result = parse_event(bad);
    assert!(result.is_err(), "invalid JSON should return Err");
}

// ---------------------------------------------------------------------------
// 4. Constant-time comparison — both matching and mismatching branches
// ---------------------------------------------------------------------------

#[test]
fn test_constant_time_matching_branch() {
    // Both branches of the fold accumulator should be exercised.
    // This test ensures the "all bytes equal → 0" path returns Ok.
    let secret = "ct-secret";
    let body = b"constant time body payload";
    let sig = sign(body, secret);

    let result = verify_signature(body, &sig, secret);
    assert!(result.is_ok(), "identical signatures should verify: {:?}", result);
}

#[test]
fn test_constant_time_mismatching_branch() {
    // Ensures the "at least one byte differs → non-zero" path returns Err.
    let secret = "ct-secret";
    let body = b"constant time body payload";
    // Flip the last character of a valid signature to force mismatch.
    let mut sig = sign(body, secret);
    let last = sig.pop().unwrap();
    sig.push(if last == 'a' { 'b' } else { 'a' });

    let result = verify_signature(body, &sig, secret);
    assert!(result.is_err(), "modified signature should not verify");
}

// ---------------------------------------------------------------------------
// 5. Event type constants — spot-check values
// ---------------------------------------------------------------------------

#[test]
fn test_event_type_constant_values() {
    assert_eq!(EVENT_APIGUARD_SCAN_COMPLETED, "apiguard.scan.completed");
    assert_eq!(EVENT_CITADEL_HARD_STOP, "citadel.hard_stop");
}
