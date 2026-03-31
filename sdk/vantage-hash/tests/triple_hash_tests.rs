use vantage_hash::{tds::Tier, Error, TripleHash};
use std::time::Duration;

// ── compute + basic shape ─────────────────────────────────────────────────────

#[test]
fn compute_returns_128_byte_digest() {
    let h = TripleHash::compute(b"hello");
    assert_eq!(h.as_bytes().len(), 128);
}

#[test]
fn hex_is_256_chars() {
    let h = TripleHash::compute(b"hello");
    assert_eq!(h.hex().len(), 256);
}

#[test]
fn blake3_hex_is_64_chars() {
    let h = TripleHash::compute(b"hello");
    assert_eq!(h.blake3_hex().len(), 64);
}

#[test]
fn sha256_hex_is_64_chars() {
    let h = TripleHash::compute(b"hello");
    assert_eq!(h.sha256_hex().len(), 64);
}

#[test]
fn sha512_hex_is_128_chars() {
    let h = TripleHash::compute(b"hello");
    assert_eq!(h.sha512_hex().len(), 128);
}

// ── verify ────────────────────────────────────────────────────────────────────

#[test]
fn verify_passes_same_content() {
    let content = b"verify me";
    let h = TripleHash::compute(content);
    assert!(TripleHash::verify(content, &h));
}

#[test]
fn verify_fails_tampered_content() {
    let h = TripleHash::compute(b"original");
    assert!(!TripleHash::verify(b"tampered", &h));
}

#[test]
fn verify_fails_empty_vs_nonempty() {
    let h = TripleHash::compute(b"data");
    assert!(!TripleHash::verify(b"", &h));
}

// ── determinism ───────────────────────────────────────────────────────────────

#[test]
fn same_input_same_output() {
    let h1 = TripleHash::compute(b"same");
    let h2 = TripleHash::compute(b"same");
    assert_eq!(h1, h2);
}

#[test]
fn different_inputs_different_hashes() {
    let h1 = TripleHash::compute(b"foo");
    let h2 = TripleHash::compute(b"bar");
    assert_ne!(h1, h2);
}

// ── edge cases ────────────────────────────────────────────────────────────────

#[test]
fn empty_input_works() {
    let h = TripleHash::compute(b"");
    assert_eq!(h.hex().len(), 256);
    assert!(TripleHash::verify(b"", &h));
}

#[test]
fn large_input_works() {
    let data = vec![0xABu8; 1024 * 1024]; // 1 MiB
    let h = TripleHash::compute(&data);
    assert_eq!(h.hex().len(), 256);
    assert!(TripleHash::verify(&data, &h));
}

#[test]
fn single_byte_flip_fails_verify() {
    let mut data = vec![0u8; 64];
    let h = TripleHash::compute(&data);
    data[0] ^= 0x01; // flip one bit
    assert!(!TripleHash::verify(&data, &h));
}

// ── component cross-checks ────────────────────────────────────────────────────

#[test]
fn sha256_component_matches_standalone() {
    use sha2::{Digest, Sha256};
    let content = b"cross-check sha256";
    let h = TripleHash::compute(content);
    let expected = hex::encode(Sha256::digest(content));
    assert_eq!(h.sha256_hex(), expected);
}

#[test]
fn sha512_component_matches_standalone() {
    use sha2::{Digest, Sha512};
    let content = b"cross-check sha512";
    let h = TripleHash::compute(content);
    let expected = hex::encode(Sha512::digest(content));
    assert_eq!(h.sha512_hex(), expected);
}

#[test]
fn blake3_component_matches_standalone() {
    let content = b"cross-check blake3";
    let h = TripleHash::compute(content);
    let expected = hex::encode(blake3::hash(content).as_bytes());
    assert_eq!(h.blake3_hex(), expected);
}

// ── hex layout (positions) ────────────────────────────────────────────────────

#[test]
fn hex_layout_is_b3_s2_s5_concatenated() {
    let content = b"layout test";
    let h = TripleHash::compute(content);
    let full = h.hex();
    assert_eq!(&full[0..64],   h.blake3_hex(),  "bytes 0–31:  BLAKE3");
    assert_eq!(&full[64..128], h.sha256_hex(),  "bytes 32–63: SHA-256");
    assert_eq!(&full[128..],   h.sha512_hex(),  "bytes 64–127: SHA-512");
}

// ── from_hex ──────────────────────────────────────────────────────────────────

#[test]
fn from_hex_roundtrip() {
    let content = b"from_hex roundtrip";
    let h1 = TripleHash::compute(content);
    let h2 = TripleHash::from_hex(&h1.hex()).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn from_hex_rejects_wrong_length() {
    let err = TripleHash::from_hex("deadbeef").unwrap_err();
    assert!(matches!(err, Error::InvalidLength { got: 8 }));
}

#[test]
fn from_hex_rejects_invalid_chars() {
    let bad = "zz".repeat(128); // 256 chars but not valid hex
    assert!(TripleHash::from_hex(&bad).is_err());
}

// ── raw byte accessors ────────────────────────────────────────────────────────

#[test]
fn blake3_bytes_len() {
    let h = TripleHash::compute(b"bytes");
    assert_eq!(h.blake3_bytes().len(), 32);
}

#[test]
fn sha256_bytes_len() {
    let h = TripleHash::compute(b"bytes");
    assert_eq!(h.sha256_bytes().len(), 32);
}

#[test]
fn sha512_bytes_len() {
    let h = TripleHash::compute(b"bytes");
    assert_eq!(h.sha512_bytes().len(), 64);
}

// ── Display / Debug ───────────────────────────────────────────────────────────

#[test]
fn display_is_16_hex_chars_plus_ellipsis() {
    let h = TripleHash::compute(b"display");
    let s = format!("{h}");
    assert!(s.ends_with('…'), "Display should end with …");
    // "…" is a 3-byte UTF-8 char; the prefix is 16 ASCII hex chars
    assert_eq!(s.chars().count(), 17); // 16 hex + 1 ellipsis char
}

#[test]
fn debug_contains_all_three_keys() {
    let h = TripleHash::compute(b"debug");
    let s = format!("{h:?}");
    assert!(s.contains("blake3:"));
    assert!(s.contains("sha256:"));
    assert!(s.contains("sha512:"));
}

// ── Serde ─────────────────────────────────────────────────────────────────────

#[test]
fn serde_json_roundtrip() {
    let content = b"serde roundtrip";
    let h = TripleHash::compute(content);
    let json = serde_json::to_string(&h).unwrap();
    let h2: TripleHash = serde_json::from_str(&json).unwrap();
    assert_eq!(h, h2);
}

#[test]
fn serde_json_has_correct_keys() {
    let h = TripleHash::compute(b"json keys");
    let v: serde_json::Value = serde_json::to_value(&h).unwrap();
    assert!(v["blake3"].is_string(), "missing blake3 field");
    assert!(v["sha256"].is_string(), "missing sha256 field");
    assert!(v["sha512"].is_string(), "missing sha512 field");
}

#[test]
fn serde_json_field_lengths() {
    let h = TripleHash::compute(b"lengths");
    let v: serde_json::Value = serde_json::to_value(&h).unwrap();
    assert_eq!(v["blake3"].as_str().unwrap().len(), 64);
    assert_eq!(v["sha256"].as_str().unwrap().len(), 64);
    assert_eq!(v["sha512"].as_str().unwrap().len(), 128);
}

#[test]
fn serde_deserialize_rejects_wrong_blake3_length() {
    let json = r#"{"blake3":"aabb","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08","sha512":"ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff4e"}"#;
    let result: Result<TripleHash, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ── TDS tier ──────────────────────────────────────────────────────────────────

#[test]
fn tds_second_hand_boundaries() {
    assert_eq!(Tier::for_duration(Duration::ZERO),                  Tier::SecondHand);
    assert_eq!(Tier::for_duration(Duration::from_millis(100)),      Tier::SecondHand);
    assert_eq!(Tier::for_duration(Duration::from_millis(299)),      Tier::SecondHand);
}

#[test]
fn tds_minute_hand_boundaries() {
    assert_eq!(Tier::for_duration(Duration::from_millis(300)),      Tier::MinuteHand);
    assert_eq!(Tier::for_duration(Duration::from_secs(15)),         Tier::MinuteHand);
    assert_eq!(Tier::for_duration(Duration::from_secs(30)),         Tier::MinuteHand);
}

#[test]
fn tds_hour_hand_boundaries() {
    assert_eq!(Tier::for_duration(Duration::from_millis(30_001)),   Tier::HourHand);
    assert_eq!(Tier::for_duration(Duration::from_secs(31)),         Tier::HourHand);
    assert_eq!(Tier::for_duration(Duration::from_secs(3_600)),      Tier::HourHand);
}

#[test]
fn tds_algorithm_names() {
    assert_eq!(Tier::SecondHand.algorithm_name(), "BLAKE3");
    assert_eq!(Tier::MinuteHand.algorithm_name(), "SHA-256");
    assert_eq!(Tier::HourHand.algorithm_name(),   "SHA-512");
}

#[test]
fn tds_byte_ranges_cover_full_128_bytes() {
    let (s0, e0) = Tier::SecondHand.byte_range();
    let (s1, e1) = Tier::MinuteHand.byte_range();
    let (s2, e2) = Tier::HourHand.byte_range();
    assert_eq!((s0, e0), (0,  32));
    assert_eq!((s1, e1), (32, 64));
    assert_eq!((s2, e2), (64, 128));
    // No gaps, no overlaps.
    assert_eq!(e0, s1);
    assert_eq!(e1, s2);
    assert_eq!(e2, 128);
}

#[test]
fn tds_digest_len() {
    assert_eq!(Tier::SecondHand.digest_len(), 32);
    assert_eq!(Tier::MinuteHand.digest_len(), 32);
    assert_eq!(Tier::HourHand.digest_len(),   64);
}

#[test]
fn tds_tier_indexes_into_triple_hash() {
    let content = b"tier indexing";
    let h = TripleHash::compute(content);
    let full = h.hex();

    let (s, e) = Tier::SecondHand.byte_range();
    assert_eq!(&full[s * 2..e * 2], h.blake3_hex());

    let (s, e) = Tier::MinuteHand.byte_range();
    assert_eq!(&full[s * 2..e * 2], h.sha256_hex());

    let (s, e) = Tier::HourHand.byte_range();
    assert_eq!(&full[s * 2..e * 2], h.sha512_hex());
}
