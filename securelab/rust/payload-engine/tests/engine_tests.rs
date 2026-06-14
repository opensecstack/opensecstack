use payload_engine::engine::PayloadEngine;
use payload_engine::result::PayloadResult;
use payload_engine::spec::PayloadSpec;

#[test]
fn test_engine_new_succeeds() {
    let _engine = PayloadEngine::new();
}

#[test]
fn test_payload_spec_roundtrip() {
    let spec = PayloadSpec::new(
        "T1059.001".to_string(),
        "host".to_string(),
        r#"{"shell":"powershell"}"#.to_string(),
    );

    let serialized = serde_json::to_string(&spec).expect("serialization failed");
    let deserialized: PayloadSpec =
        serde_json::from_str(&serialized).expect("deserialization failed");

    assert_eq!(deserialized.technique_id, "T1059.001");
    assert_eq!(deserialized.target, "host");
    assert_eq!(deserialized.parameters, r#"{"shell":"powershell"}"#);
}

#[test]
fn test_payload_result_has_fields() {
    let result = PayloadResult::new(
        "pr-001".to_string(),
        vec![0xde, 0xad, 0xbe, 0xef],
        "T1059.001".to_string(),
        "abc123".to_string(),
    );

    assert_eq!(result.payload_id, "pr-001");
    assert_eq!(result.bytes, vec![0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(result.technique_id, "T1059.001");
    assert_eq!(result.checksum_sha256, "abc123");
}
