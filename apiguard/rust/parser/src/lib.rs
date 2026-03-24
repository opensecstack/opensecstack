pub mod error;
pub mod ir;
pub mod openapi3;
pub mod resolve;
pub mod swagger2;
pub mod validate;

use error::ParseError;
use ir::{ApiGuardIR, InputFormat};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Default maximum schema size: 10 MB.
const MAX_SCHEMA_SIZE: usize = 10 * 1024 * 1024;

/// Maximum nesting depth allowed in a parsed document (billion-laughs / stack-overflow mitigation).
const MAX_VALUE_DEPTH: usize = 128;

/// Check that a parsed `serde_json::Value` does not exceed a maximum nesting depth.
/// This mitigates billion-laughs-style attacks (MEDIUM-4) and stack-overflow via deeply
/// nested deserialization (MEDIUM-2).
///
/// NOTE (MEDIUM-2): This check runs *after* the YAML/JSON library has already deserialized
/// the document into a `Value`. If the raw document is so deeply nested that the
/// deserializer itself overflows the stack, this check cannot help — that depends on
/// the YAML library's internal depth limits. `serde_yml` has improved alias handling
/// compared to `serde_yaml` 0.9, which provides some additional protection.
fn check_value_depth(value: &serde_json::Value, max_depth: usize) -> Result<(), ParseError> {
    fn depth(v: &serde_json::Value, current: usize, max: usize) -> Result<(), ()> {
        if current > max {
            return Err(());
        }
        match v {
            serde_json::Value::Array(arr) => {
                for item in arr {
                    depth(item, current + 1, max)?;
                }
            }
            serde_json::Value::Object(obj) => {
                for (_, val) in obj {
                    depth(val, current + 1, max)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    depth(value, 0, max_depth).map_err(|_| ParseError::InvalidSchema {
        errors: vec![format!(
            "document exceeds maximum nesting depth of {}",
            max_depth
        )],
    })
}

/// Parse raw YAML/JSON bytes into a `serde_json::Value`, enforcing size and depth limits.
fn parse_bytes_to_value(input: &[u8]) -> Result<serde_json::Value, ParseError> {
    // Enforce size limit before any parsing.
    if input.len() > MAX_SCHEMA_SIZE {
        return Err(ParseError::SizeExceeded {
            size_bytes: input.len(),
            max_bytes: MAX_SCHEMA_SIZE,
        });
    }

    let input_str = std::str::from_utf8(input).map_err(|e| ParseError::InvalidFormat {
        line: None,
        message: format!("input is not valid UTF-8: {e}"),
    })?;

    // serde_yml (actively maintained fork of serde_yaml) handles both YAML and JSON.
    let doc: serde_json::Value = serde_yml::from_str(input_str).map_err(|e| {
        ParseError::InvalidFormat {
            line: None,
            message: e.to_string(),
        }
    })?;

    // Reject documents that are too deeply nested (billion-laughs / stack-overflow mitigation).
    check_value_depth(&doc, MAX_VALUE_DEPTH)?;

    Ok(doc)
}

/// Parse raw bytes in the given format into an `ApiGuardIR`.
pub fn parse(input: &[u8], format: InputFormat) -> Result<ApiGuardIR, ParseError> {
    let doc = parse_bytes_to_value(input)?;
    parse_value(&doc, input, format)
}

/// Parse a pre-parsed `serde_json::Value` into an `ApiGuardIR`.
/// The raw `input` bytes are still needed for the schema hash.
pub fn parse_value(
    doc: &serde_json::Value,
    input: &[u8],
    format: InputFormat,
) -> Result<ApiGuardIR, ParseError> {
    // Compute schema hash from the original bytes.
    let schema_hash = {
        let mut hasher = Sha256::new();
        hasher.update(input);
        format!("{:x}", hasher.finalize())
    };

    let ir = match format {
        InputFormat::OpenApi3 => openapi3::parse_openapi3(doc, schema_hash)?,
        InputFormat::Swagger2 => swagger2::parse_swagger2(doc, schema_hash)?,
        InputFormat::GraphQL => {
            return Err(ParseError::UnsupportedVersion {
                version: "GraphQL".into(),
                supported: vec![
                    "OpenAPI 3.0.x".into(),
                    "OpenAPI 3.1.x".into(),
                    "Swagger 2.0".into(),
                ],
            });
        }
        InputFormat::Postman => {
            return Err(ParseError::UnsupportedVersion {
                version: "Postman".into(),
                supported: vec![
                    "OpenAPI 3.0.x".into(),
                    "OpenAPI 3.1.x".into(),
                    "Swagger 2.0".into(),
                ],
            });
        }
    };

    // Validate the produced IR.
    validate::validate_ir(&ir)?;

    Ok(ir)
}

/// Parse a file from disk, auto-detecting the format from the content.
/// The file is read once, parsed once, then the format is detected from the
/// parsed Value — eliminating the previous double-parse (MEDIUM-3).
pub fn parse_file(path: &Path) -> Result<ApiGuardIR, ParseError> {
    let input = std::fs::read(path).map_err(|e| ParseError::FetchError {
        url: path.display().to_string(),
        message: e.to_string(),
    })?;

    // Parse once — size and depth limits are enforced inside parse_bytes_to_value.
    let doc = parse_bytes_to_value(&input)?;

    // Detect format from the already-parsed Value (no second parse).
    let format = detect_format_from_value(&doc)?;

    parse_value(&doc, &input, format)
}

/// Auto-detect whether the input is OpenAPI 3.x or Swagger 2.0 from a pre-parsed Value.
fn detect_format_from_value(doc: &serde_json::Value) -> Result<InputFormat, ParseError> {
    if doc.get("openapi").and_then(|v| v.as_str()).is_some() {
        Ok(InputFormat::OpenApi3)
    } else if doc.get("swagger").and_then(|v| v.as_str()).is_some() {
        Ok(InputFormat::Swagger2)
    } else {
        Err(ParseError::InvalidFormat {
            line: None,
            message: "cannot detect format: no 'openapi' or 'swagger' key found".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_openapi3() {
        let input = b"openapi: '3.0.1'\ninfo:\n  title: Test\n  version: '1.0'\npaths:\n  /test:\n    get:\n      responses:\n        '200':\n          description: ok";
        let doc = parse_bytes_to_value(input).unwrap();
        let format = detect_format_from_value(&doc).unwrap();
        assert_eq!(format, InputFormat::OpenApi3);
    }

    #[test]
    fn test_detect_swagger2() {
        let input = b"swagger: '2.0'\ninfo:\n  title: Test\n  version: '1.0'\npaths:\n  /test:\n    get:\n      responses:\n        200:\n          description: ok";
        let doc = parse_bytes_to_value(input).unwrap();
        let format = detect_format_from_value(&doc).unwrap();
        assert_eq!(format, InputFormat::Swagger2);
    }

    #[test]
    fn test_size_exceeded() {
        let big = vec![b' '; MAX_SCHEMA_SIZE + 1];
        let result = parse(&big, InputFormat::OpenApi3);
        assert!(matches!(result, Err(ParseError::SizeExceeded { .. })));
    }
}
