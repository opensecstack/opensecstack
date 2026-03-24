use crate::error::ParseError;
use serde_json::Value;
use std::collections::HashSet;

/// Maximum $ref resolution depth before we treat it as circular.
const MAX_REF_DEPTH: usize = 10;

/// Resolve a JSON Pointer reference (e.g. `#/components/schemas/Pet`) within a document.
///
/// Returns a clone of the resolved value, or a `ParseError` on failure.
pub fn resolve_ref(
    root: &Value,
    ref_path: &str,
    visited: &mut HashSet<String>,
    depth: usize,
) -> Result<Value, ParseError> {
    if depth > MAX_REF_DEPTH {
        return Err(ParseError::CircularReference {
            path: visited.iter().cloned().collect(),
        });
    }

    if visited.contains(ref_path) {
        return Err(ParseError::CircularReference {
            path: visited.iter().cloned().collect(),
        });
    }

    visited.insert(ref_path.to_string());

    let pointer = ref_to_json_pointer(ref_path)?;
    let resolved = root.pointer(&pointer).ok_or_else(|| ParseError::InvalidSchema {
        errors: vec![format!("unresolved $ref: {ref_path}")],
    })?;

    // If the resolved value itself contains a $ref, keep resolving.
    if let Some(inner_ref) = resolved.get("$ref").and_then(|v| v.as_str()) {
        let result = resolve_ref(root, inner_ref, visited, depth + 1)?;
        visited.remove(ref_path);
        return Ok(result);
    }

    visited.remove(ref_path);
    Ok(resolved.clone())
}

/// Resolve a `$ref` within a value, returning the resolved value if it's a ref,
/// or the original value otherwise.
pub fn resolve_value(
    root: &Value,
    value: &Value,
    depth: usize,
) -> Result<Value, ParseError> {
    if let Some(ref_path) = value.get("$ref").and_then(|v| v.as_str()) {
        let mut visited = HashSet::new();
        resolve_ref(root, ref_path, &mut visited, depth)
    } else {
        Ok(value.clone())
    }
}

/// Convert a `$ref` string like `#/components/schemas/Pet` to a JSON Pointer `/components/schemas/Pet`.
fn ref_to_json_pointer(ref_path: &str) -> Result<String, ParseError> {
    if let Some(stripped) = ref_path.strip_prefix('#') {
        Ok(stripped.to_string())
    } else {
        Err(ParseError::InvalidSchema {
            errors: vec![format!(
                "external $ref not supported (only local #/ refs): {ref_path}"
            )],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_resolve_simple_ref() {
        let doc = json!({
            "components": {
                "schemas": {
                    "Pet": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" }
                        }
                    }
                }
            }
        });
        let mut visited = HashSet::new();
        let result = resolve_ref(&doc, "#/components/schemas/Pet", &mut visited, 0).unwrap();
        assert_eq!(result["type"], "object");
    }

    #[test]
    fn test_circular_ref() {
        let doc = json!({
            "components": {
                "schemas": {
                    "A": { "$ref": "#/components/schemas/B" },
                    "B": { "$ref": "#/components/schemas/A" }
                }
            }
        });
        let mut visited = HashSet::new();
        let result = resolve_ref(&doc, "#/components/schemas/A", &mut visited, 0);
        assert!(result.is_err());
        match result.unwrap_err() {
            ParseError::CircularReference { .. } => {}
            other => panic!("expected CircularReference, got {other:?}"),
        }
    }
}
