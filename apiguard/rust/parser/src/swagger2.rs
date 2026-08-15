use crate::error::ParseError;
use crate::ir::*;
use crate::openapi3;
use serde_json::Value;
use std::collections::HashMap;

/// Parse a Swagger 2.0 document by converting it to OpenAPI 3.x-like JSON
/// and then delegating to the OpenAPI 3 parser.
pub fn parse_swagger2(doc: &Value, schema_hash: String) -> Result<ApiGuardIR, ParseError> {
    validate_version(doc)?;
    let converted = convert_to_openapi3(doc)?;
    openapi3::parse_openapi3(&converted, schema_hash)
}

fn validate_version(doc: &Value) -> Result<(), ParseError> {
    let version = doc.get("swagger").and_then(|v| v.as_str()).unwrap_or("");

    if version == "2.0" {
        Ok(())
    } else {
        Err(ParseError::UnsupportedVersion {
            version: version.to_string(),
            supported: vec!["2.0".into()],
        })
    }
}

/// Convert a Swagger 2.0 document to an OpenAPI 3.0 structure (as serde_json::Value).
fn convert_to_openapi3(doc: &Value) -> Result<Value, ParseError> {
    let mut result = serde_json::Map::new();

    result.insert("openapi".into(), Value::String("3.0.0".into()));

    // info — pass through as-is
    if let Some(info) = doc.get("info") {
        result.insert("info".into(), info.clone());
    } else {
        result.insert(
            "info".into(),
            serde_json::json!({"title": "", "version": ""}),
        );
    }

    // servers from host + basePath + schemes
    let host = doc
        .get("host")
        .and_then(|v| v.as_str())
        .unwrap_or("localhost");
    let base_path = doc.get("basePath").and_then(|v| v.as_str()).unwrap_or("/");
    let scheme = doc
        .get("schemes")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("https");

    let server_url = format!("{scheme}://{host}{base_path}");
    result.insert("servers".into(), serde_json::json!([{"url": server_url}]));

    // paths — convert operations
    if let Some(paths) = doc.get("paths").and_then(|v| v.as_object()) {
        let mut new_paths = serde_json::Map::new();
        for (path, path_item) in paths {
            let converted_item = convert_path_item(doc, path_item);
            new_paths.insert(path.clone(), converted_item);
        }
        result.insert("paths".into(), Value::Object(new_paths));
    }

    // components.securitySchemes from securityDefinitions
    if let Some(sec_defs) = doc.get("securityDefinitions").and_then(|v| v.as_object()) {
        let mut schemes = serde_json::Map::new();
        for (name, def) in sec_defs {
            schemes.insert(name.clone(), convert_security_definition(def));
        }
        result.insert(
            "components".into(),
            serde_json::json!({"securitySchemes": schemes}),
        );
    }

    // Also carry over definitions into components.schemas for $ref resolution
    if let Some(definitions) = doc.get("definitions") {
        let components = result
            .entry("components")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(obj) = components.as_object_mut() {
            obj.insert("schemas".into(), definitions.clone());
        }
    }

    Ok(Value::Object(result))
}

fn convert_path_item(doc: &Value, item: &Value) -> Value {
    let methods = ["get", "post", "put", "patch", "delete", "head", "options"];
    let mut new_item = serde_json::Map::new();

    // Convert path-level parameters
    if let Some(params) = item.get("parameters") {
        new_item.insert("parameters".into(), convert_parameters(params));
    }

    for method in &methods {
        if let Some(op) = item.get(*method) {
            new_item.insert((*method).into(), convert_operation(doc, op));
        }
    }

    Value::Object(new_item)
}

fn convert_operation(_doc: &Value, op: &Value) -> Value {
    let mut new_op = serde_json::Map::new();

    // tags, security pass through
    if let Some(tags) = op.get("tags") {
        new_op.insert("tags".into(), tags.clone());
    }
    if let Some(security) = op.get("security") {
        new_op.insert("security".into(), security.clone());
    }

    // Separate body parameters from others
    let mut params_out = Vec::new();
    let mut body_schema = None;
    let mut consumes = op
        .get("consumes")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    if consumes.is_empty() {
        consumes.push(Value::String("application/json".into()));
    }

    if let Some(params) = op.get("parameters").and_then(|v| v.as_array()) {
        for p in params {
            let in_val = p.get("in").and_then(|v| v.as_str()).unwrap_or("");
            if in_val == "body" {
                body_schema = p.get("schema").cloned();
            } else if in_val == "formData" {
                // Skip formData params for now — they map to requestBody
            } else {
                // Convert $ref in definitions to components/schemas
                let mut param = p.clone();
                fix_definition_refs(&mut param, 0);
                params_out.push(param);
            }
        }
    }

    if !params_out.is_empty() {
        new_op.insert("parameters".into(), Value::Array(params_out));
    }

    // requestBody from body parameter
    if let Some(mut schema) = body_schema {
        fix_definition_refs(&mut schema, 0);
        let content_type = consumes
            .first()
            .and_then(|v| v.as_str())
            .unwrap_or("application/json");

        new_op.insert(
            "requestBody".into(),
            serde_json::json!({
                "required": true,
                "content": {
                    content_type: {
                        "schema": schema
                    }
                }
            }),
        );
    }

    // responses
    if let Some(responses) = op.get("responses").and_then(|v| v.as_object()) {
        let mut new_responses = serde_json::Map::new();
        for (code, resp) in responses {
            let mut new_resp = serde_json::Map::new();
            let desc = resp
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            new_resp.insert("description".into(), Value::String(desc.into()));

            if let Some(mut schema) = resp.get("schema").cloned() {
                fix_definition_refs(&mut schema, 0);
                new_resp.insert(
                    "content".into(),
                    serde_json::json!({
                        "application/json": {
                            "schema": schema
                        }
                    }),
                );
            }
            new_responses.insert(code.clone(), Value::Object(new_resp));
        }
        new_op.insert("responses".into(), Value::Object(new_responses));
    }

    // x-apiguard extensions
    if let Some(obj) = op.as_object() {
        for (k, v) in obj {
            if k.starts_with("x-apiguard") {
                new_op.insert(k.clone(), v.clone());
            }
        }
    }

    Value::Object(new_op)
}

fn convert_parameters(params: &Value) -> Value {
    let mut out = params.clone();
    fix_definition_refs(&mut out, 0);
    out
}

/// Swagger 2.0 uses `#/definitions/Foo`, OpenAPI 3 uses `#/components/schemas/Foo`.
/// The `depth` parameter guards against stack overflow from deeply nested or
/// adversarial documents (MEDIUM-5).
fn fix_definition_refs(value: &mut Value, depth: usize) {
    if depth > 64 {
        return; // Safety limit to prevent stack overflow on deeply nested input
    }
    match value {
        Value::Object(map) => {
            if let Some(ref_val) = map.get_mut("$ref") {
                if let Some(s) = ref_val.as_str() {
                    if let Some(stripped) = s.strip_prefix("#/definitions/") {
                        *ref_val = Value::String(format!("#/components/schemas/{stripped}"));
                    }
                }
            }
            for v in map.values_mut() {
                fix_definition_refs(v, depth + 1);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                fix_definition_refs(v, depth + 1);
            }
        }
        _ => {}
    }
}

/// Convert a Swagger 2.0 security definition to OpenAPI 3 securityScheme.
fn convert_security_definition(def: &Value) -> Value {
    let type_str = def.get("type").and_then(|v| v.as_str()).unwrap_or("");

    match type_str {
        "basic" => serde_json::json!({
            "type": "http",
            "scheme": "basic"
        }),
        "apiKey" => {
            let in_val = def.get("in").and_then(|v| v.as_str()).unwrap_or("header");
            let name = def.get("name").and_then(|v| v.as_str()).unwrap_or("");
            serde_json::json!({
                "type": "apiKey",
                "in": in_val,
                "name": name
            })
        }
        "oauth2" => {
            let flow = def
                .get("flow")
                .and_then(|v| v.as_str())
                .unwrap_or("implicit");
            let auth_url = def
                .get("authorizationUrl")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let token_url = def.get("tokenUrl").and_then(|v| v.as_str()).unwrap_or("");
            let scopes = def.get("scopes").cloned().unwrap_or(serde_json::json!({}));

            let flow_obj = match flow {
                "implicit" => serde_json::json!({
                    "implicit": {
                        "authorizationUrl": auth_url,
                        "scopes": scopes
                    }
                }),
                "password" => serde_json::json!({
                    "password": {
                        "tokenUrl": token_url,
                        "scopes": scopes
                    }
                }),
                "application" => serde_json::json!({
                    "clientCredentials": {
                        "tokenUrl": token_url,
                        "scopes": scopes
                    }
                }),
                "accessCode" => serde_json::json!({
                    "authorizationCode": {
                        "authorizationUrl": auth_url,
                        "tokenUrl": token_url,
                        "scopes": scopes
                    }
                }),
                _ => serde_json::json!({}),
            };

            serde_json::json!({
                "type": "oauth2",
                "flows": flow_obj
            })
        }
        _ => def.clone(),
    }
}
