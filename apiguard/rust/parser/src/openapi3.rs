use crate::error::ParseError;
use crate::ir::*;
use crate::resolve;
use serde_json::Value;
use std::collections::HashMap;

/// Parse an OpenAPI 3.0.x / 3.1.x document (already deserialised to serde_json::Value)
/// into an `ApiGuardIR`.
pub fn parse_openapi3(doc: &Value, schema_hash: String) -> Result<ApiGuardIR, ParseError> {
    validate_version(doc)?;

    let endpoints = extract_endpoints(doc)?;
    let auth_schemes = extract_auth_schemes(doc);
    let metadata = extract_metadata(doc, schema_hash);

    Ok(ApiGuardIR {
        endpoints,
        auth_schemes,
        metadata,
    })
}

/// Ensure the document declares a supported openapi version.
fn validate_version(doc: &Value) -> Result<(), ParseError> {
    let version = doc
        .get("openapi")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if version.starts_with("3.0.") || version.starts_with("3.1.") {
        Ok(())
    } else {
        Err(ParseError::UnsupportedVersion {
            version: version.to_string(),
            supported: vec!["3.0.x".into(), "3.1.x".into()],
        })
    }
}

/// Extract all endpoints from `paths`.
fn extract_endpoints(doc: &Value) -> Result<Vec<Endpoint>, ParseError> {
    let paths = match doc.get("paths") {
        Some(p) if p.is_object() => p,
        _ => return Ok(Vec::new()),
    };

    let methods = [
        ("get", HttpMethod::Get),
        ("post", HttpMethod::Post),
        ("put", HttpMethod::Put),
        ("patch", HttpMethod::Patch),
        ("delete", HttpMethod::Delete),
        ("head", HttpMethod::Head),
        ("options", HttpMethod::Options),
    ];

    let mut endpoints = Vec::new();

    for (path, path_item) in paths.as_object().unwrap() {
        // Path-level parameters apply to all methods.
        let path_params = extract_parameters(doc, path_item.get("parameters"));

        for &(method_str, method) in &methods {
            if let Some(operation) = path_item.get(method_str) {
                let mut params = path_params.clone();
                // Operation-level parameters override/extend path-level.
                let op_params = extract_parameters(doc, operation.get("parameters"));
                for op_p in op_params {
                    if !params.iter().any(|p| p.name == op_p.name && p.location == op_p.location) {
                        params.push(op_p);
                    }
                }

                let request_body = extract_request_body(doc, operation);
                let responses = extract_responses(doc, operation);
                let security = extract_security(operation);
                let tags = extract_tags(operation);
                let x_apiguard = extract_x_apiguard(operation);

                endpoints.push(Endpoint {
                    path: path.clone(),
                    method,
                    parameters: params,
                    request_body,
                    responses,
                    security,
                    tags,
                    x_apiguard,
                });
            }
        }
    }

    Ok(endpoints)
}

fn extract_parameters(doc: &Value, params: Option<&Value>) -> Vec<Parameter> {
    let arr = match params.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };

    arr.iter()
        .filter_map(|p| {
            let p = resolve::resolve_value(doc, p, 0).ok()?;
            let name = p.get("name")?.as_str()?.to_string();
            let loc = match p.get("in")?.as_str()? {
                "path" => ParameterLocation::Path,
                "query" => ParameterLocation::Query,
                "header" => ParameterLocation::Header,
                "cookie" => ParameterLocation::Cookie,
                _ => return None,
            };
            let required = p.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
            let schema = p.get("schema").and_then(|s| parse_schema_type(doc, s, 0));

            Some(Parameter {
                name,
                location: loc,
                required,
                schema,
            })
        })
        .collect()
}

fn extract_request_body(doc: &Value, operation: &Value) -> Option<RequestBody> {
    let rb = operation.get("requestBody")?;
    let rb = resolve::resolve_value(doc, rb, 0).ok()?;
    let required = rb.get("required").and_then(|v| v.as_bool()).unwrap_or(false);
    let content = rb.get("content")?.as_object()?;

    let mut content_types = Vec::new();
    let mut schema = None;

    for (ct, media) in content {
        content_types.push(ct.clone());
        if schema.is_none() {
            if let Some(s) = media.get("schema") {
                schema = parse_schema_type(doc, s, 0);
            }
        }
    }

    Some(RequestBody {
        content_types,
        schema,
        required,
    })
}

fn extract_responses(doc: &Value, operation: &Value) -> HashMap<String, Response> {
    let responses = match operation.get("responses").and_then(|v| v.as_object()) {
        Some(r) => r,
        None => return HashMap::new(),
    };

    let mut result = HashMap::new();
    for (code, resp_val) in responses {
        let resp = resolve::resolve_value(doc, resp_val, 0).unwrap_or(resp_val.clone());
        let description = resp
            .get("description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let schema = resp
            .get("content")
            .and_then(|c| c.as_object())
            .and_then(|c| c.values().next())
            .and_then(|media| media.get("schema"))
            .and_then(|s| parse_schema_type(doc, s, 0));

        result.insert(code.clone(), Response { description, schema });
    }
    result
}

fn extract_security(operation: &Value) -> Vec<String> {
    operation
        .get("security")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    item.as_object()
                        .and_then(|m| m.keys().next().cloned())
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_tags(operation: &Value) -> Vec<String> {
    operation
        .get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn extract_x_apiguard(operation: &Value) -> HashMap<String, serde_json::Value> {
    let obj = match operation.as_object() {
        Some(o) => o,
        None => return HashMap::new(),
    };
    obj.iter()
        .filter(|(k, _)| k.starts_with("x-apiguard"))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Extract auth schemes from `components.securitySchemes` (OpenAPI 3.x).
fn extract_auth_schemes(doc: &Value) -> Vec<AuthScheme> {
    let schemes = match doc
        .pointer("/components/securitySchemes")
        .and_then(|v| v.as_object())
    {
        Some(s) => s,
        None => return Vec::new(),
    };

    schemes
        .iter()
        .filter_map(|(name, def)| {
            let def = resolve::resolve_value(doc, def, 0).ok()?;
            let type_str = def.get("type")?.as_str()?;

            let (scheme_type, location, header_name) = match type_str {
                "http" => {
                    let scheme = def.get("scheme").and_then(|v| v.as_str()).unwrap_or("");
                    match scheme {
                        "bearer" => {
                            let bearer_format = def.get("bearerFormat").and_then(|v| v.as_str());
                            if bearer_format == Some("JWT") {
                                (AuthSchemeType::Jwt, None, Some("Authorization".to_string()))
                            } else {
                                (AuthSchemeType::Bearer, None, Some("Authorization".to_string()))
                            }
                        }
                        "basic" => (AuthSchemeType::Basic, None, Some("Authorization".to_string())),
                        _ => (AuthSchemeType::Bearer, None, Some("Authorization".to_string())),
                    }
                }
                "apiKey" => {
                    let in_val = def.get("in").and_then(|v| v.as_str()).unwrap_or("header");
                    let header = def.get("name").and_then(|v| v.as_str()).map(String::from);
                    (AuthSchemeType::ApiKey, Some(in_val.to_string()), header)
                }
                "oauth2" => (AuthSchemeType::OAuth2, None, None),
                "openIdConnect" => (AuthSchemeType::OAuth2, None, None),
                _ => return None,
            };

            Some(AuthScheme {
                name: name.clone(),
                scheme_type,
                location,
                header_name,
            })
        })
        .collect()
}

fn extract_metadata(doc: &Value, schema_hash: String) -> Metadata {
    let base_url = doc
        .get("servers")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|s| s.get("url"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let api_version = doc
        .pointer("/info/version")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Metadata {
        base_url,
        api_version,
        schema_hash,
    }
}

/// Convert a JSON schema value to our simplified `SchemaType`.
pub fn parse_schema_type(doc: &Value, schema: &Value, depth: usize) -> Option<SchemaType> {
    if depth > 10 {
        return None;
    }

    // Handle $ref
    if let Some(ref_path) = schema.get("$ref").and_then(|v| v.as_str()) {
        let resolved = resolve::resolve_value(doc, schema, depth).ok()?;
        return parse_schema_type(doc, &resolved, depth + 1);
    }

    let type_str = schema.get("type").and_then(|v| v.as_str());

    match type_str {
        Some("string") => Some(SchemaType::String),
        Some("integer") => Some(SchemaType::Integer),
        Some("number") => Some(SchemaType::Number),
        Some("boolean") => Some(SchemaType::Boolean),
        Some("array") => {
            let items = schema.get("items")?;
            let inner = parse_schema_type(doc, items, depth + 1).unwrap_or(SchemaType::String);
            Some(SchemaType::Array(Box::new(inner)))
        }
        Some("object") | None => {
            // Treat untyped schemas with properties as objects.
            if let Some(props) = schema.get("properties").and_then(|v| v.as_object()) {
                let mut map = HashMap::new();
                for (k, v) in props {
                    if let Some(st) = parse_schema_type(doc, v, depth + 1) {
                        map.insert(k.clone(), st);
                    }
                }
                Some(SchemaType::Object(map))
            } else if type_str == Some("object") {
                Some(SchemaType::Object(HashMap::new()))
            } else {
                None
            }
        }
        _ => None,
    }
}
