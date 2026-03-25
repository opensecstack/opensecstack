//! L2 Test Generator for APIGuard.
//!
//! Takes an [`ApiGuardIR`] produced by the L1 parser and generates
//! [`TestSuite`] specifications for each endpoint × OWASP module combination.

use parser::ir::{ApiGuardIR, Endpoint, HttpMethod, Parameter, ParameterLocation};
use serde::{Deserialize, Serialize};

// ── Public types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestSuite {
    pub target_url: String,
    pub spec_hash: String,
    pub test_cases: Vec<TestCase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub id: String,
    pub module_id: String,
    pub endpoint_path: String,
    pub endpoint_method: String,
    pub category: TestCategory,
    pub requests: Vec<TestRequest>,
    pub expected: ExpectedBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TestCategory {
    #[serde(rename = "auth_removal")]
    AuthRemoval,
    #[serde(rename = "auth_token_expired")]
    AuthTokenExpired,
    #[serde(rename = "auth_token_replay")]
    AuthTokenReplay,
    #[serde(rename = "auth_invalid_token")]
    AuthInvalidToken,
    #[serde(rename = "auth_unprotected_write")]
    AuthUnprotectedWrite,
    #[serde(rename = "bola_id_enum")]
    BolaIdEnum,
    #[serde(rename = "bola_cross_user")]
    BolaCrossUser,
    #[serde(rename = "mass_assign_extra_fields")]
    MassAssignExtraFields,
    #[serde(rename = "mass_assign_readonly")]
    MassAssignReadOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<serde_json::Value>,
    pub auth: AuthStrategy,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AuthStrategy {
    #[serde(rename = "none")]
    None,
    #[serde(rename = "valid")]
    Valid,
    #[serde(rename = "expired")]
    Expired,
    #[serde(rename = "other_user")]
    OtherUser,
    #[serde(rename = "invalid")]
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedBehavior {
    pub should_succeed: bool,
    pub expected_status_codes: Vec<u16>,
    pub vulnerability_if_fails: String,
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Returns `true` when a parameter name looks like an object identifier.
pub fn is_id_parameter(param: &Parameter) -> bool {
    if param.location != ParameterLocation::Path {
        return false;
    }
    let lower = param.name.to_lowercase();
    lower == "id"
        || lower.ends_with("id")
        || lower.ends_with("_id")
        || lower.contains("uuid")
}

/// Given a placeholder value for an ID parameter, produce common enumeration
/// variants an attacker would try.
pub fn generate_id_variations(original: &str) -> Vec<String> {
    let mut variations = Vec::new();

    // Try numeric variations if the original looks numeric (or is a placeholder).
    if let Ok(n) = original.parse::<i64>() {
        variations.push((n + 1).to_string());
        variations.push((n - 1).to_string());
        variations.push((n + 100).to_string());
        variations.push("0".to_string());
    } else {
        // Treat as opaque string — try neighbouring values and a random UUID.
        variations.push(format!("{original}1"));
        variations.push(format!("{original}_other"));
        variations.push(uuid::Uuid::new_v4().to_string());
    }

    variations
}

/// Produce a JSON object containing common mass-assignment injection fields.
pub fn generate_extra_fields() -> serde_json::Value {
    serde_json::json!({
        "admin": true,
        "role": "admin",
        "is_admin": true,
        "id": 1,
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2020-01-01T00:00:00Z"
    })
}

/// Produce a JSON object targeting read-only fields.
fn generate_readonly_fields() -> serde_json::Value {
    serde_json::json!({
        "id": 99999,
        "created_at": "1970-01-01T00:00:00Z",
        "updated_at": "1970-01-01T00:00:00Z"
    })
}

fn method_str(m: &HttpMethod) -> &'static str {
    match m {
        HttpMethod::Get => "GET",
        HttpMethod::Post => "POST",
        HttpMethod::Put => "PUT",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Delete => "DELETE",
        HttpMethod::Head => "HEAD",
        HttpMethod::Options => "OPTIONS",
    }
}

fn is_write_method(m: &HttpMethod) -> bool {
    matches!(m, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch | HttpMethod::Delete)
}

fn has_body_method(m: &HttpMethod) -> bool {
    matches!(m, HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch)
}

fn endpoint_has_security(ep: &Endpoint) -> bool {
    !ep.security.is_empty()
}

/// Replace path-parameter placeholders with the given value.
/// E.g. `/pets/{petId}` with `petId=42` → `/pets/42`.
fn substitute_path(path: &str, param_name: &str, value: &str) -> String {
    path.replace(&format!("{{{param_name}}}"), value)
}

// ── Counter helper for unique IDs ───────────────────────────────────────────

struct IdCounter(usize);

impl IdCounter {
    fn new() -> Self {
        Self(0)
    }
    fn next(&mut self, module: &str, category: &str) -> String {
        self.0 += 1;
        format!("{module}_{category}_{}", self.0)
    }
}

// ── Core generation entry point ─────────────────────────────────────────────

/// Generate a [`TestSuite`] from the given IR.
///
/// * `ir` — the parsed API specification.
/// * `target_url` — base URL to use in generated requests.
/// * `modules` — list of OWASP module IDs to generate tests for
///   (e.g. `["a1_bola", "a2_auth", "a3_mass_assignment"]`).
///   An empty slice means no tests are generated.
pub fn generate(ir: &ApiGuardIR, target_url: &str, modules: &[String]) -> TestSuite {
    let mut cases: Vec<TestCase> = Vec::new();
    let mut counter = IdCounter::new();

    for module in modules {
        match module.as_str() {
            "a1_bola" => generate_bola(ir, target_url, &mut cases, &mut counter),
            "a2_auth" => generate_auth(ir, target_url, &mut cases, &mut counter),
            "a3_mass_assignment" => {
                generate_mass_assignment(ir, target_url, &mut cases, &mut counter)
            }
            _ => { /* unknown module — silently skip */ }
        }
    }

    TestSuite {
        target_url: target_url.to_string(),
        spec_hash: ir.metadata.schema_hash.clone(),
        test_cases: cases,
    }
}

// ── A1 BOLA ─────────────────────────────────────────────────────────────────

fn generate_bola(
    ir: &ApiGuardIR,
    target_url: &str,
    cases: &mut Vec<TestCase>,
    counter: &mut IdCounter,
) {
    for ep in &ir.endpoints {
        // BOLA only applies to endpoints that require auth and have ID-like path params.
        if !endpoint_has_security(ep) {
            continue;
        }

        let id_params: Vec<&Parameter> = ep
            .parameters
            .iter()
            .filter(|p| is_id_parameter(p))
            .collect();

        if id_params.is_empty() {
            continue;
        }

        let method = method_str(&ep.method);

        // BolaIdEnum: enumerate IDs
        for param in &id_params {
            let original_value = "1"; // placeholder
            let variations = generate_id_variations(original_value);

            let requests: Vec<TestRequest> = variations
                .iter()
                .map(|v| {
                    let path = substitute_path(&ep.path, &param.name, v);
                    TestRequest {
                        method: method.to_string(),
                        path: format!("{target_url}{path}"),
                        headers: vec![],
                        body: None,
                        auth: AuthStrategy::Valid,
                        description: format!(
                            "Enumerate {} with value '{}'",
                            param.name, v
                        ),
                    }
                })
                .collect();

            cases.push(TestCase {
                id: counter.next("a1_bola", "id_enum"),
                module_id: "a1_bola".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::BolaIdEnum,
                requests,
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![403, 404],
                    vulnerability_if_fails: format!(
                        "BOLA: endpoint {} {} allows enumeration of '{}' — an authenticated user can access other users' objects by guessing IDs",
                        method, ep.path, param.name
                    ),
                },
            });
        }

        // BolaCrossUser: access with another user's token
        for param in &id_params {
            let path = substitute_path(&ep.path, &param.name, "1");
            let requests = vec![TestRequest {
                method: method.to_string(),
                path: format!("{target_url}{path}"),
                headers: vec![],
                body: None,
                auth: AuthStrategy::OtherUser,
                description: format!(
                    "Access {} with another user's auth token",
                    param.name
                ),
            }];

            cases.push(TestCase {
                id: counter.next("a1_bola", "cross_user"),
                module_id: "a1_bola".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::BolaCrossUser,
                requests,
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![403, 404],
                    vulnerability_if_fails: format!(
                        "BOLA: endpoint {} {} allows cross-user access via '{}' — authorization is not enforced per-object",
                        method, ep.path, param.name
                    ),
                },
            });
        }
    }
}

// ── A2 Auth ─────────────────────────────────────────────────────────────────

fn generate_auth(
    ir: &ApiGuardIR,
    target_url: &str,
    cases: &mut Vec<TestCase>,
    counter: &mut IdCounter,
) {
    for ep in &ir.endpoints {
        let method = method_str(&ep.method);
        let path_with_placeholders = fill_placeholders(&ep.path, &ep.parameters);
        let full_url = format!("{target_url}{path_with_placeholders}");

        if endpoint_has_security(ep) {
            // AuthRemoval
            cases.push(TestCase {
                id: counter.next("a2_auth", "auth_removal"),
                module_id: "a2_auth".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::AuthRemoval,
                requests: vec![TestRequest {
                    method: method.to_string(),
                    path: full_url.clone(),
                    headers: vec![],
                    body: None,
                    auth: AuthStrategy::None,
                    description: "Request with all auth headers removed".to_string(),
                }],
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![401],
                    vulnerability_if_fails: format!(
                        "Broken Authentication: endpoint {} {} is accessible without any authentication",
                        method, ep.path
                    ),
                },
            });

            // AuthTokenExpired
            cases.push(TestCase {
                id: counter.next("a2_auth", "auth_expired"),
                module_id: "a2_auth".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::AuthTokenExpired,
                requests: vec![TestRequest {
                    method: method.to_string(),
                    path: full_url.clone(),
                    headers: vec![],
                    body: None,
                    auth: AuthStrategy::Expired,
                    description: "Request with an expired auth token".to_string(),
                }],
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![401],
                    vulnerability_if_fails: format!(
                        "Broken Authentication: endpoint {} {} accepts expired tokens",
                        method, ep.path
                    ),
                },
            });

            // AuthTokenReplay
            cases.push(TestCase {
                id: counter.next("a2_auth", "auth_replay"),
                module_id: "a2_auth".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::AuthTokenReplay,
                requests: vec![TestRequest {
                    method: method.to_string(),
                    path: full_url.clone(),
                    headers: vec![],
                    body: None,
                    auth: AuthStrategy::Valid,
                    description: "Replay a previously used auth token".to_string(),
                }],
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![401, 403],
                    vulnerability_if_fails: format!(
                        "Broken Authentication: endpoint {} {} does not prevent token replay",
                        method, ep.path
                    ),
                },
            });

            // AuthInvalid (malformed token)
            cases.push(TestCase {
                id: counter.next("a2_auth", "auth_invalid"),
                module_id: "a2_auth".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::AuthInvalidToken,
                requests: vec![TestRequest {
                    method: method.to_string(),
                    path: full_url.clone(),
                    headers: vec![],
                    body: None,
                    auth: AuthStrategy::Invalid,
                    description: "Request with a malformed / invalid auth token".to_string(),
                }],
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![401],
                    vulnerability_if_fails: format!(
                        "Broken Authentication: endpoint {} {} accepts malformed tokens",
                        method, ep.path
                    ),
                },
            });
        } else if is_write_method(&ep.method) {
            // Suspicious: write endpoint with no security defined
            cases.push(TestCase {
                id: counter.next("a2_auth", "suspicious_no_auth"),
                module_id: "a2_auth".to_string(),
                endpoint_path: ep.path.clone(),
                endpoint_method: method.to_string(),
                category: TestCategory::AuthUnprotectedWrite,
                requests: vec![TestRequest {
                    method: method.to_string(),
                    path: full_url,
                    headers: vec![],
                    body: None,
                    auth: AuthStrategy::None,
                    description: format!(
                        "Suspicious: {} {} has no security defined — verify this is intentional",
                        method, ep.path
                    ),
                }],
                expected: ExpectedBehavior {
                    should_succeed: false,
                    expected_status_codes: vec![401, 403],
                    vulnerability_if_fails: format!(
                        "Broken Authentication: {} endpoint {} {} has no authentication requirement — likely a misconfiguration",
                        method, method, ep.path
                    ),
                },
            });
        }
    }
}

// ── A3 Mass Assignment ──────────────────────────────────────────────────────

fn generate_mass_assignment(
    ir: &ApiGuardIR,
    target_url: &str,
    cases: &mut Vec<TestCase>,
    counter: &mut IdCounter,
) {
    for ep in &ir.endpoints {
        if !has_body_method(&ep.method) {
            continue;
        }
        if ep.request_body.is_none() {
            continue;
        }

        let method = method_str(&ep.method);
        let path_with_placeholders = fill_placeholders(&ep.path, &ep.parameters);
        let full_url = format!("{target_url}{path_with_placeholders}");

        let auth = if endpoint_has_security(ep) {
            AuthStrategy::Valid
        } else {
            AuthStrategy::None
        };

        // MassAssignExtraFields
        let extra = generate_extra_fields();
        cases.push(TestCase {
            id: counter.next("a3_mass_assignment", "extra_fields"),
            module_id: "a3_mass_assignment".to_string(),
            endpoint_path: ep.path.clone(),
            endpoint_method: method.to_string(),
            category: TestCategory::MassAssignExtraFields,
            requests: vec![TestRequest {
                method: method.to_string(),
                path: full_url.clone(),
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some(extra),
                auth: auth.clone(),
                description: format!(
                    "Send extra privilege-escalation fields to {} {}",
                    method, ep.path
                ),
            }],
            expected: ExpectedBehavior {
                should_succeed: false,
                expected_status_codes: vec![400, 422],
                vulnerability_if_fails: format!(
                    "Mass Assignment: endpoint {} {} accepts and persists extra fields (admin, role, is_admin) not declared in the schema",
                    method, ep.path
                ),
            },
        });

        // MassAssignReadOnly
        let readonly = generate_readonly_fields();
        cases.push(TestCase {
            id: counter.next("a3_mass_assignment", "readonly_fields"),
            module_id: "a3_mass_assignment".to_string(),
            endpoint_path: ep.path.clone(),
            endpoint_method: method.to_string(),
            category: TestCategory::MassAssignReadOnly,
            requests: vec![TestRequest {
                method: method.to_string(),
                path: full_url,
                headers: vec![("Content-Type".to_string(), "application/json".to_string())],
                body: Some(readonly),
                auth,
                description: format!(
                    "Attempt to overwrite read-only fields on {} {}",
                    method, ep.path
                ),
            }],
            expected: ExpectedBehavior {
                should_succeed: false,
                expected_status_codes: vec![400, 422],
                vulnerability_if_fails: format!(
                    "Mass Assignment: endpoint {} {} allows overwriting read-only fields (id, created_at, updated_at)",
                    method, ep.path
                ),
            },
        });
    }
}

// ── Utility ─────────────────────────────────────────────────────────────────

/// Replace `{paramName}` placeholders with sensible test defaults.
fn fill_placeholders(path: &str, params: &[Parameter]) -> String {
    let mut result = path.to_string();
    for p in params {
        if p.location == ParameterLocation::Path {
            result = result.replace(&format!("{{{}}}", p.name), "1");
        }
    }
    result
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_id_parameter() {
        let make = |name: &str| Parameter {
            name: name.to_string(),
            location: ParameterLocation::Path,
            required: true,
            schema: None,
        };
        assert!(is_id_parameter(&make("petId")));
        assert!(is_id_parameter(&make("user_id")));
        assert!(is_id_parameter(&make("id")));
        assert!(is_id_parameter(&make("uuid")));
        assert!(!is_id_parameter(&make("name")));
        assert!(!is_id_parameter(&make("limit")));

        // Query params should return false
        let query = Parameter {
            name: "id".to_string(),
            location: ParameterLocation::Query,
            required: true,
            schema: None,
        };
        assert!(!is_id_parameter(&query));
    }

    #[test]
    fn test_generate_id_variations_numeric() {
        let variations = generate_id_variations("5");
        assert!(variations.contains(&"6".to_string()));
        assert!(variations.contains(&"4".to_string()));
        assert!(variations.contains(&"105".to_string()));
        assert!(variations.contains(&"0".to_string()));
    }

    #[test]
    fn test_generate_id_variations_string() {
        let variations = generate_id_variations("abc");
        assert!(variations.contains(&"abc1".to_string()));
        assert!(variations.contains(&"abc_other".to_string()));
        assert_eq!(variations.len(), 3);
    }

    #[test]
    fn test_generate_extra_fields() {
        let extra = generate_extra_fields();
        assert_eq!(extra["admin"], true);
        assert_eq!(extra["role"], "admin");
        assert_eq!(extra["is_admin"], true);
    }

    #[test]
    fn test_fill_placeholders() {
        let params = vec![Parameter {
            name: "petId".to_string(),
            location: ParameterLocation::Path,
            required: true,
            schema: None,
        }];
        let result = fill_placeholders("/pets/{petId}", &params);
        assert_eq!(result, "/pets/1");
    }
}
