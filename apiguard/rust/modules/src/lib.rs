//! L3 OWASP API Security Top 10 — Rust analysis modules.
//!
//! These functions implement performance-critical analysis that supplements the
//! Go-side scanner.  Each public function accepts JSON-serialisable input types
//! and returns a `Vec<ModuleFinding>`.  The binary entry-point (`main.rs`) wraps
//! them in a JSON stdin/stdout RPC protocol so the Go runner can invoke them via
//! subprocess.

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// A finding emitted by one of the Rust analysis modules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleFinding {
    pub owasp_id: String,
    pub module_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub endpoint_path: String,
    pub endpoint_method: String,
    pub evidence: HashMap<String, serde_json::Value>,
    pub remediation: String,
}

/// A captured HTTP response forwarded from the Go runner.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
}

/// Per-endpoint context provided alongside the response.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointCtx {
    pub path: String,
    pub method: String,
}

// ---------------------------------------------------------------------------
// API3:2023 — Excessive Data Exposure
// ---------------------------------------------------------------------------

/// Patterns that suggest personally identifiable information in a response body.
static PII_PATTERNS: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "email_address",
            Regex::new(r#"(?i)"[^"]*email[^"]*"\s*:\s*"[^"@\s]+@[^"\s]+"#).unwrap(),
        ),
        (
            "ssn",
            Regex::new(r#"(?i)"[^"]*ssn[^"]*"\s*:\s*"?\d{3}[-\s]?\d{2}[-\s]?\d{4}"?"#).unwrap(),
        ),
        (
            "card_number",
            Regex::new(
                r#"(?i)"[^"]*(?:card|pan|cc)[^"]*"\s*:\s*"?\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"?"#,
            )
            .unwrap(),
        ),
        (
            "password_field",
            Regex::new(r#"(?i)"[^"]*password[^"]*"\s*:\s*"[^"]{4,}""#).unwrap(),
        ),
        (
            "secret_field",
            Regex::new(
                r#"(?i)"[^"]*(?:secret|private_key|api_key)[^"]*"\s*:\s*"[^"]{8,}""#,
            )
            .unwrap(),
        ),
        (
            "phone_number",
            Regex::new(
                r#"(?i)"[^"]*(?:phone|mobile|tel)[^"]*"\s*:\s*"[\+\d\s\-\(\)]{7,20}""#,
            )
            .unwrap(),
        ),
    ]
});

/// Check a response body for PII field patterns (OWASP API3:2023).
pub fn check_excessive_data_exposure(resp: &HttpResponse, ctx: &EndpointCtx) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for (label, pattern) in PII_PATTERNS.iter() {
        if let Some(m) = pattern.find(&resp.body) {
            let snippet = redact(&resp.body[m.start()..m.end()]);
            let mut evidence = HashMap::new();
            evidence.insert("pii_category".to_string(), serde_json::json!(label));
            evidence.insert("matched_snippet".to_string(), serde_json::json!(snippet));
            evidence.insert(
                "status_code".to_string(),
                serde_json::json!(resp.status_code),
            );

            findings.push(ModuleFinding {
                owasp_id: "API3:2023".to_string(),
                module_id: "a3_exposure".to_string(),
                title: format!("Excessive Data Exposure — {} in response", label),
                description: format!(
                    "Endpoint {} {} returns a field matching the {} pattern. \
                     Sensitive data should be stripped before transmission.",
                    ctx.method, ctx.path, label
                ),
                severity: if *label == "password_field"
                    || *label == "card_number"
                    || *label == "ssn"
                {
                    "critical".to_string()
                } else {
                    "high".to_string()
                },
                endpoint_path: ctx.path.clone(),
                endpoint_method: ctx.method.clone(),
                evidence,
                remediation: "Apply a response allowlist: only return the fields the client is \
                     authorised to see. Do not rely on the client to discard sensitive fields."
                    .to_string(),
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// API4:2023 — Lack of Resources & Rate Limiting  (timing anomaly detection)
// ---------------------------------------------------------------------------

const MIN_TIMING_SAMPLES: usize = 3;
const TIMING_SPIKE_FACTOR: f64 = 5.0;

/// Detect timing anomalies that may indicate DoS-prone or resource-exhausting
/// endpoints (OWASP API4:2023).
pub fn check_timing_anomaly(
    ctx: &EndpointCtx,
    samples: &[u64],
    test_duration_ms: u64,
) -> Vec<ModuleFinding> {
    if samples.len() < MIN_TIMING_SAMPLES {
        return vec![];
    }

    let mean = samples.iter().sum::<u64>() as f64 / samples.len() as f64;
    let factor = test_duration_ms as f64 / mean.max(1.0);

    if factor < TIMING_SPIKE_FACTOR {
        return vec![];
    }

    let mut evidence = HashMap::new();
    evidence.insert(
        "baseline_mean_ms".to_string(),
        serde_json::json!(mean.round() as u64),
    );
    evidence.insert(
        "test_duration_ms".to_string(),
        serde_json::json!(test_duration_ms),
    );
    evidence.insert(
        "spike_factor".to_string(),
        serde_json::json!(format!("{:.1}x", factor)),
    );

    vec![ModuleFinding {
        owasp_id: "API4:2023".to_string(),
        module_id: "a4_rate_limit".to_string(),
        title: "Lack of Resources & Rate Limiting — Response Time Spike".to_string(),
        description: format!(
            "Endpoint {} {} responded in {}ms — {:.1}x slower than the baseline mean \
             of {}ms. This may indicate unbounded query complexity, missing pagination, \
             or insufficient rate limiting.",
            ctx.method,
            ctx.path,
            test_duration_ms,
            factor,
            mean.round() as u64,
        ),
        severity: if factor >= 10.0 {
            "high".to_string()
        } else {
            "medium".to_string()
        },
        endpoint_path: ctx.path.clone(),
        endpoint_method: ctx.method.clone(),
        evidence,
        remediation: "Implement rate limiting (token bucket or leaky bucket) per client/IP. \
             Add query complexity limits and enforce pagination on collection endpoints."
            .to_string(),
    }]
}

// ---------------------------------------------------------------------------
// API7:2023 — Security Misconfiguration  (HTTP security header analysis)
// ---------------------------------------------------------------------------

/// Security headers that should be present on API responses.
static REQUIRED_HEADERS: &[(&str, &str, &str)] = &[
    (
        "x-content-type-options",
        "nosniff",
        "Prevents MIME-type sniffing attacks.",
    ),
    (
        "x-frame-options",
        "DENY",
        "Prevents clickjacking via iframe embedding.",
    ),
    (
        "strict-transport-security",
        "",
        "Enforces HTTPS and prevents downgrade attacks.",
    ),
    (
        "content-security-policy",
        "",
        "Restricts sources of executable scripts and other resources.",
    ),
    (
        "cache-control",
        "no-store",
        "Prevents sensitive data from being cached by intermediaries.",
    ),
];

/// Headers that must NOT be present in production responses.
static FORBIDDEN_HEADERS: &[&str] = &[
    "x-powered-by",
    "server",
    "x-aspnet-version",
    "x-aspnetmvc-version",
];

/// Analyse security-relevant HTTP response headers (OWASP API7:2023).
pub fn check_security_headers(resp: &HttpResponse, ctx: &EndpointCtx) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();
    let lower_headers: HashMap<String, String> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    for (header, expected_value, rationale) in REQUIRED_HEADERS {
        match lower_headers.get(*header) {
            None => {
                let mut evidence = HashMap::new();
                evidence.insert("missing_header".to_string(), serde_json::json!(header));
                evidence.insert("rationale".to_string(), serde_json::json!(rationale));

                findings.push(ModuleFinding {
                    owasp_id: "API7:2023".to_string(),
                    module_id: "a7_misconfig".to_string(),
                    title: format!("Security Misconfiguration — Missing header: {}", header),
                    description: format!(
                        "Endpoint {} {} does not return the {} header. {}",
                        ctx.method, ctx.path, header, rationale
                    ),
                    severity: "medium".to_string(),
                    endpoint_path: ctx.path.clone(),
                    endpoint_method: ctx.method.clone(),
                    evidence,
                    remediation: format!(
                        "Add the {} response header{}.",
                        header,
                        if expected_value.is_empty() {
                            String::new()
                        } else {
                            format!(" with value '{}'", expected_value)
                        }
                    ),
                });
            }
            Some(value)
                if !expected_value.is_empty()
                    && !value
                        .to_lowercase()
                        .contains(&expected_value.to_lowercase()) =>
            {
                let mut evidence = HashMap::new();
                evidence.insert("header".to_string(), serde_json::json!(header));
                evidence.insert("actual_value".to_string(), serde_json::json!(value));
                evidence.insert(
                    "expected_to_contain".to_string(),
                    serde_json::json!(expected_value),
                );

                findings.push(ModuleFinding {
                    owasp_id: "API7:2023".to_string(),
                    module_id: "a7_misconfig".to_string(),
                    title: format!("Security Misconfiguration — Weak header value: {}", header),
                    description: format!(
                        "Endpoint {} {} returns {} with value '{}' which does not include '{}'.",
                        ctx.method, ctx.path, header, value, expected_value
                    ),
                    severity: "low".to_string(),
                    endpoint_path: ctx.path.clone(),
                    endpoint_method: ctx.method.clone(),
                    evidence,
                    remediation: format!("Set {} to '{}' or stronger.", header, expected_value),
                });
            }
            _ => {}
        }
    }

    for header in FORBIDDEN_HEADERS {
        if let Some(value) = lower_headers.get(*header) {
            let mut evidence = HashMap::new();
            evidence.insert("header".to_string(), serde_json::json!(header));
            evidence.insert("value".to_string(), serde_json::json!(value));

            findings.push(ModuleFinding {
                owasp_id: "API7:2023".to_string(),
                module_id: "a7_misconfig".to_string(),
                title: format!(
                    "Security Misconfiguration — Information disclosure header: {}",
                    header
                ),
                description: format!(
                    "Endpoint {} {} exposes the {} header ('{}') which reveals \
                     technology stack information to attackers.",
                    ctx.method, ctx.path, header, value
                ),
                severity: "low".to_string(),
                endpoint_path: ctx.path.clone(),
                endpoint_method: ctx.method.clone(),
                evidence,
                remediation: format!(
                    "Remove or suppress the {} header in your server/framework configuration.",
                    header
                ),
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// API8:2023 — Injection (response-side indicator detection)
// ---------------------------------------------------------------------------

static INJECTION_PATTERNS: Lazy<Vec<(&'static str, &'static str, Regex)>> = Lazy::new(|| {
    vec![
        (
            "sql_error",
            "SQL injection may have succeeded — server returned a database error.",
            Regex::new(
                r"(?i)(SQL syntax|ORA-\d+|PostgreSQL.*ERROR|mysql_fetch|You have an error in your SQL|sqlite3\.OperationalError|SQLSTATE|Unclosed quotation mark)",
            )
            .unwrap(),
        ),
        (
            "nosql_error",
            "NoSQL injection indicator found in response body.",
            Regex::new(r"(?i)(MongoError|BSONTypeError|CastError|E11000 duplicate key)").unwrap(),
        ),
        (
            "stack_trace",
            "Stack trace disclosure — may aid injection exploitation.",
            Regex::new(
                r"(?i)(at\s+[\w\.<>]+\([\w/]+\.(?:java|py|rb|php|cs|go|js|ts):\d+\)|Traceback \(most recent call last\)|panic:.*goroutine)",
            )
            .unwrap(),
        ),
        (
            "path_traversal",
            "Path traversal indicator: server returned a filesystem path.",
            Regex::new(
                r"(?:/etc/(?:passwd|shadow|hosts)|[A-Za-z]:\\Windows\\|/proc/self/environ)",
            )
            .unwrap(),
        ),
        (
            "xxe_indicator",
            "XXE indicator: server response contains unexpected XML entity content.",
            Regex::new(r#"(?i)(<!ENTITY|SYSTEM\s+['"]file://|<!DOCTYPE[^>]*SYSTEM)"#).unwrap(),
        ),
    ]
});

/// Scan a response body for injection success indicators (OWASP API8:2023).
pub fn check_injection_indicators(resp: &HttpResponse, ctx: &EndpointCtx) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();

    for (label, description, pattern) in INJECTION_PATTERNS.iter() {
        if let Some(m) = pattern.find(&resp.body) {
            let snippet = redact_short(&resp.body[m.start()..m.end()]);
            let mut evidence = HashMap::new();
            evidence.insert("indicator_type".to_string(), serde_json::json!(label));
            evidence.insert("matched_snippet".to_string(), serde_json::json!(snippet));
            evidence.insert(
                "status_code".to_string(),
                serde_json::json!(resp.status_code),
            );

            findings.push(ModuleFinding {
                owasp_id: "API8:2023".to_string(),
                module_id: "a8_injection".to_string(),
                title: format!("Injection Indicator — {}", label),
                description: format!("Endpoint {} {} — {}", ctx.method, ctx.path, description),
                severity: if *label == "sql_error" || *label == "path_traversal" {
                    "critical".to_string()
                } else {
                    "high".to_string()
                },
                endpoint_path: ctx.path.clone(),
                endpoint_method: ctx.method.clone(),
                evidence,
                remediation:
                    "Use parameterised queries / prepared statements for all database access. \
                     Sanitise inputs with an allowlist and suppress detailed error messages \
                     in production responses."
                        .to_string(),
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// API9:2023 — Improper Inventory Management
// ---------------------------------------------------------------------------

/// Check for deprecated or legacy-versioned endpoints (OWASP API9:2023).
pub fn check_inventory(resp: &HttpResponse, ctx: &EndpointCtx) -> Vec<ModuleFinding> {
    let mut findings = Vec::new();
    let lower_headers: HashMap<String, String> = resp
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    if lower_headers.contains_key("sunset") || lower_headers.contains_key("deprecation") {
        let sunset = lower_headers.get("sunset").cloned().unwrap_or_default();
        let deprecation = lower_headers
            .get("deprecation")
            .cloned()
            .unwrap_or_default();
        let mut evidence = HashMap::new();
        evidence.insert("sunset_header".to_string(), serde_json::json!(sunset));
        evidence.insert(
            "deprecation_header".to_string(),
            serde_json::json!(deprecation),
        );

        findings.push(ModuleFinding {
            owasp_id: "API9:2023".to_string(),
            module_id: "a9_inventory".to_string(),
            title: "Improper Inventory Management — Deprecated API endpoint in active use"
                .to_string(),
            description: format!(
                "Endpoint {} {} is marked as deprecated or sunset but is still reachable. \
                 Deprecated endpoints are often less hardened and may bypass newer security controls.",
                ctx.method, ctx.path
            ),
            severity: "medium".to_string(),
            endpoint_path: ctx.path.clone(),
            endpoint_method: ctx.method.clone(),
            evidence,
            remediation:
                "Decommission deprecated API versions on schedule. Ensure the Sunset date has not \
                 passed and that a migration guide is linked in the response headers."
                    .to_string(),
        });
    }

    // Flag legacy versioned paths (/v0/ or /v1/).
    let legacy_re = Regex::new(r"(?i)/v[01]/").unwrap();
    if legacy_re.is_match(&ctx.path) {
        let mut evidence = HashMap::new();
        evidence.insert("path".to_string(), serde_json::json!(ctx.path));

        findings.push(ModuleFinding {
            owasp_id: "API9:2023".to_string(),
            module_id: "a9_inventory".to_string(),
            title: "Improper Inventory Management — Legacy API version reachable".to_string(),
            description: format!(
                "Path {} appears to expose a legacy API version. \
                 Legacy versions often lack current security controls.",
                ctx.path
            ),
            severity: "medium".to_string(),
            endpoint_path: ctx.path.clone(),
            endpoint_method: ctx.method.clone(),
            evidence,
            remediation:
                "Retire legacy API versions. If backward compatibility is required, ensure legacy \
                 routes apply the same security controls as current versions and are included in \
                 the official API inventory."
                    .to_string(),
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn redact(s: &str) -> String {
    if let Some(colon) = s.find(':') {
        format!("{}: \"***REDACTED***\"", &s[..colon])
    } else {
        "***REDACTED***".to_string()
    }
}

fn redact_short(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.len() > 120 {
        format!("{}…", &trimmed[..120])
    } else {
        trimmed.to_string()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(method: &str, path: &str) -> EndpointCtx {
        EndpointCtx {
            path: path.to_string(),
            method: method.to_string(),
        }
    }

    fn resp_simple(status: u16, body: &str) -> HttpResponse {
        HttpResponse {
            status_code: status,
            headers: HashMap::new(),
            body: body.to_string(),
            duration_ms: 50,
        }
    }

    fn resp_with_headers(status: u16, body: &str, headers: &[(&str, &str)]) -> HttpResponse {
        HttpResponse {
            status_code: status,
            headers: headers
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            body: body.to_string(),
            duration_ms: 50,
        }
    }

    #[test]
    fn test_pii_email_detected() {
        let r = resp_simple(200, r#"{"user_email": "alice@example.com"}"#);
        let f = check_excessive_data_exposure(&r, &ctx("GET", "/api/v1/users/1"));
        assert!(f
            .iter()
            .any(|x| x.evidence["pii_category"] == "email_address"));
    }

    #[test]
    fn test_pii_password_is_critical() {
        let r = resp_simple(200, r#"{"password": "s3cr3t!"}"#);
        let f = check_excessive_data_exposure(&r, &ctx("GET", "/api/v1/users/1"));
        let pw = f
            .iter()
            .find(|x| x.evidence["pii_category"] == "password_field");
        assert!(pw.is_some());
        assert_eq!(pw.unwrap().severity, "critical");
    }

    #[test]
    fn test_no_pii_clean() {
        let r = resp_simple(200, r#"{"id": 42, "role": "admin"}"#);
        let f = check_excessive_data_exposure(&r, &ctx("GET", "/api/v1/users/42"));
        assert!(f.is_empty());
    }

    #[test]
    fn test_timing_spike() {
        let samples = vec![50u64, 55, 48, 52, 51];
        let f = check_timing_anomaly(&ctx("GET", "/api/v1/reports"), &samples, 600);
        assert!(!f.is_empty());
        assert_eq!(f[0].owasp_id, "API4:2023");
    }

    #[test]
    fn test_timing_within_threshold() {
        let samples = vec![50u64, 55, 48, 52, 51];
        let f = check_timing_anomaly(&ctx("GET", "/api/v1/reports"), &samples, 100);
        assert!(f.is_empty());
    }

    #[test]
    fn test_missing_hsts_header() {
        let r = resp_with_headers(200, "{}", &[("content-type", "application/json")]);
        let f = check_security_headers(&r, &ctx("GET", "/api/v1/scans"));
        assert!(f
            .iter()
            .any(|x| x.title.contains("strict-transport-security")));
    }

    #[test]
    fn test_forbidden_header_flagged() {
        let r = resp_with_headers(200, "{}", &[("x-powered-by", "Express 4.18")]);
        let f = check_security_headers(&r, &ctx("GET", "/api/v1/scans"));
        assert!(f.iter().any(|x| x.title.contains("x-powered-by")));
    }

    #[test]
    fn test_sql_injection_indicator() {
        let body = r#"{"error": "You have an error in your SQL syntax near 'foo'"}"#;
        let r = resp_simple(500, body);
        let f = check_injection_indicators(&r, &ctx("GET", "/api/v1/users"));
        assert!(!f.is_empty());
        assert_eq!(f[0].severity, "critical");
    }

    #[test]
    fn test_no_injection_clean() {
        let r = resp_simple(200, r#"{"id": 1, "name": "Alice"}"#);
        let f = check_injection_indicators(&r, &ctx("GET", "/api/v1/users/1"));
        assert!(f.is_empty());
    }

    #[test]
    fn test_legacy_v1_path() {
        let r = resp_simple(200, "{}");
        let f = check_inventory(&r, &ctx("GET", "/v1/users"));
        assert!(f.iter().any(|x| x.owasp_id == "API9:2023"));
    }

    #[test]
    fn test_sunset_header_flagged() {
        let r = resp_with_headers(200, "{}", &[("sunset", "2024-01-01")]);
        let f = check_inventory(&r, &ctx("GET", "/api/v2/users"));
        assert!(!f.is_empty());
    }
}
