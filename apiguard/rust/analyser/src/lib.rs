use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A single HTTP response captured during testing.
#[derive(Debug, Clone, Deserialize)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
}

/// A pair of responses for comparison-based analysis.
#[derive(Debug, Clone, Deserialize)]
pub struct ResponsePair {
    pub baseline: HttpResponse,
    pub test: HttpResponse,
}

/// The type of analysis to perform.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisType {
    AuthBypass,
    DataLeakage,
    ErrorDisclosure,
    TimingAnomaly,
    HeaderAnalysis,
    ContentTypeMismatch,
    RedirectAnalysis,
}

/// An analysis finding from the response analyser.
#[derive(Debug, Clone, Serialize)]
pub struct AnalysisFinding {
    pub analysis_type: String,
    pub severity: String,
    pub description: String,
    pub evidence: HashMap<String, serde_json::Value>,
}

/// Analyse a single response or pair of responses.
pub fn analyse(
    analysis_type: AnalysisType,
    response: &HttpResponse,
    baseline: Option<&HttpResponse>,
) -> Vec<AnalysisFinding> {
    match analysis_type {
        AnalysisType::AuthBypass => analyse_auth_bypass(response, baseline),
        AnalysisType::DataLeakage => analyse_data_leakage(response),
        AnalysisType::ErrorDisclosure => analyse_error_disclosure(response),
        AnalysisType::TimingAnomaly => analyse_timing(response, baseline),
        AnalysisType::HeaderAnalysis => analyse_headers(response),
        AnalysisType::ContentTypeMismatch => analyse_content_type(response),
        AnalysisType::RedirectAnalysis => analyse_redirect(response),
    }
}

fn status_class(code: u16) -> u16 {
    code / 100
}

fn analyse_auth_bypass(
    response: &HttpResponse,
    baseline: Option<&HttpResponse>,
) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();

    let baseline = match baseline {
        Some(b) => b,
        None => return findings,
    };

    let baseline_status = baseline.status_code;
    let test_status = response.status_code;

    // Auth bypass: baseline was 401/403 and test is 200
    if (baseline_status == 401 || baseline_status == 403) && test_status == 200 {
        let mut evidence = HashMap::new();
        evidence.insert(
            "baseline_status".to_string(),
            serde_json::json!(baseline_status),
        );
        evidence.insert("test_status".to_string(), serde_json::json!(test_status));

        findings.push(AnalysisFinding {
            analysis_type: "auth_bypass".to_string(),
            severity: "critical".to_string(),
            description: format!(
                "Authentication bypass detected: baseline returned {} but test request returned {}",
                baseline_status, test_status
            ),
            evidence,
        });
        return findings;
    }

    // Status codes differ significantly (different class)
    if status_class(baseline_status) != status_class(test_status) {
        let mut evidence = HashMap::new();
        evidence.insert(
            "baseline_status".to_string(),
            serde_json::json!(baseline_status),
        );
        evidence.insert("test_status".to_string(), serde_json::json!(test_status));

        findings.push(AnalysisFinding {
            analysis_type: "auth_bypass".to_string(),
            severity: "high".to_string(),
            description: format!(
                "Significant status code difference: baseline {} vs test {}",
                baseline_status, test_status
            ),
            evidence,
        });
        return findings;
    }

    // Both 2xx but body sizes differ by >= 10% — potential data difference
    if status_class(test_status) == 2 && status_class(baseline_status) == 2 {
        let baseline_len = baseline.body.len() as f64;
        let test_len = response.body.len() as f64;
        if baseline_len > 0.0 {
            let diff_ratio = (test_len - baseline_len).abs() / baseline_len;
            if diff_ratio >= 0.10 {
                let mut evidence = HashMap::new();
                evidence.insert(
                    "baseline_body_size".to_string(),
                    serde_json::json!(baseline.body.len()),
                );
                evidence.insert(
                    "test_body_size".to_string(),
                    serde_json::json!(response.body.len()),
                );
                evidence.insert("diff_ratio".to_string(), serde_json::json!(diff_ratio));

                findings.push(AnalysisFinding {
                    analysis_type: "auth_bypass".to_string(),
                    severity: "medium".to_string(),
                    description: format!(
                        "Both responses are 2xx but body size differs by {:.1}% — possible data access difference",
                        diff_ratio * 100.0
                    ),
                    evidence,
                });
            }
        }
    }

    findings
}

fn analyse_data_leakage(response: &HttpResponse) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();
    let body = &response.body;

    // Credit card pattern
    let cc_re =
        Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b").unwrap();
    if cc_re.is_match(body) {
        let matches: Vec<&str> = cc_re.find_iter(body).map(|m| m.as_str()).collect();
        let mut evidence = HashMap::new();
        evidence.insert(
            "matches_count".to_string(),
            serde_json::json!(matches.len()),
        );
        evidence.insert(
            "sample".to_string(),
            serde_json::json!(matches.first().map(|s| mask_middle(s))),
        );
        findings.push(AnalysisFinding {
            analysis_type: "data_leakage".to_string(),
            severity: "critical".to_string(),
            description: "Credit card number(s) found in response body".to_string(),
            evidence,
        });
    }

    // Private key
    let pk_re = Regex::new(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").unwrap();
    if pk_re.is_match(body) {
        let mut evidence = HashMap::new();
        evidence.insert(
            "pattern".to_string(),
            serde_json::json!("PRIVATE KEY header"),
        );
        findings.push(AnalysisFinding {
            analysis_type: "data_leakage".to_string(),
            severity: "critical".to_string(),
            description: "Private key material found in response body".to_string(),
            evidence,
        });
    }

    // AWS key
    let aws_re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
    if aws_re.is_match(body) {
        let matches: Vec<&str> = aws_re.find_iter(body).map(|m| m.as_str()).collect();
        let mut evidence = HashMap::new();
        evidence.insert(
            "matches_count".to_string(),
            serde_json::json!(matches.len()),
        );
        findings.push(AnalysisFinding {
            analysis_type: "data_leakage".to_string(),
            severity: "critical".to_string(),
            description: "AWS access key ID found in response body".to_string(),
            evidence,
        });
    }

    // JWT in body
    let jwt_re = Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+").unwrap();
    if jwt_re.is_match(body) {
        let mut evidence = HashMap::new();
        evidence.insert(
            "pattern".to_string(),
            serde_json::json!("JWT token pattern"),
        );
        findings.push(AnalysisFinding {
            analysis_type: "data_leakage".to_string(),
            severity: "high".to_string(),
            description: "JWT token found in response body".to_string(),
            evidence,
        });
    }

    // Password/secret fields in JSON
    let sensitive_keys = ["password", "passwd", "secret", "token"];
    for key in &sensitive_keys {
        // Match: "key": <non-null value>
        let pattern = format!(r#""{}"\s*:\s*(?!"null"|null\b)"#, regex::escape(key));
        if let Ok(re) = Regex::new(&pattern) {
            if re.is_match(body) {
                let mut evidence = HashMap::new();
                evidence.insert("key".to_string(), serde_json::json!(key));
                findings.push(AnalysisFinding {
                    analysis_type: "data_leakage".to_string(),
                    severity: "high".to_string(),
                    description: format!(
                        "Sensitive field '{}' with non-null value found in response body",
                        key
                    ),
                    evidence,
                });
            }
        }
    }

    // Email addresses — only flag if multiple found (suggests bulk leakage)
    let email_re = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap();
    let email_matches: Vec<&str> = email_re.find_iter(body).map(|m| m.as_str()).collect();
    if email_matches.len() > 1 {
        let mut evidence = HashMap::new();
        evidence.insert(
            "email_count".to_string(),
            serde_json::json!(email_matches.len()),
        );
        findings.push(AnalysisFinding {
            analysis_type: "data_leakage".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "Multiple email addresses ({}) found in response body — possible bulk data leakage",
                email_matches.len()
            ),
            evidence,
        });
    }

    findings
}

fn analyse_error_disclosure(response: &HttpResponse) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();
    let body = &response.body;

    // SQL error patterns
    let sql_patterns = [
        "SQL syntax",
        "mysql_fetch",
        "ORA-",
        "sqlite3.OperationalError",
        "pg_exec",
    ];
    for pattern in &sql_patterns {
        if body.contains(pattern) {
            let mut evidence = HashMap::new();
            evidence.insert("pattern".to_string(), serde_json::json!(pattern));
            findings.push(AnalysisFinding {
                analysis_type: "error_disclosure".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "SQL error disclosure detected: pattern '{}' found in response",
                    pattern
                ),
                evidence,
            });
        }
    }

    // Path disclosure patterns
    let path_patterns = ["/home/", "/var/www/", r"C:\Users\", r"C:\inetpub\"];
    for pattern in &path_patterns {
        if body.contains(pattern) {
            let mut evidence = HashMap::new();
            evidence.insert("pattern".to_string(), serde_json::json!(pattern));
            findings.push(AnalysisFinding {
                analysis_type: "error_disclosure".to_string(),
                severity: "high".to_string(),
                description: format!(
                    "File system path disclosure detected: pattern '{}' found in response",
                    pattern
                ),
                evidence,
            });
        }
    }

    // Stack trace patterns
    let trace_patterns = [
        "at com.",
        "at java.",
        "Traceback (most recent",
        "at org.",
        ".php on line",
    ];
    for pattern in &trace_patterns {
        if body.contains(pattern) {
            let mut evidence = HashMap::new();
            evidence.insert("pattern".to_string(), serde_json::json!(pattern));
            findings.push(AnalysisFinding {
                analysis_type: "error_disclosure".to_string(),
                severity: "medium".to_string(),
                description: format!(
                    "Stack trace disclosure detected: pattern '{}' found in response",
                    pattern
                ),
                evidence,
            });
        }
    }

    findings
}

fn analyse_timing(
    response: &HttpResponse,
    baseline: Option<&HttpResponse>,
) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();

    let baseline = match baseline {
        Some(b) => b,
        None => return findings,
    };

    let baseline_ms = baseline.duration_ms;
    let test_ms = response.duration_ms;

    if baseline_ms > 0 && test_ms > baseline_ms * 3 && test_ms > 3000 {
        let mut evidence = HashMap::new();
        evidence.insert(
            "baseline_duration_ms".to_string(),
            serde_json::json!(baseline_ms),
        );
        evidence.insert("test_duration_ms".to_string(), serde_json::json!(test_ms));
        evidence.insert(
            "ratio".to_string(),
            serde_json::json!(test_ms as f64 / baseline_ms as f64),
        );

        findings.push(AnalysisFinding {
            analysis_type: "timing_anomaly".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "Timing anomaly detected: test response took {}ms vs baseline {}ms ({}x slower) — possible timing attack vector",
                test_ms,
                baseline_ms,
                test_ms / baseline_ms
            ),
            evidence,
        });
    }

    findings
}

fn analyse_headers(response: &HttpResponse) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();

    // Normalise header keys to lowercase for lookup
    let headers: HashMap<String, String> = response
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    // X-Content-Type-Options: nosniff
    match headers.get("x-content-type-options") {
        None => {
            let mut evidence = HashMap::new();
            evidence.insert(
                "header".to_string(),
                serde_json::json!("X-Content-Type-Options"),
            );
            findings.push(AnalysisFinding {
                analysis_type: "header_analysis".to_string(),
                severity: "medium".to_string(),
                description: "Missing security header: X-Content-Type-Options".to_string(),
                evidence,
            });
        }
        Some(val) if !val.to_lowercase().contains("nosniff") => {
            let mut evidence = HashMap::new();
            evidence.insert(
                "header".to_string(),
                serde_json::json!("X-Content-Type-Options"),
            );
            evidence.insert("value".to_string(), serde_json::json!(val));
            findings.push(AnalysisFinding {
                analysis_type: "header_analysis".to_string(),
                severity: "medium".to_string(),
                description: "X-Content-Type-Options is present but not set to 'nosniff'"
                    .to_string(),
                evidence,
            });
        }
        _ => {}
    }

    // X-Frame-Options or Content-Security-Policy
    let has_xfo = headers.contains_key("x-frame-options");
    let has_csp = headers.contains_key("content-security-policy");
    if !has_xfo && !has_csp {
        let mut evidence = HashMap::new();
        evidence.insert(
            "missing_headers".to_string(),
            serde_json::json!(["X-Frame-Options", "Content-Security-Policy"]),
        );
        findings.push(AnalysisFinding {
            analysis_type: "header_analysis".to_string(),
            severity: "medium".to_string(),
            description: "Neither X-Frame-Options nor Content-Security-Policy header is present — clickjacking protection missing".to_string(),
            evidence,
        });
    }

    // Server header with version info
    if let Some(server_val) = headers.get("server") {
        // Heuristic: if the value contains a digit it likely includes a version
        if server_val.chars().any(|c| c.is_ascii_digit()) {
            let mut evidence = HashMap::new();
            evidence.insert("header".to_string(), serde_json::json!("Server"));
            evidence.insert("value".to_string(), serde_json::json!(server_val));
            findings.push(AnalysisFinding {
                analysis_type: "header_analysis".to_string(),
                severity: "low".to_string(),
                description: "Server header discloses version information".to_string(),
                evidence,
            });
        }
    }

    // X-Powered-By present
    if let Some(xpb_val) = headers.get("x-powered-by") {
        let mut evidence = HashMap::new();
        evidence.insert("header".to_string(), serde_json::json!("X-Powered-By"));
        evidence.insert("value".to_string(), serde_json::json!(xpb_val));
        findings.push(AnalysisFinding {
            analysis_type: "header_analysis".to_string(),
            severity: "low".to_string(),
            description: "X-Powered-By header discloses technology stack information".to_string(),
            evidence,
        });
    }

    findings
}

fn analyse_content_type(response: &HttpResponse) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();

    let body_trimmed = response.body.trim_start();
    let looks_like_json = body_trimmed.starts_with('{') || body_trimmed.starts_with('[');

    if !looks_like_json {
        return findings;
    }

    let headers: HashMap<String, String> = response
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let content_type_is_json = headers
        .get("content-type")
        .map(|ct| ct.to_lowercase().contains("json"))
        .unwrap_or(false);

    if !content_type_is_json {
        let ct_value = headers
            .get("content-type")
            .cloned()
            .unwrap_or_else(|| "<absent>".to_string());
        let mut evidence = HashMap::new();
        evidence.insert("content_type".to_string(), serde_json::json!(ct_value));
        evidence.insert(
            "body_prefix".to_string(),
            serde_json::json!(&body_trimmed.chars().take(20).collect::<String>()),
        );
        findings.push(AnalysisFinding {
            analysis_type: "content_type_mismatch".to_string(),
            severity: "medium".to_string(),
            description: format!(
                "Content-Type mismatch: body appears to be JSON but Content-Type is '{}'",
                ct_value
            ),
            evidence,
        });
    }

    findings
}

fn analyse_redirect(response: &HttpResponse) -> Vec<AnalysisFinding> {
    let mut findings = Vec::new();

    let status = response.status_code;
    if !(300..400).contains(&status) {
        return findings;
    }

    let headers: HashMap<String, String> = response
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let location = match headers.get("location") {
        Some(l) => l.clone(),
        None => return findings,
    };

    // Extract the origin host from the request — we look for the Host request header
    // If no Host header, we try to infer from the Location itself and flag absolute URLs to external hosts.
    let host_header = headers.get("host").cloned().unwrap_or_default();

    let is_external = if location.starts_with("http://") || location.starts_with("https://") {
        // Parse just the host portion
        let after_scheme = location
            .trim_start_matches("http://")
            .trim_start_matches("https://");
        let location_host = after_scheme
            .split('/')
            .next()
            .unwrap_or("")
            .split('?')
            .next()
            .unwrap_or("");
        // Strip port for comparison
        let location_host_no_port = location_host.split(':').next().unwrap_or(location_host);
        let origin_host_no_port = host_header.split(':').next().unwrap_or(&host_header);

        !origin_host_no_port.is_empty() && location_host_no_port != origin_host_no_port
    } else {
        false // relative redirect — safe
    };

    if is_external {
        let mut evidence = HashMap::new();
        evidence.insert("status_code".to_string(), serde_json::json!(status));
        evidence.insert("location".to_string(), serde_json::json!(location));
        evidence.insert("origin_host".to_string(), serde_json::json!(host_header));
        findings.push(AnalysisFinding {
            analysis_type: "redirect_analysis".to_string(),
            severity: "high".to_string(),
            description: format!(
                "Potential open redirect: status {} redirects to external host '{}'",
                status, location
            ),
            evidence,
        });
    }

    findings
}

/// Masks the middle characters of a string for safe display.
fn mask_middle(s: &str) -> String {
    if s.len() <= 4 {
        return "*".repeat(s.len());
    }
    let visible = 4;
    format!("{}...{}", &s[..visible / 2], &s[s.len() - visible / 2..])
}
