/// Integration tests for the APIGuard client using wiremock.
///
/// Each test spins up a fresh `MockServer`, points an `APIGuardClient` at it,
/// and asserts that the correct HTTP interactions occur and the SDK returns
/// the expected types or errors.
use opensecstack::{
    APIGuardClient, Error, FindingSeverity, FindingStatus, PatchFindingRequest, ScanStatus,
};
use std::time::Duration;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------- helpers ----------

/// A minimal valid JWT with exp = 9999999999 (year 2286), suitable for tests.
/// Header.Payload.Signature — payload is base64url({"exp":9999999999})
const FAKE_JWT: &str =
    "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.fake_signature_for_tests";

fn auth_response() -> serde_json::Value {
    serde_json::json!({
        "access_token": FAKE_JWT,
        "expires_in": 3600
    })
}

fn scan_json(id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "target_url": "https://api.example.com",
        "spec_url": "https://api.example.com/openapi.json",
        "spec_hash": null,
        "status": status,
        "modules": ["bola", "broken_auth"],
        "started_at": null,
        "completed_at": null,
        "created_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:00:00Z",
        "total_findings": 3,
        "critical_count": 1,
        "high_count": 1,
        "medium_count": 1,
        "low_count": 0,
        "info_count": 0,
        "error_message": null
    })
}

fn finding_json(id: &str, scan_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "scan_id": scan_id,
        "owasp_id": "API1:2023",
        "module_id": "bola",
        "title": "Broken Object Level Authorization",
        "description": "An attacker can access resources of other users.",
        "severity": "critical",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "endpoint_path": "/api/v1/users/{id}",
        "endpoint_method": "GET",
        "evidence_request": "GET /api/v1/users/42",
        "evidence_response": "HTTP/1.1 200 OK ...",
        "remediation": "Implement proper access control checks.",
        "status": "open",
        "triaged_by": null,
        "triaged_at": null,
        "triage_note": null,
        "created_at": "2024-01-15T10:05:00Z",
        "updated_at": "2024-01-15T10:05:00Z"
    })
}

async fn mock_auth(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response()))
        .mount(server)
        .await;
}

fn client(server: &MockServer) -> APIGuardClient {
    APIGuardClient::new(server.uri(), "test_api_key")
}

// ---------- test 1: authenticate success ----------

#[tokio::test]
async fn test_authenticate_success() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response()))
        .expect(1)
        .mount(&server)
        .await;

    // Also mock the scan endpoint so the client has something to call after auth.
    let scan_id = "550e8400-e29b-41d4-a716-446655440000";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(scan_json(scan_id, "completed")))
        .mount(&server)
        .await;

    let c = client(&server);

    // First call triggers authentication.
    let scan = c.get_scan(scan_id).await.expect("get_scan should succeed");
    assert_eq!(scan.id.to_string(), scan_id);
    assert_eq!(scan.status, ScanStatus::Completed);

    // Verify the token was cached: a second call should NOT hit the auth endpoint again.
    let scan2 = c.get_scan(scan_id).await.expect("second get_scan should succeed");
    assert_eq!(scan2.id.to_string(), scan_id);

    // wiremock's `expect(1)` will fail the test at drop if auth was called != 1 time.
    server.verify().await;
}

// ---------- test 2: authenticate failure ----------

#[tokio::test]
async fn test_authenticate_failure() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(serde_json::json!({"message": "invalid api key"})),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let err = c
        .get_scan("any-id")
        .await
        .expect_err("should fail with Auth error");

    assert!(
        matches!(err, Error::Auth(_)),
        "expected Error::Auth, got: {err:?}"
    );
}

// ---------- test 3: get_scan success ----------

#[tokio::test]
async fn test_get_scan() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(scan_json(scan_id, "running")))
        .mount(&server)
        .await;

    let c = client(&server);
    let scan = c.get_scan(scan_id).await.expect("get_scan failed");

    assert_eq!(scan.id.to_string(), scan_id);
    assert_eq!(scan.status, ScanStatus::Running);
    assert_eq!(scan.total_findings, 3);
    assert_eq!(scan.critical_count, 1);
    assert_eq!(scan.target_url, "https://api.example.com");
    assert_eq!(
        scan.modules,
        vec!["bola".to_string(), "broken_auth".to_string()]
    );
}

// ---------- test 4: get_scan not found ----------

#[tokio::test]
async fn test_get_scan_not_found() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let scan_id = "00000000-0000-0000-0000-000000000000";
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}")))
        .respond_with(
            ResponseTemplate::new(404).set_body_json(serde_json::json!({
                "code": "SCAN_NOT_FOUND",
                "message": "scan not found"
            })),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let err = c
        .get_scan(scan_id)
        .await
        .expect_err("should return not-found error");

    assert!(
        matches!(err, Error::NotFound(_)),
        "expected Error::NotFound, got: {err:?}"
    );
}

// ---------- test 5: list_scans with pagination ----------

#[tokio::test]
async fn test_list_scans_pagination() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let scan_id = "b1b2b3b4-e5f6-7890-abcd-ef1234567891";
    Mock::given(method("GET"))
        .and(path("/api/v1/scans"))
        .and(query_param("page", "2"))
        .and(query_param("per_page", "10"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([scan_json(scan_id, "completed")])),
        )
        .mount(&server)
        .await;

    use opensecstack::ListScansOptions;
    let c = client(&server);
    let scans = c
        .list_scans(Some(ListScansOptions {
            page: Some(2),
            per_page: Some(10),
            status: None,
        }))
        .await
        .expect("list_scans failed");

    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0].id.to_string(), scan_id);
    assert_eq!(scans[0].status, ScanStatus::Completed);
}

// ---------- test 6: patch_finding ----------

#[tokio::test]
async fn test_patch_finding() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let finding_id = "f1234567-89ab-cdef-0123-456789abcdef";
    let scan_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";

    let mut updated = finding_json(finding_id, scan_id);
    updated["status"] = serde_json::json!("false_positive");
    updated["triage_note"] = serde_json::json!("Reviewed and confirmed false positive.");

    Mock::given(method("PATCH"))
        .and(path(format!("/api/v1/findings/{finding_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(updated))
        .mount(&server)
        .await;

    let c = client(&server);
    let result = c
        .patch_finding(
            finding_id,
            PatchFindingRequest {
                status: FindingStatus::FalsePositive,
                note: Some("Reviewed and confirmed false positive.".to_string()),
            },
        )
        .await
        .expect("patch_finding failed");

    assert_eq!(result.id.to_string(), finding_id);
    assert_eq!(result.status, FindingStatus::FalsePositive);
}

// ---------- test 7: rate limit error ----------

#[tokio::test]
async fn test_rate_limit_error() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    Mock::given(method("GET"))
        .and(path("/api/v1/scans"))
        .respond_with(
            ResponseTemplate::new(429)
                .insert_header("retry-after", "30")
                .set_body_json(serde_json::json!({
                    "code": "RATE_LIMITED",
                    "message": "too many requests"
                })),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let err = c
        .list_scans(None)
        .await
        .expect_err("should return rate limit error");

    match err {
        Error::RateLimit { retry_after } => {
            assert_eq!(retry_after, 30, "retry_after should be 30 from header");
        }
        other => panic!("expected Error::RateLimit, got: {other:?}"),
    }
}

// ---------- test 8: get_findings with envelope ----------

#[tokio::test]
async fn test_get_findings_envelope() {
    let server = MockServer::start().await;
    mock_auth(&server).await;

    let scan_id = "c1d2e3f4-a5b6-7890-abcd-ef1234567892";
    let finding_id = "d1234567-89ab-cdef-0123-456789abcdef";

    // Server returns the {"data":[...]} envelope format.
    let envelope = serde_json::json!({
        "data": [finding_json(finding_id, scan_id)],
        "total": 1,
        "page": 1,
        "per_page": 20
    });

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}/findings")))
        .respond_with(ResponseTemplate::new(200).set_body_json(envelope))
        .mount(&server)
        .await;

    let c = client(&server);
    let findings = c
        .get_findings(scan_id, None)
        .await
        .expect("get_findings failed");

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].id.to_string(), finding_id);
    assert_eq!(findings[0].severity, FindingSeverity::Critical);
    assert_eq!(findings[0].owasp_id, "API1:2023");
    assert_eq!(findings[0].status, FindingStatus::Open);
    assert!((findings[0].cvss_score - 9.1).abs() < f64::EPSILON);
}

// ---------- test 9: retry on 5xx ----------

#[tokio::test]
async fn test_retry_on_5xx() {
    let server = MockServer::start().await;

    // Auth mock — always succeeds.
    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response()))
        .mount(&server)
        .await;

    let scan_id = "00000000-0000-0000-0000-000000000001";

    // First two GET /scans/{id} calls return 500.
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}")))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    // Third call succeeds.
    Mock::given(method("GET"))
        .and(path(format!("/api/v1/scans/{scan_id}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(scan_json(scan_id, "completed")))
        .mount(&server)
        .await;

    // Build a client with max_retries=2 and a tiny base wait so the test is fast.
    let client = APIGuardClient::builder(&server.uri(), "test_api_key")
        .max_retries(2)
        .retry_wait_base(Duration::from_millis(1))
        .build();

    let result = client.get_scan(scan_id).await;
    assert!(result.is_ok(), "expected Ok after retry, got: {result:?}");
    assert_eq!(result.unwrap().id.to_string(), scan_id);
}

// ---------- test 10: no retry on 4xx ----------

#[tokio::test]
async fn test_no_retry_on_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/auth/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(auth_response()))
        .mount(&server)
        .await;

    // Register a single 404 and assert it is called exactly once.
    // If the client retried, wiremock would either return a different response
    // or the `expect(1)` assertion would fail at server.verify().
    Mock::given(method("GET"))
        .and(path("/api/v1/scans/missing"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "code": "NOT_FOUND",
            "message": "scan not found"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let client = APIGuardClient::builder(&server.uri(), "test_api_key")
        .max_retries(2)
        .build();

    let result = client.get_scan("missing").await;
    assert!(
        matches!(result, Err(Error::NotFound(_))),
        "expected Error::NotFound, got: {result:?}"
    );

    // Confirms exactly one scan request was made (no retry on 4xx).
    server.verify().await;
}
