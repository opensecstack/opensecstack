/// Integration tests for the CITADEL client using wiremock.
///
/// Each test spins up a fresh `MockServer`, points a `CITADELClient` at it,
/// and asserts that the correct HTTP interactions occur and the SDK returns
/// the expected types or errors.
use opensecstack::{CITADELClient, CitadelGetEventsOptions, Error, SecurityEvent};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::time::Duration;
use wiremock::matchers::{body_json_schema, header_exists, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------- helpers ----------

fn event_json(id: &str, chain_hash: &str) -> serde_json::Value {
    json!({
        "id": id,
        "event_type": "apiguard.scan.completed",
        "source": "apiguard",
        "actor_id": "api-key-123",
        "actor_type": "api_key",
        "resource_type": "scan",
        "resource_id": "scan-abc",
        "severity": "info",
        "payload": {"score": 42},
        "chain_hash": chain_hash,
        "timestamp": "2026-01-01T12:00:00Z"
    })
}

fn make_event(id: &str, chain_hash: &str) -> SecurityEvent {
    serde_json::from_value(event_json(id, chain_hash)).expect("valid event")
}

/// Compute SHA-256(prev_chain_hash_bytes || payload_json_bytes).
fn compute_chain_hash(prev_chain_hash: &str, payload: &serde_json::Value) -> String {
    let payload_bytes = serde_json::to_vec(payload).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(prev_chain_hash.as_bytes());
    hasher.update(&payload_bytes);
    hex::encode(hasher.finalize())
}

fn client(server: &MockServer) -> CITADELClient {
    CITADELClient::with_options(
        server.uri(),
        "test-secret",
        3,
        Duration::from_millis(1),
    )
}

// ---------- test 1: disabled mode — send_event ok ----------

#[tokio::test]
async fn test_disabled_send_event_is_noop() {
    // No mock server: any real HTTP request would fail.
    let c = CITADELClient::new("", "secret");
    let result = c.send_event(make_event("e1", "genesis")).await;
    assert!(result.is_ok(), "send_event in disabled mode should return Ok");
}

// ---------- test 2: disabled mode — get_events returns empty ----------

#[tokio::test]
async fn test_disabled_get_events_returns_empty() {
    let c = CITADELClient::new("", "secret");
    let events = c.get_events(CitadelGetEventsOptions::default()).await.unwrap();
    assert!(events.is_empty(), "get_events in disabled mode should return empty vec");
}

// ---------- test 3: disabled mode — get_event returns error ----------

#[tokio::test]
async fn test_disabled_get_event_returns_error() {
    let c = CITADELClient::new("", "secret");
    let result = c.get_event("any-id").await;
    assert!(result.is_err(), "get_event in disabled mode should return Err");
}

// ---------- test 4: disabled mode — drain ok ----------

#[tokio::test]
async fn test_disabled_drain_ok() {
    let c = CITADELClient::new("", "secret");
    let result = c.drain(Some(Duration::from_millis(1))).await;
    assert!(result.is_ok());
}

// ---------- test 5: send_event posts with HMAC signature header ----------

#[tokio::test]
async fn test_send_event_posts_with_signature_header() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .and(header_exists("X-Citadel-Signature"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let c = client(&server);
    c.send_event(make_event("e1", "genesis")).await.unwrap();

    // Give the background worker time to deliver.
    tokio::time::sleep(Duration::from_millis(50)).await;
    server.verify().await;
}

// ---------- test 6: send_event signature prefix is "sha256=" ----------

#[tokio::test]
async fn test_send_event_signature_has_sha256_prefix() {
    let server = MockServer::start().await;

    // Capture the request so we can inspect the header value.
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    let c = client(&server);
    c.send_event(make_event("e1", "genesis")).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let received = server.received_requests().await.unwrap();
    assert!(!received.is_empty(), "expected at least one request");
    let sig = received[0]
        .headers
        .get("x-citadel-signature")
        .expect("X-Citadel-Signature header present")
        .to_str()
        .unwrap();
    assert!(sig.starts_with("sha256="), "signature should start with 'sha256=', got: {sig}");
}

// ---------- test 7: get_events — plain array response ----------

#[tokio::test]
async fn test_get_events_plain_array() {
    let server = MockServer::start().await;

    let body = json!([
        event_json("e1", "hash1"),
        event_json("e2", "hash2")
    ]);

    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let c = client(&server);
    let events = c.get_events(CitadelGetEventsOptions::default()).await.unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].id, "e1");
    assert_eq!(events[1].id, "e2");
}

// ---------- test 8: get_events — paginated envelope ----------

#[tokio::test]
async fn test_get_events_envelope() {
    let server = MockServer::start().await;

    let body = json!({
        "items": [event_json("env-1", "h1")],
        "total": 1
    });

    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let c = client(&server);
    let events = c.get_events(CitadelGetEventsOptions::default()).await.unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "env-1");
}

// ---------- test 9: get_events — source filter forwarded ----------

#[tokio::test]
async fn test_get_events_source_filter() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(query_param("source", "apiguard"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let c = client(&server);
    let opts = CitadelGetEventsOptions {
        source: Some("apiguard".to_string()),
        ..Default::default()
    };
    c.get_events(opts).await.unwrap();
    server.verify().await;
}

// ---------- test 10: get_events — event_type filter forwarded ----------

#[tokio::test]
async fn test_get_events_event_type_filter() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .and(query_param("event_type", "apiguard.scan.completed"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let c = client(&server);
    let opts = CitadelGetEventsOptions {
        event_type: Some("apiguard.scan.completed".to_string()),
        ..Default::default()
    };
    c.get_events(opts).await.unwrap();
    server.verify().await;
}

// ---------- test 11: get_event by ID — success ----------

#[tokio::test]
async fn test_get_event_by_id() {
    let server = MockServer::start().await;
    let event_id = "evt-abc-123";

    Mock::given(method("GET"))
        .and(path(format!("/api/v1/events/{event_id}")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(event_json(event_id, "hash-abc")),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let ev = c.get_event(event_id).await.unwrap();
    assert_eq!(ev.id, event_id);
    assert_eq!(ev.source, "apiguard");
    assert_eq!(ev.severity, "info");
}

// ---------- test 12: get_event — 404 not found ----------

#[tokio::test]
async fn test_get_event_not_found() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/events/missing"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"message": "event not found"})),
        )
        .mount(&server)
        .await;

    let c = client(&server);
    let err = c.get_event("missing").await.expect_err("should fail with NotFound");
    assert!(
        matches!(err, Error::NotFound(_)),
        "expected Error::NotFound, got: {err:?}"
    );
}

// ---------- test 13: verify_chain — valid single event ----------

#[tokio::test]
async fn test_verify_chain_single_event_ok() {
    let events = vec![make_event("e1", "genesis")];
    let result = CITADELClient::verify_chain(&events);
    assert!(result.is_ok());
}

// ---------- test 14: verify_chain — empty slice ok ----------

#[tokio::test]
async fn test_verify_chain_empty_ok() {
    let result = CITADELClient::verify_chain(&[]);
    assert!(result.is_ok());
}

// ---------- test 15: verify_chain — valid 3-event chain ----------

#[tokio::test]
async fn test_verify_chain_valid_three_events() {
    let payload0 = json!({"score": 42});
    let payload1 = json!({"step": 1});
    let payload2 = json!({"step": 2});

    // Build a valid chain.
    let hash0 = "genesis";
    let hash1 = compute_chain_hash(hash0, &payload1);
    let hash2 = compute_chain_hash(&hash1, &payload2);

    let mut ev0 = make_event("e0", hash0);
    ev0.payload = payload0;
    let mut ev1 = make_event("e1", &hash1);
    ev1.payload = payload1;
    let mut ev2 = make_event("e2", &hash2);
    ev2.payload = payload2;

    let result = CITADELClient::verify_chain(&[ev0, ev1, ev2]);
    assert!(result.is_ok(), "valid chain should pass: {result:?}");
}

// ---------- test 16: verify_chain — broken link ----------

#[tokio::test]
async fn test_verify_chain_broken_link() {
    let ev0 = make_event("e0", "genesis");
    let ev1 = make_event("e1", "wrong-hash"); // deliberate mismatch

    let result = CITADELClient::verify_chain(&[ev0, ev1]);
    assert!(
        result.is_err(),
        "broken chain should return Err"
    );
}

// ---------- test 17: retry on 5xx — succeeds on 3rd attempt ----------

#[tokio::test]
async fn test_send_event_retry_on_5xx() {
    let server = MockServer::start().await;

    // First two calls return 500.
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(2)
        .mount(&server)
        .await;

    // Third call succeeds.
    Mock::given(method("POST"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({})))
        .mount(&server)
        .await;

    // Client with max_retries=3 and 1ms base — should succeed after retries.
    let c = CITADELClient::with_options(server.uri(), "secret", 3, Duration::from_millis(1));
    c.send_event(make_event("e1", "genesis")).await.unwrap();

    // Wait for background delivery.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let requests = server.received_requests().await.unwrap();
    assert!(requests.len() >= 3, "expected at least 3 attempts, got {}", requests.len());
}

// ---------- test 18: get_events — empty response ----------

#[tokio::test]
async fn test_get_events_empty() {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("/api/v1/events"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let c = client(&server);
    let events = c.get_events(CitadelGetEventsOptions::default()).await.unwrap();
    assert!(events.is_empty());
}
