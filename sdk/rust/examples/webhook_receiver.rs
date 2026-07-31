//! # Webhook Receiver Example
//!
//! A minimal HTTP server (using Axum) that listens for signed webhook events
//! from the opensecstack platforms (APIGuard, NIS2 Compass, CITADEL),
//! verifies the HMAC-SHA256 signature, parses the event envelope, and
//! dispatches to a typed handler per event type.
//!
//! ## Usage
//!
//! ```bash
//! WEBHOOK_SECRET=my-webhook-secret cargo run --example webhook_receiver
//! ```
//!
//! The server listens on `0.0.0.0:8080` (override with the `PORT` env var).
//!
//! ## Sending a test event
//!
//! ```bash
//! SECRET=my-webhook-secret
//! BODY='{"id":"evt_1","event_type":"apiguard.scan.completed","source":"apiguard","timestamp":"2026-03-30T00:00:00Z","payload":{"scan_id":"abc","target":"https://api.example.com","stats":{"total":3,"critical":1,"high":1,"medium":1,"low":0}}}'
//! SIG="sha256=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print $2}')"
//! curl -s -X POST http://localhost:8080/webhooks \
//!      -H "Content-Type: application/json" \
//!      -H "X-APIGuard-Signature: $SIG" \
//!      -d "$BODY"
//! ```

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Router,
};
use bytes::Bytes;
use opensecstack::webhook::{
    parse_event, verify_signature, WebhookEvent, EVENT_APIGUARD_FINDING_CRITICAL,
    EVENT_APIGUARD_SCAN_COMPLETED, EVENT_APIGUARD_SCAN_FAILED, EVENT_CITADEL_HARD_STOP,
    EVENT_CITADEL_VIGIL_AMBER, EVENT_CITADEL_VIGIL_RED, EVENT_NIS2COMPASS_ASSESSMENT_COMPLETED,
    EVENT_NIS2COMPASS_CONTROL_UPDATED,
};
use std::env;

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    webhook_secret: String,
}

// ---------------------------------------------------------------------------
// Webhook handler
// ---------------------------------------------------------------------------

async fn webhook_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    // Accept signature from either platform header (case-insensitive via axum).
    let sig = headers
        .get("x-apiguard-signature")
        .or_else(|| headers.get("x-citadel-signature"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // 1. Verify HMAC-SHA256 signature before doing anything else.
    if let Err(e) = verify_signature(&body, sig, &state.webhook_secret) {
        tracing::warn!("webhook signature verification failed: {e}");
        return StatusCode::BAD_REQUEST;
    }

    // 2. Parse the event envelope.
    let event = match parse_event(&body) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("failed to parse webhook event: {e}");
            return StatusCode::UNPROCESSABLE_ENTITY;
        }
    };

    // 3. Dispatch by event type.
    dispatch_event(&event);

    StatusCode::OK
}

/// Route a verified, parsed event to the appropriate handler function.
fn dispatch_event(event: &WebhookEvent) {
    match event.event_type.as_str() {
        EVENT_APIGUARD_SCAN_COMPLETED => handle_scan_completed(event),
        EVENT_APIGUARD_SCAN_FAILED => handle_scan_failed(event),
        EVENT_APIGUARD_FINDING_CRITICAL => handle_finding_critical(event),
        EVENT_NIS2COMPASS_CONTROL_UPDATED => handle_control_updated(event),
        EVENT_NIS2COMPASS_ASSESSMENT_COMPLETED => handle_assessment_completed(event),
        EVENT_CITADEL_HARD_STOP => handle_hard_stop(event),
        EVENT_CITADEL_VIGIL_RED => handle_vigil_red(event),
        EVENT_CITADEL_VIGIL_AMBER => handle_vigil_amber(event),
        other => {
            tracing::info!(
                event_type = other,
                event_id = %event.id,
                source = %event.source,
                "received unhandled event type"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Per-event-type handlers
// ---------------------------------------------------------------------------

fn handle_scan_completed(event: &WebhookEvent) {
    let scan_id = event.payload["scan_id"].as_str().unwrap_or("");
    let target = event.payload["target"].as_str().unwrap_or("");
    let stats = &event.payload["stats"];
    tracing::info!(
        event_id = %event.id,
        scan_id,
        target,
        critical = stats["critical"].as_i64().unwrap_or(0),
        high = stats["high"].as_i64().unwrap_or(0),
        medium = stats["medium"].as_i64().unwrap_or(0),
        low = stats["low"].as_i64().unwrap_or(0),
        total = stats["total"].as_i64().unwrap_or(0),
        "apiguard.scan.completed"
    );
}

fn handle_scan_failed(event: &WebhookEvent) {
    let scan_id = event.payload["scan_id"].as_str().unwrap_or("");
    let error = event.payload["error"].as_str().unwrap_or("unknown");
    tracing::warn!(
        event_id = %event.id,
        scan_id,
        error,
        "apiguard.scan.failed"
    );
}

fn handle_finding_critical(event: &WebhookEvent) {
    let p = &event.payload;
    tracing::error!(
        event_id = %event.id,
        scan_id = p["scan_id"].as_str().unwrap_or(""),
        finding_id = p["finding_id"].as_str().unwrap_or(""),
        owasp = p["owasp"].as_str().unwrap_or(""),
        title = p["title"].as_str().unwrap_or(""),
        endpoint = p["endpoint"].as_str().unwrap_or(""),
        "apiguard.finding.critical"
    );
}

fn handle_control_updated(event: &WebhookEvent) {
    let p = &event.payload;
    tracing::info!(
        event_id = %event.id,
        org_id = p["org_id"].as_str().unwrap_or(""),
        assessment_id = p["assessment_id"].as_str().unwrap_or(""),
        measure_ref = p["measure_ref"].as_str().unwrap_or(""),
        previous_status = p["previous_status"].as_str().unwrap_or(""),
        new_status = p["new_status"].as_str().unwrap_or(""),
        updated_by = p["updated_by"].as_str().unwrap_or(""),
        "nis2compass.control.updated"
    );
}

fn handle_assessment_completed(event: &WebhookEvent) {
    let p = &event.payload;
    let stats = &p["stats"];
    tracing::info!(
        event_id = %event.id,
        org_id = p["org_id"].as_str().unwrap_or(""),
        assessment_id = p["assessment_id"].as_str().unwrap_or(""),
        compliant = stats["compliant"].as_i64().unwrap_or(0),
        partially_compliant = stats["partially_compliant"].as_i64().unwrap_or(0),
        non_compliant = stats["non_compliant"].as_i64().unwrap_or(0),
        "nis2compass.assessment.completed"
    );
}

fn handle_hard_stop(event: &WebhookEvent) {
    let p = &event.payload;
    tracing::error!(
        event_id = %event.id,
        execution_id = p["execution_id"].as_str().unwrap_or(""),
        actor_user_id = p["actor_user_id"].as_str().unwrap_or(""),
        trigger = p["trigger"].as_str().unwrap_or(""),
        irflow_incident_id = p["irflow_incident_id"].as_str().unwrap_or(""),
        "CITADEL HARD STOP"
    );
}

fn handle_vigil_red(event: &WebhookEvent) {
    let p = &event.payload;
    tracing::error!(
        event_id = %event.id,
        previous_state = p["previous_state"].as_str().unwrap_or(""),
        reason = p["reason"].as_str().unwrap_or(""),
        active_hard_stops = p["active_hard_stops"].as_i64().unwrap_or(0),
        "CITADEL VIGIL RED"
    );
}

fn handle_vigil_amber(event: &WebhookEvent) {
    let p = &event.payload;
    tracing::warn!(
        event_id = %event.id,
        previous_state = p["previous_state"].as_str().unwrap_or(""),
        reason = p["reason"].as_str().unwrap_or(""),
        mirror_id = p["mirror_id"].as_str().unwrap_or(""),
        age_seconds = p["age_seconds"].as_i64().unwrap_or(0),
        "CITADEL VIGIL AMBER"
    );
}

// ---------------------------------------------------------------------------
// Health check
// ---------------------------------------------------------------------------

async fn health() -> &'static str {
    "ok"
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    let secret = env::var("WEBHOOK_SECRET").unwrap_or_else(|_| {
        tracing::error!("WEBHOOK_SECRET environment variable is required");
        std::process::exit(1);
    });

    let port: u16 = env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let state = AppState {
        webhook_secret: secret,
    };

    let app = Router::new()
        .route("/webhooks", post(webhook_handler))
        .route("/health", get(health))
        .with_state(state);

    let addr = format!("0.0.0.0:{port}");
    tracing::info!("webhook_receiver listening on http://{addr}  (POST /webhooks)");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind TCP listener");

    axum::serve(listener, app).await.expect("server error");
}
