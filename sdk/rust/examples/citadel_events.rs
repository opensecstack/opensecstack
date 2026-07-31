//! # CITADEL Events Example
//!
//! Demonstrates the full CITADEL client lifecycle:
//!
//! 1. Build a [`CITADELClient`] with HMAC signing and retry options.
//! 2. Send a test [`SecurityEvent`] (non-blocking — queued to background worker).
//! 3. Query recent events with optional source and date filters.
//! 4. Verify the SHA-256 hash chain across the returned events.
//! 5. Fetch a single event by ID.
//! 6. Drain the client on graceful shutdown.
//!
//! ## Usage
//!
//! ```bash
//! CITADEL_URL=https://citadel.internal \
//! CITADEL_SHARED_SECRET=supersecret \
//! cargo run --example citadel_events
//! ```
//!
//! ## Required environment variables
//!
//! | Variable               | Description                                         |
//! |------------------------|-----------------------------------------------------|
//! | `CITADEL_URL`          | Base URL of your CITADEL instance                   |
//! | `CITADEL_SHARED_SECRET`| HMAC-SHA256 shared signing secret                   |
//!
//! ## Optional environment variables
//!
//! | Variable         | Default     | Description                             |
//! |------------------|-------------|-----------------------------------------|
//! | `CITADEL_SOURCE` | `apiguard`  | Source filter for `get_events`          |

use chrono::Utc;
use opensecstack::{CITADELClient, CitadelGetEventsOptions, SecurityEvent};
use serde_json::json;
use std::env;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base_url = require_env("CITADEL_URL");
    let shared_secret = require_env("CITADEL_SHARED_SECRET");
    let source = env::var("CITADEL_SOURCE").unwrap_or_else(|_| "apiguard".to_string());

    // ------------------------------------------------------------------
    // 1. Build the client.
    // ------------------------------------------------------------------
    println!("Building CITADEL client — base URL: {base_url}");
    let client = CITADELClient::with_options(
        &base_url,
        &shared_secret,
        3,                          // max_retries
        Duration::from_millis(500), // retry_wait_base
    );

    // ------------------------------------------------------------------
    // 2. Send a test event (non-blocking).
    // ------------------------------------------------------------------
    let event_id = format!("evt_{}", uuid::Uuid::new_v4().simple());
    let event = SecurityEvent {
        id: event_id.clone(),
        event_type: "apiguard.scan.completed".to_string(),
        source: "apiguard".to_string(),
        actor_id: "ak_example_key".to_string(),
        actor_type: "api_key".to_string(),
        resource_type: "scan".to_string(),
        resource_id: "scan_abc123".to_string(),
        severity: "info".to_string(),
        payload: json!({
            "scan_id": "scan_abc123",
            "spec_hash": "sha256:deadbeef",
            "findings_summary": { "critical": 0, "high": 1, "medium": 3 }
        }),
        prev_hash: None,
        chain_hash: "0".repeat(64),
        timestamp: Utc::now(),
    };

    println!("\n[1] Queuing event {event_id} ({}) …", event.event_type);
    client.send_event(event).await?;
    println!("    Event queued for background delivery.");

    // Brief yield so the background worker can pick up the event.
    sleep(Duration::from_millis(200)).await;

    // ------------------------------------------------------------------
    // 3. Query recent events.
    // ------------------------------------------------------------------
    let since = Utc::now() - chrono::Duration::hours(24);
    let opts = CitadelGetEventsOptions {
        source: Some(source.clone()),
        since: Some(since),
        limit: Some(20),
        page: Some(1),
        ..Default::default()
    };

    println!("\n[2] Querying events: source={source}, since={since}");
    let events = match client.get_events(opts).await {
        Ok(ev) => {
            println!("    Retrieved {} event(s)", ev.len());
            for e in &ev {
                println!(
                    "      [{}] {} | {} | {}",
                    e.timestamp.format("%Y-%m-%dT%H:%M:%SZ"),
                    e.id,
                    e.event_type,
                    e.severity
                );
            }
            ev
        }
        Err(err) => {
            eprintln!("    get_events failed: {err}");
            vec![]
        }
    };

    // ------------------------------------------------------------------
    // 4. Verify the hash chain.
    // ------------------------------------------------------------------
    if events.len() >= 2 {
        println!(
            "\n[3] Verifying hash chain across {} events …",
            events.len()
        );
        match CITADELClient::verify_chain(&events) {
            Ok(()) => println!("    Chain intact — all links verified."),
            Err(err) => println!("    Chain verification FAILED: {err}"),
        }
    } else {
        println!("\n[3] Skipping chain verification (fewer than 2 events returned)");
    }

    // ------------------------------------------------------------------
    // 5. Fetch a single event by ID.
    // ------------------------------------------------------------------
    if let Some(last) = events.last() {
        let target_id = last.id.clone();
        println!("\n[4] Fetching single event by ID: {target_id}");
        match client.get_event(&target_id).await {
            Ok(single) => {
                println!(
                    "    Fetched: {} | {} | chain_hash: {}…",
                    single.id,
                    single.event_type,
                    &single.chain_hash[..16.min(single.chain_hash.len())]
                );
            }
            Err(err) => eprintln!("    get_event failed: {err}"),
        }
    }

    // ------------------------------------------------------------------
    // 6. Drain the client on graceful shutdown.
    // ------------------------------------------------------------------
    println!("\n[5] Draining client (waiting up to 10 s for in-flight deliveries) …");
    client.drain(Some(Duration::from_secs(10))).await?;
    println!("    Drain complete.");

    println!("\nDone.");
    Ok(())
}

/// Return the value of `name` from the environment or exit with an error.
fn require_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("error: required environment variable {name} is not set");
        std::process::exit(1);
    })
}
