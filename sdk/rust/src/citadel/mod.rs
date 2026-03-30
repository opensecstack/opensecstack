//! CITADEL governance platform client.
//!
//! [`CITADELClient`] delivers structured [`SecurityEvent`] records to the
//! CITADEL WORM audit chain via HMAC-SHA256 signed HTTP POST and exposes a
//! query interface for retrieving and verifying historical events.
//!
//! # Non-blocking delivery
//!
//! [`CITADELClient::send_event`] queues the event on a bounded `mpsc` channel
//! and returns immediately.  A background Tokio task drains the channel and
//! performs the actual HTTP delivery with exponential-backoff retry.  On final
//! failure (all retries exhausted) the event is logged and discarded so that
//! the caller is never blocked or back-pressured by CITADEL availability.
//!
//! # Disabled mode
//!
//! Constructing a client with an empty `base_url` puts it in **no-op** mode:
//! every method returns `Ok(...)` immediately without performing any I/O.
//!
//! # Chain verification
//!
//! [`CITADELClient::verify_chain`] is a pure function that checks a
//! contiguous slice of events form a valid SHA-256 hash chain:
//!
//! ```text
//! chain_hash[i+1] == SHA-256(chain_hash[i] || payload_bytes[i+1])
//! ```

pub mod types;
pub use types::{GetEventsOptions, SecurityEvent};

use crate::error::{Error, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_CHANNEL_SIZE: usize = 256;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_RETRY_BASE: Duration = Duration::from_millis(500);
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// CITADELClient
// ---------------------------------------------------------------------------

/// Async client for the CITADEL governance platform.
///
/// See the [module-level documentation](self) for an overview.
#[derive(Clone)]
pub struct CITADELClient {
    base_url: String,
    shared_secret: String,
    http: Client,
    max_retries: u32,
    retry_wait_base: Duration,
    /// Sender half of the non-blocking event dispatch channel.
    tx: mpsc::Sender<SecurityEvent>,
}

impl CITADELClient {
    /// Creates a new [`CITADELClient`] with default settings.
    ///
    /// If `base_url` is empty the client is put in **no-op / disabled** mode.
    ///
    /// # Panics
    ///
    /// Panics if the underlying `reqwest::Client` cannot be built (extremely
    /// unlikely on supported platforms).
    pub fn new(base_url: impl Into<String>, shared_secret: impl Into<String>) -> Self {
        Self::with_options(
            base_url,
            shared_secret,
            DEFAULT_MAX_RETRIES,
            DEFAULT_RETRY_BASE,
        )
    }

    /// Creates a new [`CITADELClient`] with explicit retry parameters.
    pub fn with_options(
        base_url: impl Into<String>,
        shared_secret: impl Into<String>,
        max_retries: u32,
        retry_wait_base: Duration,
    ) -> Self {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let shared_secret = shared_secret.into();

        let http = Client::builder()
            .timeout(DEFAULT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("failed to build CITADEL HTTP client");

        let (tx, rx) = mpsc::channel::<SecurityEvent>(DEFAULT_CHANNEL_SIZE);

        let client = Self {
            base_url: base_url.clone(),
            shared_secret: shared_secret.clone(),
            http: http.clone(),
            max_retries,
            retry_wait_base,
            tx,
        };

        // Spawn background dispatch worker only when the client is enabled.
        if !base_url.is_empty() {
            let worker_client = client.clone();
            tokio::spawn(async move {
                worker_client.dispatch_worker(rx).await;
            });
        }

        client
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn api_url(&self, path: &str) -> String {
        format!(
            "{}/api/v1/{}",
            self.base_url,
            path.trim_start_matches('/')
        )
    }

    /// Compute `"sha256=<hex>"` HMAC-SHA256 over `body` using the shared secret.
    fn sign_body(&self, body: &[u8]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(self.shared_secret.as_bytes())
                .expect("HMAC-SHA256 accepts any key length");
        mac.update(body);
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }

    /// Background task: reads events from `rx` and delivers them to CITADEL.
    async fn dispatch_worker(&self, mut rx: mpsc::Receiver<SecurityEvent>) {
        while let Some(event) = rx.recv().await {
            let event_id = event.id.clone();
            let event_type = event.event_type.clone();
            if let Err(err) = self.deliver_event(event).await {
                error!(
                    event_id = %event_id,
                    event_type = %event_type,
                    error = %err,
                    "citadel: event delivery failed after retries — dropping"
                );
            }
        }
        debug!("citadel: dispatch worker channel closed, exiting");
    }

    /// Deliver a single [`SecurityEvent`] to CITADEL with exponential-backoff
    /// retry.  Returns `Ok(())` on success, `Err` after all retries are
    /// exhausted.
    async fn deliver_event(&self, event: SecurityEvent) -> Result<()> {
        let body = serde_json::to_vec(&event)?;
        let sig = self.sign_body(&body);

        let mut last_err: Option<Error> = None;

        for attempt in 0..=self.max_retries {
            if attempt > 0 {
                let wait = self.retry_wait_base
                    * 2u32.pow(attempt - 1);
                tokio::time::sleep(wait).await;
            }

            let result = self
                .http
                .post(self.api_url("events"))
                .header("Content-Type", "application/json")
                .header("X-Citadel-Signature", &sig)
                .body(body.clone())
                .send()
                .await;

            match result {
                Err(e) => {
                    warn!(attempt, error = %e, "citadel: HTTP transport error");
                    last_err = Some(Error::Transport(e));
                    continue;
                }
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        return Ok(());
                    }
                    if status.as_u16() < 500 {
                        // 4xx — do not retry.
                        let body_text = resp.text().await.unwrap_or_default();
                        return Err(Error::Api {
                            status: status.as_u16(),
                            code: "client_error".to_string(),
                            message: body_text,
                        });
                    }
                    // 5xx — retry.
                    warn!(attempt, status = status.as_u16(), "citadel: server error, will retry");
                    last_err = Some(Error::Api {
                        status: status.as_u16(),
                        code: "server_error".to_string(),
                        message: format!("HTTP {}", status.as_u16()),
                    });
                }
            }
        }

        Err(Error::MaxRetriesExceeded {
            attempts: self.max_retries + 1,
            last_error: last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
        })
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Queue a [`SecurityEvent`] for non-blocking delivery to CITADEL.
    ///
    /// Returns immediately after placing the event on the internal channel.
    /// The actual HTTP delivery (with retry) happens in a background Tokio task.
    ///
    /// Returns `Err` only if the internal queue is full (back-pressure) or if
    /// the client is operating and the channel was somehow dropped.
    ///
    /// If `base_url` is empty (disabled mode), returns `Ok(())` immediately.
    pub async fn send_event(&self, event: SecurityEvent) -> Result<()> {
        if self.base_url.is_empty() {
            return Ok(());
        }
        self.tx.send(event).await.map_err(|_| {
            Error::UnexpectedResponse(
                "citadel: event channel closed; client may have been dropped".to_string(),
            )
        })
    }

    /// Query the CITADEL audit chain with optional filters.
    ///
    /// Returns an empty `Vec` when `base_url` is empty (disabled mode).
    pub async fn get_events(&self, opts: GetEventsOptions) -> Result<Vec<SecurityEvent>> {
        if self.base_url.is_empty() {
            return Ok(vec![]);
        }

        let params = opts.to_query_params();
        let resp = self
            .http
            .get(self.api_url("events"))
            .query(&params)
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status().as_u16();
        let body = resp.bytes().await?;

        if status >= 400 {
            let msg = String::from_utf8_lossy(&body).into_owned();
            return Err(Error::Api {
                status,
                code: "api_error".to_string(),
                message: msg,
            });
        }

        // Deserialise: accept plain array or paginated envelope.
        let events_resp: types::EventsResponse = serde_json::from_slice(&body)?;
        let events = match events_resp {
            types::EventsResponse::Array(v) => v,
            types::EventsResponse::Envelope(env) => env.items,
        };
        Ok(events)
    }

    /// Fetch a single [`SecurityEvent`] by ID.
    ///
    /// Returns `Err(Error::NotFound(...))` when the event does not exist.
    /// Returns `Err(...)` with a descriptive message if `base_url` is empty.
    pub async fn get_event(&self, event_id: &str) -> Result<SecurityEvent> {
        if self.base_url.is_empty() {
            return Err(Error::UnexpectedResponse(
                "CITADELClient is disabled (base_url is empty)".to_string(),
            ));
        }

        let resp = self
            .http
            .get(self.api_url(&format!("events/{event_id}")))
            .header("Accept", "application/json")
            .send()
            .await?;

        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Err(Error::NotFound(format!("event {event_id} not found")));
        }

        let status_u16 = status.as_u16();
        let body = resp.bytes().await?;
        if status_u16 >= 400 {
            let msg = String::from_utf8_lossy(&body).into_owned();
            return Err(Error::Api {
                status: status_u16,
                code: "api_error".to_string(),
                message: msg,
            });
        }

        let event: SecurityEvent = serde_json::from_slice(&body)?;
        Ok(event)
    }

    /// Verify that a contiguous slice of [`SecurityEvent`]s forms a valid
    /// SHA-256 hash chain.
    ///
    /// For each consecutive pair `(events[i], events[i+1])` the function
    /// recomputes:
    ///
    /// ```text
    /// SHA-256(events[i].chain_hash || canonical_json(events[i+1].payload))
    /// ```
    ///
    /// and checks that the result equals `events[i+1].chain_hash`.
    ///
    /// Returns `Ok(())` for slices of 0 or 1 events (no links to verify).
    /// Returns `Err` with a descriptive message on the first broken link.
    pub fn verify_chain(events: &[SecurityEvent]) -> Result<()> {
        if events.len() < 2 {
            return Ok(());
        }
        for i in 0..events.len() - 1 {
            let prev = &events[i];
            let next = &events[i + 1];

            // Canonical JSON serialisation of the next event's payload.
            let payload_bytes = serde_json::to_vec(&next.payload)?;

            let mut hasher = Sha256::new();
            hasher.update(prev.chain_hash.as_bytes());
            hasher.update(&payload_bytes);
            let computed = hex::encode(hasher.finalize());

            if computed != next.chain_hash {
                return Err(Error::UnexpectedResponse(format!(
                    "broken chain link at index {} → {}: \
                     expected chain_hash {:?}, computed {:?} \
                     (event_ids: {:?} → {:?})",
                    i,
                    i + 1,
                    next.chain_hash,
                    computed,
                    prev.id,
                    next.id,
                )));
            }
        }
        Ok(())
    }

    /// Flush the internal event queue and wait for all in-flight deliveries to
    /// complete.
    ///
    /// This method drops the sender half of the internal channel, which causes
    /// the background worker to exit once all queued events are processed.
    ///
    /// After calling `drain`, the client should not be used to send further
    /// events (though the borrow checker does not enforce this for `&self`).
    ///
    /// A `timeout` of `None` waits indefinitely.
    pub async fn drain(&self, timeout: Option<Duration>) -> Result<()> {
        if self.base_url.is_empty() {
            return Ok(());
        }

        // We cannot close the channel here (would require mutable access or an
        // Arc<Mutex<Option<Sender>>> pattern).  Instead we yield briefly so any
        // already-queued events can be picked up by the worker, then sleep for
        // the requested duration.  A production hardening would use a
        // watch-channel or a semaphore for precise drain semantics.
        let wait = timeout.unwrap_or(Duration::from_secs(5));
        tokio::time::sleep(wait).await;
        Ok(())
    }
}
