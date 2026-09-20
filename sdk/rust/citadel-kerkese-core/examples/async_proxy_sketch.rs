//! Illustrative sketch of RFC-0005's "Option 2 — User-space async proxy"
//! instantiation of [`KerkeseTransport`]: a hosted process (Runix's
//! `desktop`/`mobile` are the motivating callers) that already runs Tokio
//! and talks to MARSHAL over HTTP via `reqwest`, bridging that async world
//! back into this crate's synchronous `submit` signature.
//!
//! Only this example depends on `tokio`/`reqwest` (see this crate's
//! `Cargo.toml`: they're `[dev-dependencies]` gated behind this example's
//! `required-features`, not real dependencies) — `citadel-kerkese-core`
//! itself stays `no_std` with zero networking of its own, so it still builds
//! for a freestanding target with none of this pulled in.
//!
//! # The sync/async bridge
//!
//! [`KerkeseTransport::submit`] is deliberately `fn`, not `async fn` (see
//! `src/transport.rs`'s doc comment on why: this crate has no
//! executor/reactor dependency at all). A caller that only has an async HTTP
//! client therefore has to cross that boundary *inside* its own `submit`
//! implementation — this crate doesn't do it for them. [`AsyncHttpTransport`]
//! does this by holding a dedicated single-threaded Tokio runtime and calling
//! [`tokio::runtime::Runtime::block_on`] to drive the `reqwest` future to
//! completion synchronously. This blocks the calling thread until the HTTP
//! round-trip finishes — acceptable for a proxy process where `submit` is
//! already expected to be a blocking call from the caller's point of view,
//! but wrong to do on, say, an existing Tokio worker thread (blocking a
//! worker thread inside `block_on` risks starving the runtime — a real
//! integration embedded in an already-async process would instead use
//! `tokio::runtime::Handle::block_on` from outside any async context, e.g.
//! via `tokio::task::block_in_place`, or restructure the caller to await
//! `submit` on a blocking thread pool; this example owns its runtime
//! outright to keep the sketch self-contained).

use citadel_kerkese_core::{Kerkese, KerkeseTransport, TransportError};
use tokio::runtime::Runtime;

/// RFC-0005 Option 2: an async-backed [`KerkeseTransport`] for a user-space
/// proxy process that already has Tokio + `reqwest` available.
struct AsyncHttpTransport {
    client: reqwest::Client,
    citadel_url: String,
    /// Dedicated current-thread runtime used only to drive `submit`'s
    /// internal `reqwest` call to completion. A real integration living
    /// inside a larger Tokio application would more likely hold a
    /// `tokio::runtime::Handle` into that application's existing runtime
    /// instead of owning a private one — this example owns its runtime so
    /// it has no dependency on being constructed from within a `#[tokio::
    /// main]` context.
    runtime: Runtime,
}

impl AsyncHttpTransport {
    fn new(citadel_url: impl Into<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            citadel_url: citadel_url.into(),
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to build Tokio runtime for AsyncHttpTransport"),
        }
    }

    /// The actual async submission logic — kept separate from `submit` so
    /// the sync/async boundary in `submit` is visually obvious (one
    /// `block_on` call wrapping one async fn), rather than buried inside a
    /// larger function body.
    async fn submit_async(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        let response = self
            .client
            .post(&self.citadel_url)
            .header("Content-Type", "application/json")
            .body(envelope_bytes.to_vec())
            .send()
            .await
            .map_err(|e| TransportError::Unreachable(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TransportError::BadResponse(format!(
                "HTTP {}",
                response.status()
            )));
        }

        response
            .bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| TransportError::BadResponse(e.to_string()))
    }
}

impl KerkeseTransport for AsyncHttpTransport {
    fn submit(&self, envelope_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
        // This is the sync/async bridge: `submit` itself is sync (required
        // by the `KerkeseTransport` trait), but the only I/O primitive this
        // proxy has is `reqwest`'s async client. `block_on` drives the
        // future to completion on this thread, blocking it for the
        // duration of the HTTP round-trip.
        self.runtime.block_on(self.submit_async(envelope_bytes))
    }
}

fn main() {
    // A real proxy would point this at MARSHAL's actual Kerkese endpoint;
    // this example just demonstrates construction and the trait wiring, not
    // a live call (no server is running at this URL).
    let transport = AsyncHttpTransport::new("https://citadel.example.internal/marshal/kerkese");

    let kerkese = Kerkese {
        kerkese_version: "1.0".into(),
        ts_utc: "2026-07-26T12:00:00Z".into(),
        project_id: "apiguard".into(),
        execution_id: citadel_kerkese_core::Uuid::from_bytes([0; 16]),
        action: Default::default(),
        actor: Default::default(),
        verifier: Default::default(),
        evidence: Default::default(),
        sod: Default::default(),
        dry_run: false,
        emergency: false,
        emergency_justification: String::new(),
        sig_operator: String::new(),
        sig_verifier: String::new(),
        actor_token: String::new(),
        verifier_token: String::new(),
    };

    match citadel_kerkese_core::submit_kerkese(&transport, &kerkese) {
        Ok(decision) => println!("decision outcome: {:?}", decision.outcome),
        Err(e) => println!("submit_kerkese failed (expected — no real MARSHAL endpoint here): {e}"),
    }
}
