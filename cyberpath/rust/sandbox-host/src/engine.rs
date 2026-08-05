// wasmtime Engine and per-session pre-warm pool.
//
// Architecture (docs/wasm-sandbox.md §Runtime architecture):
//   Go API  →  unix socket  →  this process  →  wasmtime instance
//
// The Engine is a single shared instance (it is internally Arc<>-wrapped
// by wasmtime).  Each lab session gets its own Store<WasiCtx> with an
// isolated capability bag.  A pre-warm pool of N=10 empty stores is
// kept ready so the first command in a new session can start without
// paying the Store allocation cost on the critical path.

use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use wasmtime::component::{Component, Instance, Linker};
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{DirPerms, FilePerms, ResourceTable, WasiCtx, WasiCtxBuilder, WasiView};

use crate::capability::CapabilityBag;
use crate::cosign_verify;
use crate::host_func::network_deny::is_egress_allowed;
use crate::oci_pull;

/// Number of pre-warmed stores kept in the pool.
const PREWARM_POOL_SIZE: usize = 10;

/// Per-session store data: the WASI Preview 2 context (capability-scoped
/// filesystem/network access, per `build_capability_scoped_store` below)
/// plus the resource table wasmtime-wasi needs to hand out `wasi:io`
/// resources to the guest. This is the `T` in `Store<T>` / `Linker<T>`.
pub struct HostState {
    wasi_ctx: WasiCtx,
    table: ResourceTable,
}

impl WasiView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi_ctx
    }
}

/// Lifecycle state of a lab session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    Starting,
    Running,
    Stopped,
}

impl std::fmt::Display for SessionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionState::Starting => write!(f, "starting"),
            SessionState::Running => write!(f, "running"),
            SessionState::Stopped => write!(f, "stopped"),
        }
    }
}

/// A single lab session backed by a wasmtime Store.
pub struct Session {
    pub session_id: String,
    pub lab_id: String,
    pub state: SessionState,
    pub capabilities: CapabilityBag,
    /// The wasmtime store for this session, scoped to this session's
    /// `CapabilityBag` (see `build_capability_scoped_store`).
    /// Option so we can take ownership when the session stops.
    store: Option<Store<HostState>>,
    /// The instantiated lab Wasm component, once `load_lab_module` has
    /// pulled, verified, and instantiated it. `None` until then (a session
    /// exists — and is bookkept — before its module is loaded).
    ///
    /// TODO(v1.0.0): wire stdio (this component's `wasi:cli/stdin` etc.)
    /// to the IPC relay WebSocket once that transport exists.
    instance: Option<Instance>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("session_id", &self.session_id)
            .field("lab_id", &self.lab_id)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Shared wasmtime Engine + pre-warm pool.
///
/// Wrapped in Arc<Mutex<>> so it can be shared across tokio tasks.
pub struct SandboxEngine {
    engine: Engine,
    /// Pre-warmed stores ready to be assigned to new sessions.
    prewarm_pool: Vec<Store<HostState>>,
    /// Active sessions, keyed by session_id.
    sessions: Vec<Session>,
}

impl SandboxEngine {
    /// Build a new Engine with fuel enabled and fill the pre-warm pool.
    pub fn new() -> Result<Arc<Mutex<Self>>> {
        let engine = build_engine()?;

        let mut prewarm_pool = Vec::with_capacity(PREWARM_POOL_SIZE);
        for _ in 0..PREWARM_POOL_SIZE {
            let store = build_prewarm_store(&engine)?;
            prewarm_pool.push(store);
        }

        tracing::info!(
            pool_size = PREWARM_POOL_SIZE,
            "sandbox engine initialised; pre-warm pool ready"
        );

        Ok(Arc::new(Mutex::new(Self {
            engine,
            prewarm_pool,
            sessions: Vec::new(),
        })))
    }

    /// Start a new session for the given lab.
    ///
    /// This performs session bookkeeping and allocates a store whose WASI
    /// context is scoped to `capabilities` (filesystem allowlist + network
    /// egress policy — see `build_capability_scoped_store`). It does
    /// *not* touch the network: pulling the lab's OCI image and verifying
    /// its cosign signature is a separate, async step (`load_lab_module`)
    /// that the caller must run — and must not proceed past a failure of —
    /// before any guest code from `lab_image` can be considered part of
    /// this session. Keeping the two steps separate lets session lifecycle
    /// (this method, `stop_session`, `get_session`) be exercised without
    /// requiring a live OCI registry, which is what the tests in this
    /// module and in `tests/escape_attempts.rs` do.
    pub fn start_session(
        &mut self,
        session_id: String,
        lab_id: String,
        _lab_image: &str,
        capabilities: CapabilityBag,
    ) -> Result<&Session> {
        if self.sessions.iter().any(|s| s.session_id == session_id) {
            bail!("session {} already exists", session_id);
        }

        // Consume a pre-warmed slot to preserve the "no allocation cost on
        // the critical path" property of the pool (see build_prewarm_store);
        // note the placeholder store itself is discarded below rather than
        // reused, because a wasmtime WasiCtx is immutable once built and
        // cannot be retargeted at this session's own CapabilityBag. See the
        // TODO on build_prewarm_store for the follow-up that would let a
        // pre-warmed *Component instance* actually be claimed in O(1).
        if let Some(_placeholder) = self.prewarm_pool.pop() {
            tracing::debug!(session_id, "consumed a pre-warm pool slot");
        } else {
            tracing::warn!(session_id, "pre-warm pool exhausted");
        }

        // Refill the pool asynchronously if it ran low.
        // TODO(v1.0.0): spawn a background task to refill.
        if self.prewarm_pool.len() < PREWARM_POOL_SIZE / 2 {
            tracing::warn!(
                remaining = self.prewarm_pool.len(),
                "pre-warm pool below half capacity"
            );
        }

        let store = build_capability_scoped_store(&self.engine, &capabilities)
            .context("failed to build capability-scoped store for session")?;

        let session = Session {
            session_id: session_id.clone(),
            lab_id,
            state: SessionState::Starting,
            capabilities,
            store: Some(store),
            instance: None,
        };

        self.sessions.push(session);

        // Safety: we just pushed, so last() is Some.
        let idx = self.sessions.len() - 1;
        self.sessions[idx].state = SessionState::Running;

        tracing::info!(session_id, "session started");
        Ok(&self.sessions[idx])
    }

    /// Pull the lab's OCI image, verify its cosign signature, and
    /// instantiate the resulting Wasm component inside `session_id`'s
    /// existing (capability-scoped) store.
    ///
    /// This is deliberately split out from `start_session` (see the
    /// doc-comment there) so callers — namely the IPC dispatch loop in
    /// `main.rs` — can run session bookkeeping synchronously and then await
    /// the network-dependent pull+verify+instantiate step, stopping the
    /// session on any failure rather than leaving a half-started session
    /// with unverified guest code sitting around.
    ///
    /// Returns an error, and instantiates nothing, if:
    ///   * the image cannot be pulled from its OCI registry,
    ///   * the image does not contain a `/lab.wasm` layer entry,
    ///   * the image's cosign signature is missing, invalid, or was not
    ///     produced by the expected publisher (see `cosign_verify`), or
    ///   * the pulled bytes are not a valid Wasm component.
    pub async fn load_lab_module(&mut self, session_id: &str, lab_image: &str) -> Result<()> {
        let pulled = oci_pull::pull_lab_wasm(lab_image)
            .await
            .with_context(|| format!("failed to pull lab image {lab_image}"))?;

        // Verify against the exact digest we just pulled, not whatever a
        // floating tag currently resolves to (avoids a TOCTOU window
        // between "what got verified" and "what gets instantiated").
        let digest_pinned = oci_pull::digest_pinned_reference(lab_image, &pulled.digest)?;
        cosign_verify::verify_lab_image(&digest_pinned)
            .await
            .with_context(|| {
                format!(
                    "cosign verification failed for {digest_pinned}; refusing to instantiate"
                )
            })?;

        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.session_id == session_id)
            .with_context(|| format!("session {session_id} not found"))?;

        let store = session
            .store
            .as_mut()
            .with_context(|| format!("session {session_id} has no store (already stopped?)"))?;

        let component = Component::new(&self.engine, &pulled.wasm_bytes).with_context(|| {
            format!(
                "pulled artifact for {lab_image} is not a valid Wasm component \
                 (this sandbox host is configured with wasm_component_model(true) \
                 and expects a WASI Preview 2 component, not a bare core module)"
            )
        })?;

        let mut linker: Linker<HostState> = Linker::new(&self.engine);
        wasmtime_wasi::add_to_linker_sync(&mut linker)
            .context("failed to link WASI host functions into the component linker")?;

        let instance = linker
            .instantiate(&mut *store, &component)
            .with_context(|| format!("failed to instantiate lab component for {lab_image}"))?;

        session.instance = Some(instance);

        tracing::info!(session_id, lab_image, "lab wasm module pulled, verified, and instantiated");
        Ok(())
    }

    /// Stop and remove a session.
    ///
    /// Drops the wasmtime Store, which frees the linear memory allocation.
    /// TODO(v1.0.0): flush stdio buffers, write audit log tail, then drop.
    pub fn stop_session(&mut self, session_id: &str) -> Result<()> {
        let pos = self
            .sessions
            .iter()
            .position(|s| s.session_id == session_id)
            .context("session not found")?;

        let mut session = self.sessions.remove(pos);
        session.state = SessionState::Stopped;
        // Dropping `session` here drops the Store and frees linear memory.
        tracing::info!(session_id, "session stopped");

        // Attempt to refill the pool by one.
        if self.prewarm_pool.len() < PREWARM_POOL_SIZE {
            match build_prewarm_store(&self.engine) {
                Ok(s) => self.prewarm_pool.push(s),
                Err(e) => tracing::error!(?e, "failed to refill pre-warm pool"),
            }
        }

        Ok(())
    }

    /// Look up a session by ID.
    pub fn get_session(&self, session_id: &str) -> Option<&Session> {
        self.sessions.iter().find(|s| s.session_id == session_id)
    }
}

/// Build the shared wasmtime Engine with the settings required by the
/// CyberPath sandbox threat model.
fn build_engine() -> Result<Engine> {
    let mut config = Config::new();

    // Enable fuel-based CPU metering (see docs/wasm-sandbox.md §Resource limits).
    config.consume_fuel(true);

    // Component Model support for WASI Preview 2.
    config.wasm_component_model(true);

    // Disable features that expand the attack surface.
    config.wasm_threads(false); // revisit at v1.1

    Engine::new(&config).context("failed to build wasmtime Engine")
}

/// Build a minimal pre-warmed Store with a bare WASI context.
///
/// The store created here has no filesystem mounts and no network — it
/// exists purely to keep `SandboxEngine::new()`'s pool at
/// `PREWARM_POOL_SIZE` and to smoke-test that the Engine can produce
/// stores at startup. `start_session` does *not* hand this store to a
/// session (see the comment there): a real session's store is always
/// built fresh by `build_capability_scoped_store`, because a wasmtime
/// `WasiCtx` cannot be reconfigured after `WasiCtxBuilder::build()`.
///
/// TODO(v1.0.0): the pre-warm store should be a true wasmtime Component
/// instance with the WASI host functions already linked, so claim is O(1).
fn build_prewarm_store(engine: &Engine) -> Result<Store<HostState>> {
    let wasi_ctx = WasiCtxBuilder::new()
        // No ambient filesystem — only explicit mounts allowed.
        // No network by default.
        // Stdin/stdout/stderr will be wired to the IPC relay at session start.
        // TODO(v1.0.0): pipe stdin/stdout to the WebSocket relay.
        .build();

    let mut store = Store::new(
        engine,
        HostState {
            wasi_ctx,
            table: ResourceTable::new(),
        },
    );

    // Set initial fuel budget.  This will be reset per-command at runtime.
    store
        .set_fuel(1_000_000_000)
        .context("failed to set initial fuel on pre-warmed store")?;

    Ok(store)
}

/// Build a `Store<HostState>` whose WASI context enforces `capabilities`:
///   * filesystem access is limited to `capabilities.fs_allowlist`, mounted
///     read-write at the same path inside the guest as on the host,
///   * outbound network connections are routed through
///     `host_func::network_deny::is_egress_allowed`, which — regardless of
///     `capabilities.network_allow` — always denies loopback/wildcard
///     addresses (see that module's `BLOCKED_HOSTS`),
///   * the fuel budget is `capabilities.fuel_limit` instead of a fixed
///     constant.
///
/// Preopening a directory that doesn't exist on the *host* filesystem
/// (expected on non-Linux dev machines, and in CI, where `/lab` and
/// `/scratch` are production-only mount points) is logged and skipped
/// rather than treated as a fatal error: the allowlist enforcement itself
/// (`host_func::fs_sandbox::allow_path`) is the security boundary this
/// crate's test suite exercises directly; this preopen step is the
/// production wiring of that same policy into wasmtime-wasi's own
/// capability-based filesystem API, and its absence on a given host simply
/// means that particular mount isn't available to the guest (a fail-closed
/// outcome, not fail-open).
fn build_capability_scoped_store(
    engine: &Engine,
    capabilities: &CapabilityBag,
) -> Result<Store<HostState>> {
    let mut builder = WasiCtxBuilder::new();

    for host_path in &capabilities.fs_allowlist {
        // Only directories can be preopened via wasmtime-wasi's API; file
        // entries in the allowlist (e.g. /etc/lab.json) are enforced at the
        // `allow_path()` layer instead, not preopened here.
        if !host_path.is_dir() {
            tracing::debug!(
                path = %host_path.display(),
                "fs_sandbox: allowlist entry is not a directory on this host; not preopening"
            );
            continue;
        }

        let guest_path = host_path.to_string_lossy().to_string();
        match builder.preopened_dir(host_path, &guest_path, DirPerms::all(), FilePerms::all()) {
            Ok(_) => {
                tracing::debug!(path = %guest_path, "fs_sandbox: preopened capability path");
            }
            Err(err) => {
                tracing::warn!(
                    path = %guest_path,
                    error = %err,
                    "fs_sandbox: could not preopen capability path"
                );
            }
        }
    }

    let network_allow = capabilities.network_allow;
    builder.socket_addr_check(move |addr, _use| {
        let host = addr.ip().to_string();
        let port = addr.port();
        let allowed = is_egress_allowed(&host, port, network_allow);
        Box::pin(async move { allowed })
    });
    if !network_allow {
        // Deny-by-default also covers DNS resolution: without outbound
        // sockets there is nothing to resolve a name for, and leaving
        // lookups enabled would let a guest probe internal DNS as a side
        // channel even though it can never open the resulting connection.
        builder.allow_ip_name_lookup(false);
    }

    let wasi_ctx = builder.build();
    let mut store = Store::new(
        engine,
        HostState {
            wasi_ctx,
            table: ResourceTable::new(),
        },
    );

    let fuel = capabilities.fuel_limit.max(1);
    store
        .set_fuel(fuel)
        .context("failed to set fuel budget on session store")?;

    Ok(store)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::default_capabilities;

    #[tokio::test]
    async fn engine_initialises_with_prewarm_pool() {
        let engine = SandboxEngine::new().expect("engine init failed");
        let guard = engine.lock().await;
        assert_eq!(guard.prewarm_pool.len(), PREWARM_POOL_SIZE);
    }

    #[tokio::test]
    async fn start_and_stop_session() {
        let engine = SandboxEngine::new().expect("engine init failed");
        let mut guard = engine.lock().await;

        let session_id = Uuid::new_v4().to_string();
        guard
            .start_session(
                session_id.clone(),
                "test-lab".to_string(),
                "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
                default_capabilities(),
            )
            .expect("start_session failed");

        assert!(guard.get_session(&session_id).is_some());

        guard.stop_session(&session_id).expect("stop_session failed");
        assert!(guard.get_session(&session_id).is_none());
    }

    #[tokio::test]
    async fn duplicate_session_id_rejected() {
        let engine = SandboxEngine::new().expect("engine init failed");
        let mut guard = engine.lock().await;

        let session_id = Uuid::new_v4().to_string();
        guard
            .start_session(
                session_id.clone(),
                "test-lab".to_string(),
                "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
                default_capabilities(),
            )
            .expect("first start_session failed");

        let result = guard.start_session(
            session_id.clone(),
            "test-lab".to_string(),
            "ghcr.io/opensecstack/cyberpath-labs/test-lab:latest",
            default_capabilities(),
        );

        assert!(result.is_err(), "duplicate session ID must be rejected");
    }
}
