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
use wasmtime::{Config, Engine, Store};
use wasmtime_wasi::{WasiCtxBuilder, WasiCtx};

use crate::capability::CapabilityBag;

/// Number of pre-warmed stores kept in the pool.
const PREWARM_POOL_SIZE: usize = 10;

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
    /// The wasmtime store for this session.
    /// Option so we can take ownership when the session stops.
    ///
    /// TODO(v1.0.0): replace `()` with the real WasiCtx data type once
    /// the WASI context is plumbed through.  The Store type parameter
    /// must match the linker's type.
    store: Option<Store<WasiCtx>>,
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
    prewarm_pool: Vec<Store<WasiCtx>>,
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
    /// Pops a pre-warmed store from the pool (or allocates a fresh one
    /// if the pool is empty), attaches the capability bag, and registers
    /// the session.
    ///
    /// TODO(v1.0.0): pull the .wasm module from the OCI image, verify
    /// with cosign, instantiate via the wasmtime Component Model API,
    /// and wire stdio to the IPC relay WebSocket.
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

        let store = if let Some(s) = self.prewarm_pool.pop() {
            tracing::debug!(session_id, "using pre-warmed store");
            s
        } else {
            tracing::warn!(session_id, "pre-warm pool exhausted; allocating fresh store");
            build_prewarm_store(&self.engine)?
        };

        // Refill the pool asynchronously if it ran low.
        // TODO(v1.0.0): spawn a background task to refill.
        if self.prewarm_pool.len() < PREWARM_POOL_SIZE / 2 {
            tracing::warn!(
                remaining = self.prewarm_pool.len(),
                "pre-warm pool below half capacity"
            );
        }

        let session = Session {
            session_id: session_id.clone(),
            lab_id,
            state: SessionState::Starting,
            capabilities,
            store: Some(store),
        };

        self.sessions.push(session);

        // Safety: we just pushed, so last() is Some.
        let idx = self.sessions.len() - 1;
        self.sessions[idx].state = SessionState::Running;

        tracing::info!(session_id, "session started");
        Ok(&self.sessions[idx])
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
/// The store created here has no filesystem mounts and no network.
/// When a real session claims it, the WASI context is reconfigured
/// with the session's capability bag.
///
/// TODO(v1.0.0): the pre-warm store should be a true wasmtime Component
/// instance with the WASI host functions already linked, so claim is O(1).
fn build_prewarm_store(engine: &Engine) -> Result<Store<WasiCtx>> {
    let wasi_ctx = WasiCtxBuilder::new()
        // No ambient filesystem — only explicit mounts allowed.
        // No network by default.
        // Stdin/stdout/stderr will be wired to the IPC relay at session start.
        // TODO(v1.0.0): pipe stdin/stdout to the WebSocket relay.
        .build();

    let mut store = Store::new(engine, wasi_ctx);

    // Set initial fuel budget.  This will be reset per-command at runtime.
    store
        .set_fuel(1_000_000_000)
        .context("failed to set initial fuel on pre-warmed store")?;

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
