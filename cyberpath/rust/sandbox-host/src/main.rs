// CyberPath sandbox host — entry point.
//
// Listens on a Unix domain socket and dispatches JSON-encoded IPC
// requests (StartRequest / StopRequest) to the wasmtime engine.
// The Go API is the only client; it never speaks to wasmtime directly.
//
// Socket path: $SANDBOX_SOCK  (default: /run/cyberpath/sandbox.sock)

use cyberpath_sandbox_host::capability;
use cyberpath_sandbox_host::engine::SandboxEngine;
use cyberpath_sandbox_host::ipc::{Request, Response, StartResponse, StopResponse};

use anyhow::{Context, Result};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;
use tracing::{error, info};

/// Default socket path; overridden by $SANDBOX_SOCK.
const DEFAULT_SOCK: &str = "/run/cyberpath/sandbox.sock";

#[tokio::main]
async fn main() -> Result<()> {
    // Initialise structured logging.  JSON format in production,
    // pretty-printed when RUST_LOG_FORMAT=pretty.
    init_tracing();

    let sock_path = std::env::var("SANDBOX_SOCK").unwrap_or_else(|_| DEFAULT_SOCK.to_string());

    // Remove stale socket file from a previous run.
    if std::path::Path::new(&sock_path).exists() {
        std::fs::remove_file(&sock_path)
            .with_context(|| format!("failed to remove stale socket at {sock_path}"))?;
    }

    let engine = SandboxEngine::new().context("failed to initialise sandbox engine")?;

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("failed to bind unix socket at {sock_path}"))?;

    info!(sock = %sock_path, "sandbox host listening");

    loop {
        let (stream, _addr) = listener.accept().await.context("accept failed")?;
        let engine = Arc::clone(&engine);

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, engine).await {
                error!(?e, "connection handler error");
            }
        });
    }
}

/// Handle a single IPC connection from the Go API.
///
/// The protocol is newline-delimited JSON:
///   → one Request JSON object per line
///   ← one Response JSON object per line
///
/// The connection stays open until the Go side closes it.
async fn handle_connection(
    stream: tokio::net::UnixStream,
    engine: Arc<Mutex<SandboxEngine>>,
) -> Result<()> {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let response: Response = match serde_json::from_str::<Request>(&line) {
            Ok(req) => dispatch(req, &engine).await,
            Err(e) => {
                error!(?e, raw = %line, "failed to parse IPC request");
                // Return an error response so the Go side gets useful feedback.
                Response::Stop(StopResponse {
                    session_id: String::new(),
                    status: format!("parse_error: {e}"),
                })
            }
        };

        let mut serialised = serde_json::to_string(&response)?;
        serialised.push('\n');
        writer.write_all(serialised.as_bytes()).await?;
    }

    Ok(())
}

/// Dispatch a parsed Request to the engine and return a Response.
async fn dispatch(req: Request, engine: &Arc<Mutex<SandboxEngine>>) -> Response {
    match req {
        Request::Start(start) => {
            info!(
                session_id = %start.session_id,
                lab_id = %start.lab_id,
                "IPC: StartRequest received"
            );

            let capabilities = capability::from_lab_manifest(&start.lab_id);

            let mut guard = engine.lock().await;
            match guard.start_session(
                start.session_id.clone(),
                start.lab_id,
                &start.lab_image,
                capabilities,
            ) {
                Ok(session) => {
                    let status = session.state.to_string();
                    Response::Start(StartResponse {
                        session_id: start.session_id,
                        status,
                        // TODO(v1.0.0): allocate a real WebSocket relay port.
                        ws_relay_port: 0,
                    })
                }
                Err(e) => {
                    error!(?e, session_id = %start.session_id, "start_session failed");
                    Response::Start(StartResponse {
                        session_id: start.session_id,
                        status: format!("error: {e}"),
                        ws_relay_port: 0,
                    })
                }
            }
        }

        Request::Stop(stop) => {
            info!(session_id = %stop.session_id, "IPC: StopRequest received");

            let mut guard = engine.lock().await;
            match guard.stop_session(&stop.session_id) {
                Ok(()) => Response::Stop(StopResponse {
                    session_id: stop.session_id,
                    status: "stopped".to_string(),
                }),
                Err(e) => {
                    error!(?e, session_id = %stop.session_id, "stop_session failed");
                    Response::Stop(StopResponse {
                        session_id: stop.session_id,
                        status: format!("error: {e}"),
                    })
                }
            }
        }
    }
}

fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("cyberpath_sandbox_host=info,warn"));

    let format = std::env::var("RUST_LOG_FORMAT").unwrap_or_default();

    if format == "pretty" {
        fmt().with_env_filter(filter).pretty().init();
    } else {
        fmt().with_env_filter(filter).json().init();
    }
}
