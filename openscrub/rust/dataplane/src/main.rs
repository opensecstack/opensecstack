// SPDX-License-Identifier: Apache-2.0
//
// openscrub-loader — CLI that pins the XDP data plane to a NIC and
// keeps it attached for the lifetime of the process. Agent B (Go
// control plane) drives map updates over a separate channel; this
// binary does not expose any RPC of its own beyond a periodic stats
// log line.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use openscrub_dataplane::{ipc, AttachMode, DataplaneError, Loader, DEFAULT_BPF_OBJECT_PATH};
use tokio::signal;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser, Debug)]
#[command(
    name = "openscrub-loader",
    about = "Load and pin the OpenScrub XDP data plane",
    version
)]
struct Args {
    /// Network interface to attach to (e.g. eth0, ens3, lo).
    #[arg(long)]
    iface: String,

    /// XDP attach mode.
    #[arg(long, value_enum, default_value_t = CliAttachMode::Driver)]
    mode: CliAttachMode,

    /// Path to the compiled BPF object.
    #[arg(long, default_value = DEFAULT_BPF_OBJECT_PATH)]
    bpf_object: String,

    /// Stats log interval in seconds (0 disables).
    #[arg(long, default_value_t = 10)]
    stats_interval_secs: u64,

    /// Path to the Unix socket the IPC RPC server binds. The Go control
    /// plane (internal/dataplane/uds.go) connects here. Empty disables
    /// the server (useful for "loader-only" smoke runs without the Go
    /// API attached).
    #[arg(long, default_value = "/run/openscrub/dataplane.sock")]
    ipc_socket: String,
}

#[derive(Copy, Clone, Debug, clap::ValueEnum)]
enum CliAttachMode {
    Driver,
    Skb,
    Hardware,
}

impl From<CliAttachMode> for AttachMode {
    fn from(m: CliAttachMode) -> Self {
        match m {
            CliAttachMode::Driver => AttachMode::Driver,
            CliAttachMode::Skb => AttachMode::Skb,
            CliAttachMode::Hardware => AttachMode::Hardware,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .json()
        .init();

    let args = Args::parse();

    let mut loader = Loader::new(&args.bpf_object);
    tracing::info!(
        iface = %args.iface,
        mode = ?args.mode,
        bpf_object = %args.bpf_object,
        "openscrub-loader: starting"
    );

    match loader.attach(&args.iface, args.mode.into()).await {
        Ok(()) => tracing::info!(iface = %args.iface, "openscrub-loader: attached"),
        Err(DataplaneError::UnsupportedPlatform) => {
            anyhow::bail!("openscrub-loader requires Linux with CAP_BPF + CAP_NET_ADMIN");
        }
        Err(e) => return Err(e).context("attach failed"),
    }

    let stats_reader = loader.stats_reader();

    // IPC RPC server — wraps MapWriter + StatsReader and serves the
    // Go control plane over a Unix socket. Spawned alongside the
    // stats logger; both are cancelled when ctrl_c fires.
    if !args.ipc_socket.is_empty() {
        let socket = PathBuf::from(&args.ipc_socket);
        let writer = loader.map_writer();
        let stats = stats_reader.clone();
        tokio::spawn(async move {
            if let Err(e) = ipc::serve(socket, writer, stats).await {
                tracing::error!(error = %e, "openscrub-loader: ipc server failed");
            }
        });
    }

    if args.stats_interval_secs > 0 {
        let interval = Duration::from_secs(args.stats_interval_secs);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.tick().await; // skip first immediate tick
            loop {
                tick.tick().await;
                match stats_reader.read() {
                    Ok(s) => tracing::info!(
                        passed = s.packets_passed,
                        dropped = s.packets_dropped,
                        ratelimited = s.packets_ratelimited,
                        malformed = s.packets_malformed,
                        "openscrub-loader: stats"
                    ),
                    Err(e) => tracing::warn!(error = %e, "openscrub-loader: stats read failed"),
                }
            }
        });
    }

    signal::ctrl_c().await.context("waiting for SIGINT")?;
    tracing::info!("openscrub-loader: detaching");
    loader.detach().await?;
    Ok(())
}
