// SPDX-License-Identifier: Apache-2.0
//
// IPC RPC server — line-delimited JSON over a Unix-domain socket.
//
// Wire protocol (must stay in lockstep with
// openscrub/internal/dataplane/uds.go):
//
//   request   {"op": "<name>", ...op-specific fields }\n
//   response  {"ok": true,  "result": <op-specific JSON or null>}\n
//          |  {"ok": false, "error":  "<string>"}\n
//
// Each connection is a stream of newline-delimited request/response
// pairs (the Go client multiplexes one connection per UDSClient
// instance, so we just loop until EOF).
//
// Ops:
//   add_blocklist_v4    {"prefix": "198.51.100.0/24"}
//   remove_blocklist_v4 {"prefix": "198.51.100.0/24"}
//   add_blocklist_v6    {"prefix": "2001:db8::/32"}
//   remove_blocklist_v6 {"prefix": "2001:db8::/32"}
//   set_ratelimit       {"src": "198.51.100.5", "pps": 500}
//   clear_ratelimit     {"src": "198.51.100.5"}
//   enable_syncookie    {"port": 443}
//   disable_syncookie   {"port": 443}
//   snapshot            {} -> {blocklist_v4: [...], blocklist_v6: [...],
//                              ratelimits: {ip: pps}, syncookie_ports: [...]}
//   stats               {} -> {packets_passed, packets_dropped,
//                              packets_ratelimited, packets_malformed,
//                              syn_cookies_sent}

use std::path::{Path, PathBuf};
use std::str::FromStr;

use ipnet::{Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::maps::{MapWriter, RatelimitRule};
use crate::stats::StatsReader;

/// Run the JSON-RPC server on `socket_path` until cancelled. The
/// caller (main.rs) keeps the loader attached for the server's
/// lifetime; on shutdown we attempt to remove the socket file so the
/// next start doesn't EADDRINUSE.
pub async fn serve(
    socket_path: PathBuf,
    writer: MapWriter,
    stats: StatsReader,
) -> anyhow::Result<()> {
    // Best-effort cleanup of a stale socket from a prior crashed run.
    if Path::new(&socket_path).exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    if let Some(parent) = socket_path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let listener = UnixListener::bind(&socket_path)?;
    tracing::info!(socket = %socket_path.display(), "openscrub-loader: ipc listening");

    loop {
        let (stream, _) = listener.accept().await?;
        let writer = writer.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, writer, stats).await {
                tracing::warn!(error = %e, "ipc connection terminated");
            }
        });
    }
}

async fn handle_conn(
    stream: UnixStream,
    writer: MapWriter,
    stats: StatsReader,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let resp = match handle_request(line, &writer, &stats) {
            Ok(value) => Envelope::ok(value),
            Err(e) => Envelope::err(&e.to_string()),
        };
        let mut bytes = serde_json::to_vec(&resp)?;
        bytes.push(b'\n');
        write_half.write_all(&bytes).await?;
    }
    Ok(())
}

#[derive(Serialize)]
struct Envelope {
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
}

impl Envelope {
    fn ok(result: serde_json::Value) -> Self {
        Self { ok: true, error: None, result: Some(result) }
    }
    fn err(msg: &str) -> Self {
        Self { ok: false, error: Some(msg.to_string()), result: None }
    }
}

#[derive(Deserialize)]
struct Request {
    op: String,
    #[serde(default)]
    prefix: Option<String>,
    #[serde(default)]
    src: Option<String>,
    #[serde(default)]
    pps: Option<u64>,
    #[serde(default)]
    port: Option<u16>,
}

fn handle_request(
    line: &str,
    writer: &MapWriter,
    stats: &StatsReader,
) -> anyhow::Result<serde_json::Value> {
    let req: Request = serde_json::from_str(line)?;
    let null = || serde_json::Value::Null;
    match req.op.as_str() {
        "add_blocklist_v4" => {
            let p = Ipv4Net::from_str(&req.prefix.ok_or_else(|| anyhow::anyhow!("prefix required"))?)?;
            writer.add_blocklist_v4(p)?;
            Ok(null())
        }
        "remove_blocklist_v4" => {
            let p = Ipv4Net::from_str(&req.prefix.ok_or_else(|| anyhow::anyhow!("prefix required"))?)?;
            writer.remove_blocklist_v4(p)?;
            Ok(null())
        }
        "add_blocklist_v6" => {
            let p = Ipv6Net::from_str(&req.prefix.ok_or_else(|| anyhow::anyhow!("prefix required"))?)?;
            writer.add_blocklist_v6(p)?;
            Ok(null())
        }
        "remove_blocklist_v6" => {
            let p = Ipv6Net::from_str(&req.prefix.ok_or_else(|| anyhow::anyhow!("prefix required"))?)?;
            writer.remove_blocklist_v6(p)?;
            Ok(null())
        }
        "set_ratelimit" => {
            let src = std::net::Ipv4Addr::from_str(&req.src.ok_or_else(|| anyhow::anyhow!("src required"))?)?;
            let pps = req.pps.ok_or_else(|| anyhow::anyhow!("pps required"))?;
            if pps == 0 || pps > u32::MAX as u64 {
                anyhow::bail!("pps out of range");
            }
            writer.set_ratelimit(RatelimitRule::new(src, pps as u32)?)?;
            Ok(null())
        }
        "clear_ratelimit" => {
            let src = std::net::Ipv4Addr::from_str(&req.src.ok_or_else(|| anyhow::anyhow!("src required"))?)?;
            writer.clear_ratelimit(src)?;
            Ok(null())
        }
        "enable_syncookie" => {
            let port = req.port.ok_or_else(|| anyhow::anyhow!("port required"))?;
            writer.enable_syncookie(port)?;
            Ok(null())
        }
        "disable_syncookie" => {
            let port = req.port.ok_or_else(|| anyhow::anyhow!("port required"))?;
            writer.disable_syncookie(port)?;
            Ok(null())
        }
        "snapshot" => {
            let snap = writer.snapshot();
            let v4: Vec<String> = snap.blocklist_v4.iter().map(|p| p.to_string()).collect();
            let v6: Vec<String> = snap.blocklist_v6.iter().map(|p| p.to_string()).collect();
            let rl: serde_json::Map<String, serde_json::Value> = snap
                .ratelimits
                .iter()
                .map(|(ip, pps)| (ip.to_string(), serde_json::json!(*pps as u64)))
                .collect();
            let mut ports: Vec<u16> = snap.syncookie_listeners.iter().copied().collect();
            ports.sort();
            Ok(serde_json::json!({
                "blocklist_v4": v4,
                "blocklist_v6": v6,
                "ratelimits": rl,
                "syncookie_ports": ports,
            }))
        }
        "stats" => {
            let s = stats.read()?;
            Ok(serde_json::json!({
                "packets_passed":      s.packets_passed,
                "packets_dropped":     s.packets_dropped,
                "packets_ratelimited": s.packets_ratelimited,
                "packets_malformed":   s.packets_malformed,
                "syn_cookies_sent":    s.syn_cookies_sent,
            }))
        }
        other => anyhow::bail!("unknown op: {other}"),
    }
}
