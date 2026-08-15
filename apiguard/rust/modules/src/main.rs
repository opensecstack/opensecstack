//! apiguard-modules — JSON stdin/stdout subprocess interface.
//!
//! The Go runner invokes this binary as a subprocess, sends a JSON request on
//! stdin, and reads a JSON response from stdout.
//!
//! Request schema:
//! ```json
//! {
//!   "module": "a3_exposure" | "a4_rate_limit" | "a7_misconfig" | "a8_injection" | "a9_inventory",
//!   "endpoint": { "path": "/api/v1/users/1", "method": "GET" },
//!   "response": {
//!     "status_code": 200,
//!     "headers": { "content-type": "application/json" },
//!     "body": "...",
//!     "duration_ms": 45
//!   },
//!   // For a4_rate_limit only:
//!   "baseline_samples_ms": [50, 55, 48],
//!   "test_duration_ms": 600
//! }
//! ```
//!
//! Response schema:
//! ```json
//! { "findings": [ ... ] }
//! ```

use clap::Parser;
use modules::{
    check_excessive_data_exposure, check_injection_indicators, check_inventory,
    check_security_headers, check_timing_anomaly, EndpointCtx, HttpResponse, ModuleFinding,
};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

#[derive(Parser)]
#[command(name = "apiguard-modules", about = "APIGuard Rust L3 OWASP modules")]
struct Cli {
    /// Read request from a file instead of stdin (useful for testing).
    #[arg(long)]
    input: Option<std::path::PathBuf>,
}

#[derive(Deserialize)]
struct Request {
    module: String,
    endpoint: EndpointCtx,
    response: Option<HttpResponse>,
    /// For a4_rate_limit: baseline timing samples in milliseconds.
    #[serde(default)]
    baseline_samples_ms: Vec<u64>,
    /// For a4_rate_limit: the test measurement in milliseconds.
    #[serde(default)]
    test_duration_ms: u64,
}

#[derive(Serialize)]
struct Response {
    findings: Vec<ModuleFinding>,
}

fn run(req: Request) -> Vec<ModuleFinding> {
    match req.module.as_str() {
        "a3_exposure" => {
            let resp = match &req.response {
                Some(r) => r,
                None => return vec![],
            };
            check_excessive_data_exposure(resp, &req.endpoint)
        }
        "a4_rate_limit" => check_timing_anomaly(
            &req.endpoint,
            &req.baseline_samples_ms,
            req.test_duration_ms,
        ),
        "a7_misconfig" => {
            let resp = match &req.response {
                Some(r) => r,
                None => return vec![],
            };
            check_security_headers(resp, &req.endpoint)
        }
        "a8_injection" => {
            let resp = match &req.response {
                Some(r) => r,
                None => return vec![],
            };
            check_injection_indicators(resp, &req.endpoint)
        }
        "a9_inventory" => {
            let resp = match &req.response {
                Some(r) => r,
                None => return vec![],
            };
            check_inventory(resp, &req.endpoint)
        }
        unknown => {
            eprintln!("apiguard-modules: unknown module '{}'", unknown);
            vec![]
        }
    }
}

fn main() {
    let cli = Cli::parse();

    let raw = if let Some(path) = cli.input {
        std::fs::read_to_string(&path).unwrap_or_else(|e| {
            eprintln!("apiguard-modules: failed to read {:?}: {}", path, e);
            std::process::exit(1);
        })
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("apiguard-modules: failed to read stdin: {}", e);
            std::process::exit(1);
        });
        buf
    };

    let req: Request = serde_json::from_str(&raw).unwrap_or_else(|e| {
        eprintln!("apiguard-modules: invalid JSON request: {}", e);
        std::process::exit(1);
    });

    let findings = run(req);
    let resp = Response { findings };

    let out = serde_json::to_string(&resp).unwrap_or_else(|e| {
        eprintln!("apiguard-modules: failed to serialise response: {}", e);
        std::process::exit(1);
    });

    io::stdout().write_all(out.as_bytes()).ok();
    io::stdout().write_all(b"\n").ok();
}
