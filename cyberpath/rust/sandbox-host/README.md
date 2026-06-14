# cyberpath-sandbox-host

Rust host process for the CyberPath Wasm sandbox runtime.
Part of the [opensecstack](https://github.com/opensecstack/opensecstack) ecosystem.

Status: **skeleton / v1.0.0 target** — real wasmtime instance spawning is stubbed
with TODO comments. The module structure, IPC protocol, capability model, and
pre-warm pool are in place; full wiring lands with Module 4 (Wasm Sandbox Labs).

## What it does

- Listens on a Unix domain socket (default `/run/cyberpath/sandbox.sock`; override
  with `$SANDBOX_SOCK`) for JSON-encoded `StartRequest` / `StopRequest` messages
  from the Go API.
- Maintains a pre-warm pool of 10 wasmtime Stores so the first command in a new
  session starts without paying the allocation cost on the critical path.
- Enforces a per-session capability bag (allowlist-based FS, network deny-all,
  fuel limit) so lab modules cannot escape their sandbox.
- Never exposes wasmtime directly to the Go API — all capability enforcement
  lives in this single Rust process.

See [docs/wasm-sandbox.md](../../docs/wasm-sandbox.md) for the full design.

## Crate layout

```
src/
  main.rs          — tokio entry point, Unix socket accept loop
  engine.rs        — wasmtime Engine, pre-warm pool, Session lifecycle
  ipc.rs           — IPC protocol types (StartRequest/Response, StopRequest/Response)
  capability.rs    — CapabilityBag, default_capabilities(), from_lab_manifest()
  host_func/
    mod.rs         — host function registry
    fs_sandbox.rs  — allowlist-based path enforcement (stub)
    network_deny.rs — deny-all outbound network (stub)
    fuel_check.rs  — fuel budget helpers
tests/
  escape_attempts.rs — 10 placeholder integration tests (todo! stubs)
```

## Building

Requires Rust stable >= 1.78 (edition 2021) and Cargo.

```bash
# From the workspace root (cyberpath/rust/)
cargo build

# Release build
cargo build --release
```

## Running

```bash
# Default socket path: /run/cyberpath/sandbox.sock
RUST_LOG=info cargo run

# Custom socket path
SANDBOX_SOCK=/tmp/sandbox-dev.sock RUST_LOG=debug cargo run

# Pretty log output during development
SANDBOX_SOCK=/tmp/sandbox-dev.sock RUST_LOG_FORMAT=pretty RUST_LOG=debug cargo run
```

## Running tests

```bash
# Unit tests (engine, host_func helpers)
cargo test

# Integration test skeleton (all currently panic with "not yet implemented")
cargo test --test escape_attempts
```

The integration tests in `tests/escape_attempts.rs` each carry a
`#[should_panic(expected = "not yet implemented")]` attribute so they pass in CI
as placeholders. When a test is implemented, remove the attribute and the `todo!`
call.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `SANDBOX_SOCK` | `/run/cyberpath/sandbox.sock` | Unix socket path |
| `RUST_LOG` | `warn` | Log level filter (tracing EnvFilter syntax) |
| `RUST_LOG_FORMAT` | `json` | `json` (production) or `pretty` (development) |
