# Wasm Lab Setup

CyberPath supports a second lab type — `wasm` — backed by the PyramidOS sandbox. Wasm labs are lighter, start in under a second, and require no Docker daemon access. They are best suited for theory-reinforcement exercises, algorithm challenges, and single-binary scenarios.

## How Wasm Labs Use PyramidOS

The PyramidOS Wasm runtime is embedded in the CyberPath backend. When a Wasm lab starts, `internal/labs/wasm.go`:

1. Locates the `.wasm` module referenced in `lab.yaml` under `wasm_module`.
2. Instantiates it inside a PyramidOS sandbox with the configured environment variables and resource limits.
3. Exposes a virtual shell interface over the same WebSocket protocol used by Docker labs (`internal/labs/terminal.go` is runtime-agnostic at the WebSocket layer).

The PyramidOS runtime provides a POSIX-compatible environment implemented in Wasm + WASI. Learners interact with it via the browser terminal exactly as they would with a Docker container.

## When to Use Wasm vs Docker

| Criterion | Wasm | Docker |
|---|---|---|
| Start time | < 1 second | 5-30 seconds (image pull excluded) |
| Network services (HTTP, DB) | Not supported | Supported |
| Multi-process scenarios | No | Yes |
| File system persistence within session | Ephemeral, in-memory | Writable layer |
| Resource overhead per session | Very low (~10 MB) | Medium (image size + runtime) |
| Requires Docker daemon | No | Yes |
| Best for | Scripting tasks, CTF-style single-binary, theory exercises | Vulnerable web apps, network labs, multi-service scenarios |

Use Wasm for modules that need a shell but not a network service. Use Docker for anything that runs a server (API, database, proxy).

## PyramidOS Wasm Runtime Requirements

The PyramidOS runtime ships as part of the CyberPath binary. No separate installation is required. Runtime version compatibility:

- WASI preview1 (`wasi_snapshot_preview1`) — fully supported.
- WASI preview2 (component model) — not yet supported; planned.
- Multi-memory proposal — supported.
- Threads proposal — not supported (WASM atomics are available but shared memory is not enabled).

Wasm modules must be compiled targeting WASI. Common toolchains:

```bash
# Rust
cargo build --target wasm32-wasip1 --release

# C/C++ via wasi-sdk
/opt/wasi-sdk/bin/clang --sysroot=/opt/wasi-sdk/share/wasi-sysroot -o lab.wasm main.c

# Python (via Pyodide-based wrapper — see content/shared-wasm/pyodide-shell/)
```

## Supported Wasm Module Types

- **Single-binary CTF**: A compiled binary that learners interact with via stdin/stdout. Flags are embedded in the binary logic.
- **Script runner**: A shell script runner that evaluates learner-submitted scripts against expected outputs.
- **Theory exercise**: A guided walkthrough with embedded prompts and automated checking of typed responses.

## lab.yaml for a Wasm Lab

```yaml
id: wasm-jwt-decode
title: "Decode and analyse a JWT token"
type: wasm
wasm_module: content/shared-wasm/jwt-analyser/jwt-analyser.wasm
version: "1.0.0"
time_limit_minutes: 30
shell: /bin/sh       # virtual shell provided by PyramidOS

environment:
  - name: TARGET_JWT
    value: "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."

flags:
  - id: flag-jwt-alg-none
    type: static
    value: "CYBERPATH{alg_none_bypass}"
    points: 100

resources:
  memory_limit: "32m"  # interpreted by PyramidOS, not Docker
```

## Limitations vs Docker Labs

- No network services: Wasm labs cannot bind ports or serve HTTP. Learners cannot run `curl` against a target inside the same lab.
- Single process: PyramidOS runs one Wasm instance per session. Process forking is simulated but restricted.
- No persistent storage: The in-memory filesystem is reset at session end. There is no way to mount a volume.
- Limited syscall surface: Only WASI-defined syscalls are available. Raw socket creation, `ptrace`, `ioctl`, and similar are not supported.
- Larger Wasm binaries (> 50 MB) increase session startup time noticeably. Keep modules small; use shared data files referenced via the virtual filesystem rather than embedding large datasets in the binary.

For any lab that requires a real HTTP server, database, or multi-process interaction, use the `docker` type.
