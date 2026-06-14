# Module 4: Wasm Sandbox Labs

> Status: design intent for v1.0.0. The sandbox host crate
> (`cyberpath-sandbox-host`) and the lab images (under
> `ghcr.io/opensecstack/cyberpath-labs/`) land alongside this module
> in v1.0.0. Module 3 (Docker-Based Labs) is the bridge runtime
> for v1.0.0.
>
> See [wasm-sandbox.md](wasm-sandbox.md) for the full sandbox design,
> threat model, capability model, and image distribution guide. This
> document covers the module-layer concerns: lifecycle, IDE integration,
> challenge validation, and the API contract.

## Overview

Module 4 manages Wasm-based lab sessions. It shares the same API
surface as Module 3 (Docker labs) from the frontend's perspective —
the `lab_sessions` table, the WebSocket terminal relay, and the
validate endpoint are common. What differs is the runtime underneath:
instead of a Docker container, each session is a wasmtime instance
managed by the `cyberpath-sandbox-host` Rust crate.

The Go API (`internal/lab/wasm/`) speaks to the Rust host over a
Unix socket (loopback on Windows). The Rust host manages the wasmtime
engine, the prewarm pool, the capability bag, and the per-command
supervisor.

## How Wasm labs differ from Docker labs

| Dimension | Docker (Module 3) | Wasm (Module 4) |
|---|---|---|
| Start latency | p95 ~30 s (image pull + namespace) | p95 ~200 ms (prewarm pool) |
| Memory per session | ~150 MB RSS (Linux userspace) | ~30 MB |
| Kernel sharing | Shares host kernel | No kernel; runs in wasmtime VM |
| Audit trail | Docker exec log | Per-command `lab_command_log` with input/output hash |
| Reset mechanism | New container | New wasmtime instance (same prewarm pool) |
| Filesystem | Overlay FS (container layers) | Virtual FS (read-only `/lab`, writable `/scratch` in-memory) |
| Network | Docker bridge with egress block | WASI sockets via proxy; per-lab egress whitelist |
| v1.0.0 audit scope | **Out of scope** | **In scope** |

Docker labs remain for Track 7 (Linux hardening) where a genuine
Linux userspace (SELinux, auditd, package manager) is required by the
exercise. All other tracks use Wasm labs in v1.0.0+.

## Sandbox architecture

See [wasm-sandbox.md](wasm-sandbox.md) for the full architecture
diagram and component breakdown. Summary for this module's purposes:

```
Go API (internal/lab/wasm/)
  │
  │  IPC: Unix socket (JSON-RPC 2.0)
  ▼
cyberpath-sandbox-host (Rust)
  │  wasmtime engine
  │  WASI Preview 2
  │  prewarm pool (N=10 instances per lab image)
  ▼
Lab module (.wasm)
  pulled from OCI by digest, verified by cosign
```

The Go API issues commands to the Rust host:

- `session.start` — claim a prewarm instance (or cold-start if pool is empty)
- `session.exec` — run a command inside the instance; returns stdout/stderr + exit code
- `session.reset` — discard the instance; replenish pool with a new prewarm
- `session.stop` — discard the instance; no replenishment
- `session.validate` — run the embedded challenge checker; returns pass/fail + feedback

All commands are serialised per-session. Concurrent `exec` calls on
the same session are rejected with `concurrent_exec_rejected`.

## Syscall allow-list

The Wasm module has no direct syscall surface — this is enforced by
the wasmtime runtime, not by an allow-list. Instead, capability
admission is reviewed at the host-import level: every WASI import the
module uses must be present in the capability bag attached at
instantiation.

The effective allow-list is the intersection of:
1. WASI Preview 2 functions the Rust host exposes, and
2. The capabilities declared in the lab manifest (see
   [wasm-sandbox.md § Capability model](wasm-sandbox.md#capability-model)).

Raw syscalls (`syscall`, `io_uring_*`, etc.) are not in the WASI
interface and are structurally unavailable — no kernel exposure.

## Memory limits

Enforced via wasmtime's `Config::max_wasm_stack` and the linear memory
limit in `InstanceLimits`. These are set by the Rust host, not by the
lab module; the module cannot override them.

Default: 512 MB linear memory. Labs declare their requirement in the
manifest; the host caps the allocation at `min(declared, 512 MB)`.
If a lab module attempts to grow memory beyond its cap,
`memory.grow` returns -1 (WASM semantics) — the module receives a
clean error, not an OOM kill.

Stack overflow (deep recursion) results in a wasmtime trap delivered
to the host; the host returns `exec_trapped` to the Go API, which
surfaces it to the learner as "your command crashed the sandbox."

## Execution timeout

Two layers:

1. **Wasm fuel** — a wasmtime mechanism that counts executed
   instructions. Each command execution starts with a fresh fuel
   budget (`10⁹` units by default). When fuel runs out, execution
   is interrupted with a `fuel_exhausted` trap. This is a
   non-cooperative interrupt; the guest cannot suppress it.

2. **Wall-clock supervisor** — the Rust host runs each `session.exec`
   on an async task with a tokio timeout (60 s default). If the wall
   clock expires before fuel does (e.g. the module is blocked on
   I/O), the Rust host sends a trap signal to the instance.

Per-lab overrides (from the manifest) are applied at session start:

```yaml
resource_limits:
  fuel_per_command: 5_000_000_000
  wall_clock_per_command_seconds: 120
  total_session_seconds: 1800
  memory_mb: 256
```

## IDE integration

Labs that present a code-editing task use the browser-based IDE
surface rather than a raw terminal. The IDE (Monaco-based, v1.0.0
candidate) communicates with the Wasm instance via the same WebSocket
relay, but uses a structured channel instead of raw terminal I/O:

```
WS metadata channel (JSON):
  { "type": "ide_save", "file": "/scratch/solution.py", "content": "..." }
  { "type": "ide_run",  "file": "/scratch/solution.py" }

WS output channel (raw):
  stdout/stderr of the run (same as terminal output)
```

The Go API translates `ide_save` into a `session.exec` that writes
the content to `/scratch/<file>` via a host-side helper (does not go
through the Wasm module's filesystem API — uses the host's in-memory
VFS directly). `ide_run` translates to a `session.exec` of the lab's
run script with the saved file as input.

IDE integration is gated behind `CYBERPATH_LAB_IDE_ENABLED=true`. In
v1.0.0, only Track 3 (Secure coding) and Track 5 (API security) labs
use the IDE surface. All other tracks use the raw terminal.

## Challenge validation

Challenge validation for Wasm labs is different from Docker labs:
there is no external check script. The challenge checker is compiled
into the Wasm module itself as a separate export:

```rust
// In the lab module (Rust, design intent)
#[export_name = "cyberpath_validate"]
pub extern "C" fn validate() -> i32 {
    // Returns 0 = pass, non-zero = fail
    // Writes feedback to stdout before returning
}
```

The Rust host calls this export via the `session.validate` IPC
command. The Go API does not need to exec a script path — validation
is a first-class module operation.

This design has two advantages over the Docker check-script approach:
1. The checker runs inside the sandbox — it cannot access host
   resources the module itself cannot access.
2. The checker is signed alongside the module (same OCI artefact, same
   cosign signature) — there is no separate script to tamper with.

On pass:
1. `lab_sessions.status` → `validated`
2. `lab_sessions.ended_at` → now()
3. Prewarm pool replenished (a new instance is started in the
   background to replace the consumed one).
4. Module 1 is notified via the internal lab-complete callback.

On fail:
- Status remains `running`.
- Fuel and wall-clock budgets are reset for the next command.
- Learner sees the checker's stdout feedback (≤2 KB, truncated by the
  host if the module emits more).

## Prewarm pool

The Rust host maintains a pool of pre-instantiated wasmtime instances
per lab image. Pool size is configurable:

```bash
CYBERPATH_WASM_PREWARM_POOL_SIZE=10   # instances per lab image
CYBERPATH_WASM_PREWARM_REFILL_DELAY=5 # seconds after consumption before refill starts
```

When a learner starts a lab:
1. The host checks the pool for the requested lab image.
2. If a prewarm instance is available, it is claimed immediately
   (sub-second start).
3. If the pool is empty (cold path), the host instantiates a new
   instance synchronously (≤1 s for typical lab sizes).
4. A background task refills the pool asynchronously.

Prewarm instances are initialised with the lab's static capability
bag. The per-session capability bag (with learner-specific values like
session metadata) is applied at claim time via a host-side patch
before handing off the instance to the session.

## Lab session state

Wasm lab sessions go through the same state machine as Docker lab
sessions (`created` → `running` → `validated` | `stopped` | `expired`).
The `lab_sessions` table is shared; the `runtime` column differentiates
the two.

Wasm sessions do not persist state across resets or restarts —
`/scratch` is in-memory and discarded on instance teardown. This is
by design; see [wasm-sandbox.md § v1.1+ ideas](wasm-sandbox.md#v11-ideas)
for the snapshotting roadmap item.

## Audit trail

Every command exec is logged in `lab_command_log` (defined in
[wasm-sandbox.md § Audit trail](wasm-sandbox.md#audit-trail)):

- `input_hash` — SHA-256 of the command argv + stdin
- `output_hash_truncated` — SHA-256 of the first 4 KB of stdout/stderr
- exit code, wall-clock ms, fuel used
- session id, command index (monotonic)

The validate call is also logged as a special command with
`is_validation: true`.

## API contract

The Wasm lab API is identical to the Docker lab API (Module 3) from
the caller's perspective. The `runtime` field in the response
distinguishes which runtime handled the session.

### Start a lab session

```
POST /api/v1/labs/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "lesson_id": "uuid"
}

200 OK
{
  "session_id":         "uuid",
  "runtime":            "wasmtime",
  "ws_url":             "wss://cyberpath.example.org/api/v1/labs/sessions/{session_id}/terminal",
  "session_timeout_at": "2025-05-06T10:30:00Z",
  "reset_allowed":      true,
  "resets_remaining":   3,
  "prewarm_hit":        true
}
```

`prewarm_hit` is informational for telemetry; the frontend does not
use it.

### Validate (check work)

```
POST /api/v1/labs/sessions/{session_id}/validate
Authorization: Bearer <token>

200 OK
{
  "passed":    true,
  "feedback":  "Phishing indicator correctly identified. Score: 5/5.",
  "runtime":   "wasmtime",
  "fuel_used": 48203917
}
```

`fuel_used` is included for operator observability (understand whether
challenges are compute-heavy).

### IDE save + run (structured channel over WebSocket)

The IDE surface uses the WebSocket metadata channel; no separate HTTP
endpoints. See the IDE integration section above for the message
schema.

## Configuration

```bash
CYBERPATH_LAB_RUNTIME=wasmtime                 # selects Module 4 over Module 3
CYBERPATH_WASM_HOST_SOCKET=/run/cyberpath/sandbox.sock
CYBERPATH_WASM_PREWARM_POOL_SIZE=10
CYBERPATH_WASM_PREWARM_REFILL_DELAY=5
CYBERPATH_WASM_DEFAULT_FUEL=1000000000
CYBERPATH_WASM_DEFAULT_WALL_CLOCK_S=60
CYBERPATH_WASM_DEFAULT_SESSION_TIMEOUT_S=1800
CYBERPATH_WASM_DEFAULT_MEMORY_MB=512
CYBERPATH_LAB_IDE_ENABLED=false
```

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `lab_not_found` | 404 | No lab defined for this lesson |
| `session_not_found` | 404 | Session UUID does not exist |
| `active_session_exists` | 409 | Learner already has a running session for this lesson |
| `session_expired` | 409 | Session wall-clock exceeded |
| `session_not_running` | 409 | Validate or reset on a non-running session |
| `exec_trapped` | 500 | Wasm instance trapped (stack overflow, OOM within sandbox) |
| `fuel_exhausted` | 429 | Command exceeded fuel budget |
| `concurrent_exec_rejected` | 429 | Second exec while first is still running |
| `image_unverified` | 502 | cosign verification failed for the lab image |
| `sandbox_host_unavailable` | 503 | Unix socket to Rust host is down |

## Observability

- `cyberpath_wasm_sessions_started_total` — counter, labels: `track_slug`, `prewarm_hit`
- `cyberpath_wasm_sessions_validated_total` — counter, labels: `track_slug`
- `cyberpath_wasm_sessions_expired_total` — counter
- `cyberpath_wasm_prewarm_pool_size` — gauge, labels: `lab_slug`
- `cyberpath_wasm_exec_fuel_used` — histogram, labels: `lab_slug`
- `cyberpath_wasm_exec_duration_ms` — histogram, labels: `lab_slug`
- `cyberpath_wasm_traps_total` — counter, labels: `trap_reason`

## See also

- [wasm-sandbox.md](wasm-sandbox.md) — full sandbox design, capability model, threat model
- [module-3-docker-labs.md](module-3-docker-labs.md) — Docker lab module (bridge runtime)
- [module-1-learning-path.md](module-1-learning-path.md) — lab as lesson sub-item
- [architecture.md](architecture.md) — system topology
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
- Bytecode Alliance wasmtime: <https://wasmtime.dev>
- WASI Preview 2: <https://github.com/WebAssembly/WASI>
