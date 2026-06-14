# Wasm Sandbox — Ecosystem Overview

This document describes the role WebAssembly (Wasm) sandboxing plays
across the opensecstack ecosystem, the shared Rust host crate that
implements it, and the roadmap for expanding Wasm use beyond its
current home in CyberPath.

For the CyberPath-specific runtime detail — lab images, capability
bag, audit trail, build/sign/verify pipeline — see
[cyberpath/docs/wasm-sandbox.md](../cyberpath/docs/wasm-sandbox.md).

---

## Why the ecosystem needs a Wasm sandbox layer

Three opensecstack concerns require executing untrusted or
semi-trusted code in isolation:

1. **CyberPath lab runtime.** Learners execute exercises inside a
   live environment. The environment must be isolated from the host,
   from other learners, and from the CyberPath API process itself.

2. **VertGuard sandboxed model execution (planned, Phase 4.2+).**
   VertGuard's ML inference side-car runs community-contributed
   detection models. A contributed model that is buggy, adversarial,
   or simply slow must not be able to crash the side-car, leak memory
   from adjacent inferences, or consume unbounded CPU.

3. **SecureLab simulation payloads (planned, Phase 3).** Attack
   simulation scenarios contain deliberately adversarial code
   fragments. Running them in a Wasm sandbox bounds the blast radius
   of a scenario that misbehaves.

In all three cases the threat model is the same: code written by
someone other than the core platform team executes on production
infrastructure. The sandbox provides isolation without the overhead
and kernel-sharing risk of Docker.

---

## The shared sandbox-host crate

Rather than build an independent Wasm runtime per platform, the
ecosystem shares a single Rust crate:

```
sdk/rust/sandbox-host/          (canonical location)
```

The crate is published internally as `opensecstack-sandbox-host`.
Platform-specific host crates depend on it and add the
IPC surface, capability bag configuration, and prewarm logic
appropriate to their use case:

| Platform | Host crate | Status |
|---|---|---|
| CyberPath | `cyberpath-sandbox-host` | Active — ships with Module 4 in v1.0.0 |
| VertGuard | `vertguard-sandbox-host` | Planned — Phase 4.2 |
| SecureLab | `securelab-sandbox-host` | Planned — Phase 3 |

The shared crate owns:

- **Runtime initialisation** — `wasmtime::Engine` + `wasmtime::Store`
  construction with the security configuration described below.
- **Fuel accounting** — instruction-count-based CPU metering, exposed
  as a configurable limit per execution unit.
- **Memory cap enforcement** — host-side memory limit applied at
  `wasmtime::Config` level, not guest-cooperative.
- **Execution timeout** — wall-clock supervisor (Rust async task)
  that sends a trap to the instance on deadline; not defeatable by
  guest code.
- **Cosign verification helper** — verifies OCI-based Wasm artefacts
  against the Sigstore trust root before instantiation.
- **Audit event emission** — structured JSON log line per execution
  unit (input hash, output hash truncated to 4 KB, fuel used,
  wall-clock, exit code).

Platform-specific crates extend it with IPC (unix socket or loopback)
and any platform-specific WASI host functions.

---

## Security model

### Runtime

The sandbox host uses `wasmtime` (Bytecode Alliance), pinned to a
release with active security support. The pinned version is recorded
in `Cargo.lock` and reviewed alongside each platform's SECURITY.md.
The patch SLA for high/critical wasmtime CVEs is 7 days across all
platforms that embed the sandbox host.

### Syscall surface

Wasm modules have no syscall surface. There is no `int 0x80`, no
`syscall` instruction, no OS-level capability. The module interacts
with the world only through explicitly granted WASI host functions.
This is a property of the Wasm ISA and the wasmtime runtime, not a
policy enforced by opensecstack code.

### Syscall allow-list (WASI capability bag)

The default bag applied by `opensecstack-sandbox-host` is deny-all.
Each consuming platform assembles a bag from the following set of
permitted capabilities:

| Capability | Default | Notes |
|---|---|---|
| Virtual FS read | on | Read-only mount of pre-staged fixtures |
| Virtual FS write | on | Per-session in-memory scratch dir only |
| Stdin / stdout / stderr | on | Relay to the calling process |
| Monotonic + wall clock | on | Millisecond resolution only; high-precision counters are not exposed |
| CSPRNG | on | Host-provided; `getrandom` equivalent |
| Args + env | on | Flat list controlled by the host |
| Raw syscalls | off (enforced by runtime) | Not available in Wasm |
| `fork` / `exec` / `spawn` | off | Not in WASI Preview 2 |
| Host filesystem | off | Only the virtual FS is mounted |
| Network egress | off by default | Per-module whitelist required; enforced via host-side proxy |
| Listening sockets | off | Modules never bind |
| Threads | off in v1.0 | Revisit when `wasi-threads` spec stabilises |

Platform crates may restrict this further. CyberPath, for example,
does not expose network egress by default; a lab must explicitly
declare the egress whitelist in its manifest, and the manifest is
reviewed in CI before merge.

### Memory caps

Memory is limited at the wasmtime engine level. Attempts by guest
code to allocate beyond the cap raise a Wasm trap, not a panic in
the host process. The host process is never at risk of OOM from a
runaway guest.

Default caps (per platform, overridable in the module manifest):

| Platform | Default memory cap |
|---|---|
| CyberPath labs | 512 MB (shell: 256 MB, Jupyter: 1 GB) |
| VertGuard model runner (planned) | 2 GB (inference workloads are larger) |
| SecureLab simulation (planned) | 256 MB |

### Execution timeout

Each execution unit (a single command in CyberPath, a single
inference call in VertGuard) is supervised by a Rust async task in
the host process. On deadline the supervisor sends a non-cooperative
trap to the wasmtime instance. Guest code cannot defer or catch this
trap — it terminates the instance.

Fuel limits (instruction counting) provide a secondary, CPU-based
bound. The wall-clock timeout is the primary safety net; fuel catches
pathological loops that consume CPU without making I/O calls.

### Module provenance

Every Wasm module loaded by the sandbox host must pass cosign
verification against the Sigstore trust root before instantiation.
The OCI digest is content-addressed; a module that does not match
the pinned digest fails verification and is never instantiated.
Verification runs on every pull, not only at publish time.

---

## How each platform integrates the sandbox

### CyberPath (active)

```
CyberPath API (Go) :8086
    |
    | unix socket / loopback IPC
    v
cyberpath-sandbox-host (Rust)
    |-- wasmtime instance per lab session
    |-- WASI Preview 2 component model
    |-- prewarm pool (N=10 instances, configurable)
    v
Lab module (.wasm) pulled from OCI registry
```

The Go API never speaks to wasmtime directly. Every interaction goes
through the Rust host so the capability bag is enforced in one place.
The prewarm pool keeps N instances ready so session start latency
stays sub-second at cohort scale.

See [cyberpath/docs/wasm-sandbox.md](../cyberpath/docs/wasm-sandbox.md)
for the full capability matrix, lab image lifecycle, and audit trail.

### VertGuard model runner (planned — Phase 4.2)

```
VertGuard Go service :8091
    |
    | gRPC (internal)
    v
VertGuard ML inference side-car (Python / gRPC) :50051
    |
    | IPC
    v
vertguard-sandbox-host (Rust)
    |-- one wasmtime instance per inference call
    |-- model artefact pulled from internal OCI registry
    |-- memory cap: 2 GB per instance
    |-- timeout: configurable per model, default 30 s
```

The side-car will wrap community-contributed detection models
(deepfake classifiers, prompt-injection detectors). Sandboxing
ensures a contributed model cannot exfiltrate inference inputs,
access adjacent model weights, or consume unbounded resources.
The architecture is designed for Phase 4.2; the interface is
specced in [VertGuard RFC-0004](../rfcs/RFC-0004-vertguard-platform.md).

### SecureLab simulation runner (planned — Phase 3)

Attack simulation scenarios will compile adversarial payloads to
Wasm. The sandbox runner executes them against virtual targets
(network stubs, file system mocks) without touching real
infrastructure. Results feed IRFlow, OpenScrub, and ThreatFlow for
detection-rule validation.

---

## Operational considerations

### Resource limits

Each platform's sandbox host exposes Prometheus metrics:

| Metric | Description |
|---|---|
| `sandbox_instance_starts_total` | Count of instances launched |
| `sandbox_instance_failures_total` | Count of traps, timeouts, OOM kills |
| `sandbox_fuel_used_total` | Cumulative fuel consumed (proxy for CPU) |
| `sandbox_memory_bytes_peak` | Peak guest memory per instance |
| `sandbox_wall_clock_seconds` | Execution wall time histogram |
| `sandbox_prewarm_pool_size` | CyberPath: current prewarm pool depth |

Alert on `sandbox_instance_failures_total` spiking relative to
`sandbox_instance_starts_total` — a sudden failure rate increase
indicates either a bad module artefact or resource exhaustion on
the host.

### Capacity planning

A wasmtime instance for a typical CyberPath lab pins approximately
30 MB RSS on startup. At 200 concurrent sessions this is 6 GB for
instances alone, plus the prewarm pool. Plan host memory with a 2x
headroom factor. For VertGuard inference workloads the per-instance
cap is 2 GB; plan inference hosts accordingly and isolate them from
CyberPath hosts.

### Security patching

The shared `opensecstack-sandbox-host` crate carries the wasmtime
dependency. A security patch to wasmtime propagates to all platforms
via a single crate update and a coordinated release. The 7-day patch
SLA for high/critical CVEs applies to any platform that ships the
sandbox host in a production release.

### Audit trail

Every execution unit generates an audit event persisted by the
platform that owns the session:

- session or inference ID
- module OCI digest (verifiable reference)
- fuel consumed
- wall-clock duration
- input hash (SHA-256 of argv + stdin or inference input)
- output hash truncated (SHA-256 of first 4 KB)
- exit code or trap reason
- capability bag snapshot (which capabilities were active)

For CyberPath, these events are queryable per learner session. For
VertGuard, they are part of the detection evidence chain that flows
to CITADEL's WORM log.

---

## Roadmap

| Milestone | Target | What ships |
|---|---|---|
| CyberPath v1.0.0 (Phase 2) | 2026 Q3 | `cyberpath-sandbox-host`; WASI Preview 2 lab modules; cosign verification; prewarm pool |
| SDK sandbox-host extraction | 2026 Q4 | `opensecstack-sandbox-host` extracted to `sdk/rust/sandbox-host/`; shared by all future consumers |
| VertGuard Phase 4.2 | 2027 Q3–Q4 | `vertguard-sandbox-host`; sandboxed ML model execution; gRPC inference interface |
| SecureLab Phase 3 | 2027 Q3 | `securelab-sandbox-host`; adversarial payload runner; virtual network stubs |
| Threading (all platforms) | v1.1 | `wasi-threads` support once spec stabilises and shared-memory side-channel threat model is reviewed |
| gVisor fallback (CyberPath) | v1.1 | Docker labs (Track 7 Linux hardening) wrapped in gVisor to close kernel-shared attack surface |
| Snapshotting | v1.1 | Instance snapshot/restore for long-form CyberPath labs that span pod restarts |

---

## Related

- [cyberpath/docs/wasm-sandbox.md](../cyberpath/docs/wasm-sandbox.md) — CyberPath runtime detail, lab image lifecycle, threat model
- [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md) — Wasm vs Docker decision record
- [rfcs/RFC-0004-vertguard-platform.md](../rfcs/RFC-0004-vertguard-platform.md) — VertGuard architecture including sandboxed model runner
- [docs/security-architecture.md](./security-architecture.md) — Five-layer defence model (Layer 3: Host Fence)
- [docs/deployment-topology.md](./deployment-topology.md) — Port assignments and network segmentation
- Bytecode Alliance wasmtime: https://wasmtime.dev
- WASI Preview 2: https://github.com/WebAssembly/WASI
- Sigstore cosign: https://docs.sigstore.dev/cosign/overview
