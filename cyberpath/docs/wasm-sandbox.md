# CyberPath Wasm Sandbox

> Status: design intent for v1.0.0. The sandbox host crate
> (`cyberpath-sandbox-host`) and the lab images (under
> `ghcr.io/opensecstack/cyberpath-labs/`) land alongside Module 4
> ("Wasm Sandbox Labs") in v1.0.0. Module 3 ("Docker-Based Labs")
> ships in v1.0.0 as the bridge runtime.

## Why Wasm vs Docker

ADR-012 chose Wasm as the v1.0.0+ lab runtime; recap of the
decision:

- **Spinup latency.** Docker container spinup p95 is 30s+ on a warm
  host (image pull + namespace setup + entrypoint init).
  `wasmtime` instance spinup is sub-second for the same lab classes.
  At cohort-scale (hundreds of learners launching the same lab
  within a 5-minute window), Docker forces operator-side capacity
  pre-warming; Wasm does not.
- **Resource cost.** A Docker container holding a Linux userspace
  for an exercise that only needs "edit a file, run a checker"
  pins ~150 MB RSS per session. A Wasm instance for the same task
  pins ~30 MB.
- **Attack surface.** Docker shares a kernel with the host; sandbox
  escapes are kernel CVEs. Wasm runs in a Bytecode-Alliance-hardened
  VM with no syscall surface — the threat model is well-bounded.
- **Reproducibility.** A Wasm module is a single signed artefact.
  Lab content is reproducible bit-for-bit from the OCI digest;
  Docker images can drift via layer caches.

Docker labs (Module 3) remain in scope for exercises that *genuinely
need* a Linux userspace (e.g. CIS-benchmark hardening on a
deliberately under-hardened reference VM — Track 7 Linux hardening).
For everything else — phishing-sample classification, secure-coding
patching, IRFlow-driven IR exercises, PCAP analysis — Wasm is the
default in v1.0.0+.

## Runtime architecture

```
┌──────────────────────────────────────┐
│  CyberPath API (Go) :8086            │
│   internal/lab/                      │
│    • POST /api/v1/labs/start         │
│    • WebSocket relay (xterm.js)      │
└─────────────┬────────────────────────┘
              │ unix socket / loopback
              ▼
┌──────────────────────────────────────┐
│  cyberpath-sandbox-host (Rust)       │
│   • wasmtime engine                  │
│   • WASI Preview 2 implementation    │
│   • per-session capability bag       │
│   • prewarm pool (N=10 instances)    │
└─────────────┬────────────────────────┘
              │ wasmtime instance boundary
              ▼
┌──────────────────────────────────────┐
│  Lab module (.wasm)                  │
│   pulled from OCI:                   │
│   ghcr.io/opensecstack/cyberpath-    │
│   labs/<lab-id>:<version>            │
│   verified via cosign keyless        │
└──────────────────────────────────────┘
```

- **Runtime:** `wasmtime` (Bytecode Alliance), pinned at a release
  with active security support. The version is recorded in
  `Cargo.toml` and reviewed alongside SECURITY.md's patch SLA.
- **Host crate:** `cyberpath-sandbox-host`, Rust. Exposes a small
  IPC surface to the Go API. The Go API never speaks to wasmtime
  directly — every interaction goes through the Rust host so the
  capability bag is enforceable in one place.
- **Module format:** WASI Preview 2 components. Lab authors compile
  with `cargo component build --release` (Rust) or
  `wasi-sdk` clang (C / C++) or `tinygo build -target=wasi` (Go).

## Capability model

Every lab module runs with an explicit capability bag attached at
instantiation. The default bag is **deny-all**; the lab manifest
enumerates each capability the lab needs and the host audits that
list at admission time.

| Capability | Default | What it enables |
|---|---|---|
| Virtual FS read | on | Read pre-staged lab fixtures (read-only mount) |
| Virtual FS write | on | Write to a per-session scratch dir (in-memory tmpfs) |
| Stdin / stdout / stderr | on | xterm.js relay |
| Wall clock | on | `monotonic_now`, `wall_now` |
| Random | on | `random_get` (host-provided CSPRNG) |
| Args + env | on | flat list passed by the host |
| Raw syscalls | **off** | Wasm has no syscall surface; this is enforced by the runtime, not opt-in |
| `fork` / `exec` / `spawn` | **off** | Not in WASI Preview 2 |
| Network egress | **off by default** | Per-lab whitelist (see below) |
| Host filesystem | **off** | Only the virtual FS is mounted |
| Sockets — listen | **off** | Labs never expose listening sockets |
| Threads | **off in v1.0.0** | Single-threaded only; revisit at v1.1 |

### Virtual filesystem

Each lab session gets a fresh virtual FS:

```
/lab           (read-only)  — pre-staged fixtures from the lab image
/scratch       (read-write) — per-session tmpfs, gone at instance teardown
/etc/lab.json  (read-only)  — session metadata (lab id, content_version_id)
```

There is **no** `/proc`, no `/dev`, no `/sys`, no `/host`. The lab
module sees only what the manifest declared.

### Network egress whitelist

Labs that legitimately need outbound network (e.g. Track 6 Threat
Intelligence basics, where the learner queries a sample TAXII feed)
declare the egress whitelist in the lab manifest:

```yaml
# labs/threat-intel-taxii/lab.yaml
id: threat-intel-taxii
runtime: wasmtime
network:
  egress:
    - host: taxii.lab.opensecstack.io
      port: 443
      protocol: https
```

The Rust host enforces the whitelist via a host-side proxy: the
Wasm module only sees a `wasi:sockets/0.2.0` interface bound to a
proxy address, and the proxy refuses anything not in the whitelist.
DNS resolution is server-side and cached.

## Resource limits

Defaults (per-lab override in the manifest):

| Limit | Default | Shell-lab override | Jupyter-lab override |
|---|---|---|---|
| CPU | 1 core | 1 core | 2 cores |
| Memory | 512 MB | 256 MB | 1 GB |
| Wall-clock per command | 60 s | 30 s | 300 s |
| Total session | 30 min | 30 min | 60 min |
| Wasm fuel | 10⁹ units / command | 5×10⁸ | 10¹⁰ |
| File descriptors | 64 | 64 | 256 |

Enforcement: wasmtime fuel + memory limits (host-side, not
guest-cooperative); the per-command wall-clock is enforced by the
Rust host's IPC supervisor (which sends a `trap` to the instance
on timeout).

The Go API tracks total session time and refuses new commands once
the budget is exhausted; the learner sees a clean
`session-time-exceeded` message.

## Lab images

### Build

```bash
# Rust lab — most common
cd labs/phish-classify-1
cargo component build --release --target wasm32-wasip2
# Output: target/wasm32-wasip2/release/phish_classify_1.wasm

# Multi-stage container that bundles fixtures alongside the .wasm
docker build -t ghcr.io/opensecstack/cyberpath-labs/phish-classify-1:1.4.0 \
    -f labs/phish-classify-1/Dockerfile.lab .
```

The `Dockerfile.lab` is a thin OCI wrapper — it does not produce a
runnable container, only a registry artefact whose layers are the
`.wasm` module + the pre-staged virtual FS.

### Distribute

```bash
docker push ghcr.io/opensecstack/cyberpath-labs/phish-classify-1:1.4.0
# Capture the digest for pinning
docker buildx imagetools inspect \
    ghcr.io/opensecstack/cyberpath-labs/phish-classify-1:1.4.0 \
    --format '{{json .Manifest}}' | jq -r .digest
# → sha256:8f3c9e5a2b...
```

The digest goes into `lab_definitions.image_digest`. The `image_ref`
(tag) is informational; the host pulls by digest only.

### Sign

Cosign keyless (Sigstore), same trust root as VertGuard's container
images:

```bash
cosign sign --yes \
    ghcr.io/opensecstack/cyberpath-labs/phish-classify-1@sha256:8f3c9e5a2b...
```

### Verify (host-side, on every pull)

```bash
cosign verify \
    --certificate-identity-regexp 'https://github.com/opensecstack/.+' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    ghcr.io/opensecstack/cyberpath-labs/phish-classify-1@sha256:8f3c9e5a2b...
```

The Rust host runs the cosign verification before instantiating the
module. Verification failures are surfaced to the API as
`lab_image_unverified` — the lab does not start.

## Threat model

Six adversaries the sandbox is designed against, and the
mitigations:

### T1: Sandbox escape via runtime CVE

A wasmtime CVE that lets a malicious module break out of the VM
boundary.

**Mitigation.** Pinned runtime version with active security support;
SECURITY.md commits to a 7-day patch SLA for high/critical wasmtime
CVEs. The Rust host is the only path the lab module sees, so even
on partial escape the host's seccomp-bpf profile (Linux deployments)
and Windows job-object limits still apply. The host process itself
runs as an unprivileged user.

### T2: Resource exhaustion / DoS

A lab module allocates memory in a loop, spins on CPU, or fills the
scratch FS.

**Mitigation.** Hard memory limit via wasmtime config; CPU enforced
via fuel; scratch tmpfs sized at 64 MB by default; per-command
wall-clock enforced by host supervisor (a non-cooperative trap, not
a guest-side timer).

### T3: Side-channel timing attacks

A lab module measures wall-clock differences to leak host-side
information (e.g. cache timing, branch prediction).

**Mitigation.** The host clock is exposed at millisecond resolution
only; high-precision counters (`performance.now`-equivalent) are
not part of the capability bag. Cross-tenant labs run on different
sandbox host pods, so cross-lab side-channels stay within a single
learner's session.

### T4: Content tampering between host and sandbox

An attacker replaces the lab image after the digest pin but before
instantiation.

**Mitigation.** Cosign verification runs on every pull, not only at
publish time. The OCI digest is end-to-end content-addressed; a
tampered image has a different digest and fails the pin.

### T5: Capability creep via manifest abuse

A lab author requests an over-broad capability (e.g.
`network.egress: [*]`) that the reviewer does not catch.

**Mitigation.** Manifest schema validates the capability list
against an allowlist; broad wildcards (`*`) are rejected by schema.
Manifests are reviewed in PR alongside lab content. The host emits
a per-launch audit event listing the capability bag, so post-hoc
review of "what did this lab actually have access to?" is a single
SQL query.

### T6: Exfiltration via lab output

A lab module emits secrets through stdout (e.g. by reading
`/etc/lab.json` and printing it back to the learner).

**Mitigation.** `/etc/lab.json` carries only the lab id and
`content_version_id`; no secrets. The host never injects secrets
into the capability bag. The learner sees their own session output
only — no cross-learner leakage by construction.

## Audit trail

Every command exec inside a lab session is logged with:

- session id (`lab_sessions.id`)
- command index (monotonic per-session)
- `input_hash` — SHA-256 of the command argv + stdin
- `output_hash_truncated` — SHA-256 of the first 4 KB of stdout/stderr
- exit code
- wall-clock + cpu time used
- timestamp

The log is the **evidence** for the lab session. If a learner
challenges a completion ("I did the lab correctly"), an instructor
can reproduce the exact sequence of inputs the learner tried.

```sql
-- Example reconciliation query: which commands did learner X run in their last lab session?
SELECT command_index, exit_code, wall_clock_ms
FROM lab_command_log
WHERE session_id = (
    SELECT id FROM lab_sessions
    WHERE user_id = '<user-uuid>'
    ORDER BY started_at DESC LIMIT 1
)
ORDER BY command_index;
```

The full output bytes are *not* persisted — only the truncated hash
— so the audit trail does not become a privacy hazard.

## v1.1+ ideas

- **gVisor fallback** for legacy Docker labs. Currently Module 3
  Docker labs (Track 7 Linux hardening) run with the standard
  Docker engine. Wrapping them in gVisor closes the kernel-shared
  attack surface at the cost of ~10% syscall overhead. Decision
  deferred until measured impact on lab UX.
- **GPU passthrough for ML labs.** Adversarial-ML training is a
  natural extension of the catalogue; GPU passthrough into the
  Wasm sandbox is not a solved problem upstream. Track this in the
  wasmtime + WASI WG.
- **Threading.** `wasi-threads` is in flight. v1.0 ships
  single-threaded; v1.1 revisits once the spec stabilises and the
  threat model for shared-memory side channels is reviewed.
- **Snapshotting.** `wasmtime`'s instance snapshot/restore would
  let a lab resume mid-session across pod restarts. Useful for
  long-form labs (Track 3 Secure coding); v1.1 candidate.

## See also

- [architecture.md](architecture.md) — system topology
- [data-model.md](data-model.md) — `lab_definitions`, `lab_sessions`
- [secrets-management.md](secrets-management.md) — cosign trust root
- [performance.md](performance.md) — sandbox cold-start budget
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
- Bytecode Alliance wasmtime: <https://wasmtime.dev>
- WASI Preview 2: <https://github.com/WebAssembly/WASI>
- Sigstore cosign: <https://docs.sigstore.dev/cosign/overview>
