## ADR-007 — Three-tier architecture: Go API, Python ML, Rust crypto

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core
- Related: [`docs/architecture.md`](../docs/architecture.md),
  ADR-001 (gRPC Go↔Python),
  ADR-002 (Rust subprocess IPC),
  ADR-012 (Python ML service)

## Context

VertGuard must combine three distinct capability clusters:
API orchestration (Go ecosystem strength), ML inference (Python
ecosystem strength), and cryptographic operations (Rust ecosystem
strength for `c2pa-rs`, memory-safe pattern matching). No single
language covers all three well.

The question is how to structure the runtime boundaries between
these concerns.

## Decision

VertGuard uses a **three-tier architecture**:

1. **Go — transport and orchestration.** The chi HTTP server,
   database access (pgx), CITADEL integration, ThreatFlow push,
   rate limiting, authentication, and request-scoped logging. Go
   is the control plane; it owns all external API surfaces.

2. **Python — ML inference (Phase 4.2+).** HuggingFace model
   loading, preprocessing, inference, and scoring. Runs as a
   separate gRPC service (`ghcr.io/opensecstack/vertguard-ml`).
   Communicates with Go via the `proto/ml/v1/inference.proto`
   contract (see ADR-001).

3. **Rust — cryptographic and hot-path operations.** C2PA manifest
   verification (`c2pa-rs`), OWASP LLM Top 10 pattern matching,
   audio fingerprinting, and TripleHash computation. Called from
   Go via subprocess IPC (see ADR-002) or compiled in-process via
   `rust/prompt-patterns/`.

Each tier communicates only through well-defined interfaces. The Go
tier owns all state (PostgreSQL); the Rust and Python tiers are
stateless workers.

## Reasons

- **Ecosystem fit.** Python's ML stack (transformers, torch,
  onnxruntime) is years ahead of Go or Rust equivalents. Rust's
  memory safety guarantees and `c2pa-rs` ecosystem are unmatched
  for cryptographic verification. Go's concurrency model and
  ecosystem familiarity (all other opensecstack platforms are Go)
  make it the right control plane.
- **Independent scaling.** The Python ML pod can be sized and
  scheduled (GPU node pool) independently of the Go API pod. The
  Rust subprocess has near-zero marginal overhead and adds no
  separate process for pattern matching.
- **Fault isolation.** A crash in the Python ML pod degrades
  ML-dependent modules (deepfake, phishing ML) but leaves
  prompt injection (Rust patterns), threat feed (Go), and media
  C2PA verification (Rust subprocess) fully operational. A Rust
  subprocess crash returns a structured error to Go; it does not
  take down the API.
- **Consistent with opensecstack conventions.** All opensecstack
  platforms use Go as the API layer. Familiarity reduces on-call
  cognitive load.

## Consequences

- **Two container images.** `vertguard-api` (Go + Rust binaries)
  and `vertguard-ml` (Python). Both ride the same `vertguard/v*`
  release tag to prevent skew. The Helm subchart gates the ML
  pod behind `ml.enabled`.
- **Two release channels to coordinate.** Proto file changes must
  be backward-compatible or both images must be rolled atomically.
  The `.proto` file carries a `v1` version prefix for this reason.
- **Rust compilation in CI.** `cargo build --release` for two
  crates (`c2pa-verify`, `prompt-patterns`) adds ≈ 3 min to CI.
  Cached via `~/.cargo/registry` layer in GitHub Actions.

## Alternatives considered + rejected

- **Single Go binary with CGo for Rust.** CGo links Rust into Go;
  scheduler interference; one Rust panic kills the Go process.
  No Python ML story. **Rejected.**
- **Python monolith.** Go HTTP performance, ecosystem, and existing
  opensecstack operator familiarity lost. Python's GIL limits
  request concurrency. **Rejected.**
- **Microservices per module.** Five separate services instead of
  three tiers adds operational overhead with no scaling benefit
  at current traffic volumes. **Deferred to v1.x enterprise.**

## Validation

- `go test ./...` must pass with `ml.enabled=false` (no Python).
- `cargo test --workspace` must pass independently of Go.
- End-to-end: scan, media verify, phishing, and IOC feed endpoints
  must all return 2xx in the integration test suite.

## Follow-ups

- ADR-014 (when issued) — mTLS between Go and Python tiers.
- Phase 4.3: evaluate shared-cluster ML service (one Python pod
  serving multiple Go pods) vs. sidecar per pod.
