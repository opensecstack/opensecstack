## ADR-002 — C2PA media verification via Rust subprocess IPC

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core, Module 1
- Related: [`docs/architecture.md`](../docs/architecture.md),
  [`docs/module-1-media-authenticity.md`](../docs/module-1-media-authenticity.md),
  [`rust/c2pa/`](../rust/c2pa/),
  [`rust/c2pa-verify/`](../rust/c2pa-verify/),
  [`internal/media/`](../internal/media/)

## Context

Module 1 (Media Authenticity) must validate C2PA manifests embedded
in images, video, and audio. C2PA verification requires X.509
certificate chain validation and COSE cryptographic operations. The
canonical implementation is `c2pa-rs` — a Rust crate maintained by
the C2PA working group. No production-ready Go port exists.

Options evaluated: Go implementation from scratch, CGo binding to
`c2pa-rs`, and subprocess IPC via a compiled CLI binary.

## Decision

VertGuard implements C2PA verification as a **compiled Rust CLI**
(`rust/c2pa-verify/`) invoked from Go via subprocess IPC. The
`MediaConfig.BinaryPath` (env `VERTGUARD_MEDIA_BINARY_PATH`) points
at the binary. Go reads stdout (JSON result) and stderr (structured
errors); the process exits non-zero on hard failure.

## Reasons

- **CGo rejected.** CGo links the Rust runtime into the Go binary.
  Rust's panic-unwind and Go's runtime scheduler interact badly;
  a Rust panic inside a CGo call can corrupt the Go heap or deadlock.
  The Rust `c2pa-rs` crate itself spawns threads internally, which
  amplifies the scheduler interference risk.
- **Subprocess IPC isolates fault domains.** A crash in the Rust
  binary does not take down the Go server. Go captures the exit code
  and returns a structured 500 rather than panicking.
- **Performance is acceptable.** Media verification is not on the hot
  path — it is a per-file operation, not a per-token operation. The
  subprocess fork overhead (≈ 5–10 ms) is well inside the media
  handler's timeout budget.
- **No Go implementation.** Writing C2PA certificate chain validation
  and COSE signature verification from scratch in Go would be
  months of work with high risk of cryptographic errors. `c2pa-rs`
  is the reference implementation endorsed by the C2PA working group.

## Consequences

- **Binary must be present at startup.** When `BinaryPath` is empty
  the media handler returns 503 rather than panicking. Operators
  must ship the compiled binary in the container image or mount it
  as a sidecar volume.
- **Cross-compilation.** The Rust crate is compiled via `cargo build
  --release` targeting the server OS. The CI matrix compiles for
  `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu`.
- **Trust anchor + CRL reloads.** Trust anchors (`TrustAnchorsDir`)
  and CRL (`RevocationListPath`) are forwarded to the CLI at
  invocation time; the Go layer polls for mtime changes and sends
  SIGHUP to trigger hot reload.

## Alternatives considered + rejected

- **CGo binding.** Runtime interference between Rust and Go
  schedulers; one Rust panic kills the Go process. **Rejected.**
- **Go C2PA from scratch.** Months of cryptographic work; high
  defect risk; no ecosystem backing. **Rejected.**
- **Python subprocess.** Python startup overhead (≥ 200 ms) is
  unacceptable for an interactive media API. **Rejected.**

## Validation

- `cargo test -p c2pa` passes against the C2PA test-media corpus.
- `go test ./internal/media/...` exercises the subprocess wrapper,
  timeout path, and JSON result parsing.
- A media with a valid C2PA manifest must return `authentic: true`
  end-to-end via `POST /api/v1/media/verify`.

## Follow-ups

- Phase 4.2: deepfake detection (ML) for media without manifests.
- Revocation: OCSP stapling support in `c2pa-verify` (`C2PAOCSPEnabled`
  config flag is wired; implementation deferred to Phase 4.2).
