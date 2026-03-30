# ADR-002: Use Rust for Schema Parsing, Response Analysis, and CVSS Scoring

## Status

Accepted

## Context

This ADR is the repository-level complement to the ecosystem-level [ADR-001: Rust for Parsing](../../adrs/ADR-001-rust-for-parsing.md). It records the specific design decisions made within the APIGuard Rust implementation, beyond the language choice itself.

Three APIGuard layers are implemented in Rust:

- **L1 (Schema Parser)** — parses untrusted OpenAPI 3.x, Swagger 2.x, and GraphQL schemas
- **L5 (Response Analyser)** — matches patterns against untrusted HTTP responses
- **L6 (CVSS Scorer)** — implements the CVSS 3.1 formula deterministically

The key implementation decisions beyond the language choice are: how the parser communicates its output to the Go layers, how the IR is designed, and how the parser is isolated from the main process.

## Decision

### Subprocess isolation, not FFI

The Rust parser, analyser, and CVSS scorer are compiled as separate binaries and invoked by the Go orchestration layer as subprocesses via `exec.Command`. They communicate via stdin/stdout using newline-delimited JSON.

The alternative — a shared library via cgo FFI — was rejected.

### Normalised IR as the subprocess output contract

The parser subprocess outputs a single JSON object matching the `ApiSpec` IR schema. The Go layer parses this JSON into typed Go structs. The IR is the only contract between the Rust and Go worlds.

### Parser subprocess runs with a resource cap

The Go process sets `ulimit`-equivalent constraints on the parser subprocess: 512 MB memory limit, 30-second CPU timeout. A malformed spec can cause the parser to consume unbounded memory (e.g. a circular `$ref` explosion). The subprocess is killed if it exceeds limits, and the scan fails cleanly.

## Rationale

### Why subprocess, not FFI (cgo)

- A malformed schema can crash the parser. Via FFI, a parser crash is an in-process crash — it brings down the entire APIGuard server. Via subprocess, the crash is isolated to the child process. The Go parent catches the non-zero exit code and records a scan failure without affecting other running scans.
- cgo adds complexity: every cgo-using Go binary loses cross-compilation simplicity, requires the C linker, and complicates static binary builds.
- The performance cost of subprocess invocation (fork+exec, JSON serialisation) is negligible — the parser is invoked once per scan, not per HTTP request.

### Why a normalised IR, not OpenAPI structs

- OpenAPI 3.0, Swagger 2.0, and GraphQL have different structural representations. The OWASP modules should not need to know which format was parsed.
- The IR strips features APIGuard does not use, reducing the attack surface of the schema-to-module data path.
- The IR is stable across spec format versions — a Swagger 2.0 schema and an OpenAPI 3.1 schema produce identical IR for equivalent API definitions.

### CVSS as a pure Rust function

The CVSS 3.1 scorer takes metric values as typed enum inputs and returns a score. It is a pure function with no I/O, no state, and no external dependencies. The Rust type system makes invalid metric combinations unrepresentable. This eliminates an entire class of scoring bugs.

## Consequences

- Contributors to L1, L5, L6 need Rust knowledge.
- The subprocess invocation pattern means the Rust components cannot share in-memory state with the Go components. This is a feature, not a limitation — it enforces a clean boundary.
- JSON serialisation between the parser and Go adds a small overhead (~1–2ms for a 100-endpoint spec). This is negligible relative to scan duration.
- Adding new input formats (e.g. AsyncAPI, gRPC protobuf) requires only a new parser module in the Rust binary — the Go layer is unaffected as long as the IR contract is unchanged.
