# ADR-001: Use Rust for Schema Parsing and Security Analysis

## Status

Accepted

## Context

APIGuard parses untrusted OpenAPI/Swagger/GraphQL schemas from external sources. The parser must handle malformed input without crashing. Response analysis runs regex matching against untrusted API responses at high throughput. CVSS scoring must be deterministic.

These requirements demand a language that provides memory safety without runtime overhead, predictable performance under load, and a type system strong enough to enforce correctness in security-critical calculations.

## Decision

Use Rust for the following APIGuard layers:

- **L1 (Schema Parser)** -- Parses untrusted schema files into the normalised APIGuard IR using serde for safe, typed deserialization.
- **L5 (Response Analyser)** -- Performs pattern matching and regex analysis against untrusted HTTP responses at high throughput.
- **L6 (CVSS Scorer)** -- Implements the CVSS 3.1 formula as a pure, deterministic calculation.

## Rationale

- **Memory safety** eliminates buffer overflow vulnerabilities when processing untrusted input. There is no need for manual memory management discipline; the compiler enforces safety at build time.
- **No garbage collector** provides predictable latency for high-throughput response analysis. There are no GC pauses during critical scanning operations.
- **Type system** enforces deterministic CVSS calculation. Invalid score combinations are unrepresentable.
- **serde** provides safe, typed deserialization of OpenAPI, Swagger, and GraphQL schemas. Malformed input produces typed errors, not undefined behaviour.
- **regex crate** is fast and safe. Its design prevents ReDoS by construction, which is critical when matching patterns against untrusted API response bodies.
- **Result types** force explicit error handling at every call site. The parser cannot panic on bad input because the compiler requires all error paths to be handled.

## Alternatives Considered

- **Go**: Good concurrency model but lacks the memory safety guarantees needed for untrusted input parsing. The garbage collector introduces unpredictable latency during high-throughput analysis.
- **C/C++**: Fast execution but memory safety requires manual discipline. A single mistake in the parser could introduce a security vulnerability in a security tool.
- **Python**: Too slow for high-throughput response analysis. The GIL limits true parallelism for CPU-bound regex matching.

## Consequences

- Developers contributing to L1, L5, or L6 need Rust knowledge, which narrows the contributor pool compared to more widely known languages.
- The FFI boundary between Rust and Go components adds complexity to the build and debugging process.
- The build pipeline requires the Rust toolchain in addition to the Go toolchain, increasing CI/CD setup requirements.
- In return, the security-critical parsing and analysis layers gain compile-time safety guarantees that eliminate entire classes of vulnerabilities.
