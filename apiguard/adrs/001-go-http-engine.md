# ADR-001: Use Go for HTTP Orchestration and API Server

## Status

Accepted

## Context

APIGuard requires concurrent HTTP execution for the 10 OWASP modules, a REST API server for the dashboard and integrations, a CLI binary distributed to developers and CI/CD pipelines, and database access for scan persistence.

These requirements demand a language with a mature HTTP ecosystem, first-class concurrency primitives, and a straightforward path to single-binary distribution.

## Decision

Use Go for the following APIGuard layers:

- **L2 (TestGen)** — generates test case specifications from the APIGuard IR
- **L3 (OWASP Modules)** — HTTP execution for all 10 OWASP modules (concurrent via goroutines)
- **L4 (Auth Handler)** — manages JWT/OAuth2/API key lifecycles across scan execution
- **L7 (Report Generator)** — JSON and SARIF output generation
- **L8 (Persistence)** — PostgreSQL access via pgx + sqlx, migrations via golang-migrate
- **L9 (API Server)** — REST API with chi router, zerolog structured logging
- **L10 (CLI)** — single binary, distributed via GitHub Releases

## Rationale

- **Goroutines** provide lightweight concurrency for running 10 OWASP modules in parallel against the target API without the overhead of OS threads. A scan with 100 endpoints running 10 modules launches up to 1,000 goroutines — Go handles this without configuration.
- **Single binary** deployment simplifies CI/CD integration dramatically. Users download one binary, no runtime required.
- **net/http** and the Go HTTP ecosystem (chi, zerolog, pgx) are battle-tested, have known security properties, and receive regular updates.
- **Interface-based design** makes the module system clean — each OWASP module implements the `Module` interface and is registered at startup.
- **Standard tooling** (`go build`, `go test`, `go mod`) is stable and well-documented.

## Alternatives Considered

- **Node.js/TypeScript**: Mature HTTP ecosystem, but not appropriate for a security tool — npm supply chain risk, async model less readable for concurrent scan orchestration, single-binary distribution requires additional tooling (pkg, nexe).
- **Python**: Widely used for security tools, but the GIL limits true parallelism for CPU-bound work, and distribution as a binary (PyInstaller) is fragile. Python handles the report generation layer (L7 HTML/PDF) where these concerns are absent.
- **Java/Kotlin**: Strong concurrency model (virtual threads in Java 21+), but JVM startup time adds latency to CLI invocations, and fat-JAR distribution is substantially heavier than a Go binary.
- **Rust**: Chosen for the parser, analyser, and CVSS layers. Not used here because the HTTP orchestration and API server layers benefit more from Go's faster iteration speed and concurrency model than from Rust's ownership system.

## Consequences

- Contributors to L2, L3, L4, L7, L8, L9, L10 need Go knowledge.
- The build pipeline requires the Go toolchain (in addition to Rust for L1/L5/L6).
- An FFI/subprocess boundary between Rust and Go components exists at L1→L2 (parser subprocess) and L3→L5 (analyser subprocess). This adds complexity to local development and debugging.
- The module interface must be kept stable once external plugins are supported. See [RFC-0001](../rfcs/0001-plugin-architecture.md).
