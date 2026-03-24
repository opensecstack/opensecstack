# ADR-002: Use Go for HTTP Execution and Service Orchestration

## Status

Accepted

## Context

APIGuard needs to send concurrent HTTP requests to target APIs (10 OWASP modules running in parallel), serve a REST API, and produce a single binary for CI/CD integration. The orchestration layer must coordinate authentication, test execution, report generation, persistence, and command-line interaction.

These requirements demand a language with strong concurrency primitives, a mature HTTP ecosystem, and straightforward deployment characteristics.

## Decision

Use Go for the following APIGuard layers:

- **L2 (Test Generator, partial)** -- Consumes Rust-generated test case specifications and coordinates test execution.
- **L3 (OWASP Module HTTP execution)** -- Sends concurrent HTTP requests to target APIs across all 10 OWASP API Top 10 modules.
- **L4 (Auth Handler)** -- Manages token lifecycle, refresh flows, and multi-step authentication (JWT, OAuth2, API key, session).
- **L7 (Report Generator, JSON/SARIF)** -- Produces machine-readable JSON and SARIF output for CI/CD consumption.
- **L8 (Persistence layer)** -- Stores scan results and findings in PostgreSQL for history and regression detection.
- **L10 (CLI)** -- Provides the command-line interface distributed as a single binary via GitHub Releases.

## Rationale

- **Goroutines** naturally handle concurrent module execution. Running 10 OWASP modules in parallel against a target API maps directly to Go's concurrency model with minimal boilerplate.
- **net/http and ecosystem** (chi for routing, zerolog for structured logging) are mature, well-tested, and widely deployed in production systems.
- **Single binary deployment** simplifies CI/CD integration. There are no runtime dependencies to install -- the binary runs on GitHub Actions, GitLab CI, Jenkins, and local machines without additional setup.
- **Strong CLI ecosystem** (cobra for command structure, viper for configuration) provides a professional command-line experience with minimal custom code.
- **Excellent PostgreSQL drivers** (pgx) provide high-performance, type-safe database access for scan persistence and trend analysis.

## Alternatives Considered

- **Rust**: Capable of HTTP execution but the ecosystem for web services is less mature than Go's. Longer compile times would slow the development cycle for the orchestration layer, where iteration speed matters more than memory safety.
- **Node.js**: Good HTTP ecosystem but the single-threaded event loop model is less suited for coordinating CPU-bound analysis alongside concurrent HTTP execution.
- **Python**: Too slow for concurrent HTTP execution at the scale required. Deployment complexity (virtualenvs, dependency management) conflicts with the single-binary distribution goal.

## Consequences

- The two-language codebase requires developers comfortable with both Go and Rust, or at minimum an understanding of the boundary between them.
- Inter-process communication between Go and Rust components adds latency at layer boundaries. This is acceptable because the dominant latency is network round-trips to the target API, not internal IPC.
- Go's type system is simpler than Rust's. Some invariants that Rust enforces at compile time must be enforced by convention and testing in the Go layers.
- In return, the orchestration, HTTP, and CLI layers benefit from Go's fast compilation, straightforward concurrency, and zero-dependency deployment model.
