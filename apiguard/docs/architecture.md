# APIGuard Architecture Overview

## System Overview

APIGuard is a layered pipeline. Each layer has a single responsibility, a defined input contract, and a defined output contract. No layer knows the internals of another. This makes each layer independently testable and replaceable.

| Layer | Language | Input | Output | Responsibility |
|-------|----------|-------|--------|----------------|
| L1 Schema Parser | Rust (serde) | OpenAPI 3.x / Swagger 2.x / GraphQL | Normalised APIGuard IR | Parse schema safely. Handle malformed input without panic. Extract endpoints, methods, params, auth, responses. |
| L2 Test Generator | Rust + Go | APIGuard IR | Test case specification set (JSON) | Generate test cases for each endpoint x OWASP module. Rust ensures type-safe generation. Go consumes. |
| L3 OWASP Modules | Rust + Go | Test case spec + target URL + auth config | Raw test results per module | One module per OWASP API Top 10 item. Rust: payload generation + response analysis. Go: HTTP execution. |
| L4 Auth Handler | Go | Auth config (JWT/OAuth2/API key/session) | Auth headers/cookies for test execution | Manage token lifecycle, refresh, multi-step auth flows. Stateful across test execution. |
| L5 Response Analyser | Rust | HTTP response (status, headers, body, timing) | Vulnerability findings with evidence | Pattern matching, timing analysis, response comparison. Fast regex via Rust regex crate. |
| L6 CVSS Scorer | Rust | Vulnerability findings | CVSS 3.1 scores per finding | Implements CVSS 3.1 formula exactly. Deterministic. No interpretation — pure calculation. |
| L7 Report Generator | Python + Go | All findings with CVSS scores | HTML / PDF / JSON / SARIF | Python Jinja2 for HTML/PDF. Go for JSON/SARIF machine output. CI/CD consumes SARIF. |
| L8 Persistence | PostgreSQL | Scan runs + findings | Scan history + trend data | Store all scan results. Enable regression detection. Feed dashboard. |
| L9 Dashboard | React + PostgreSQL | Scan history queries | Interactive UI | Scan history, finding trends, regression alerts, team management, API inventory. |
| L10 CLI | Go | User command + flags | Exit code + report output | GitHub Actions, GitLab CI, Jenkins, local use. Binary distributed via GitHub Releases. |

## Data Flow Diagram

```
OpenAPI Spec / Swagger / GraphQL
          │
          ▼
  ┌──────────────┐
  │  L1: Parser  │  ← Rust/serde — safe, typed, no panics
  │  (Rust)      │
  └──────┬───────┘
         │ APIGuard IR
         ▼
  ┌──────────────┐
  │ L2: TestGen  │  ← Generate test cases per endpoint × module
  │ (Rust + Go)  │
  └──────┬───────┘
         │ Test case specs
         ▼
  ┌──────────────────────────────────────┐
  │  L3: OWASP Modules (concurrent)      │
  │  A1:BOLA  A2:Auth  A3:Mass  ...A10   │  ← Go HTTP execution
  └──────────────────┬───────────────────┘     Rust analysis
                     │ Raw results
         ┌───────────┴──────────┐
         │                      │
         ▼                      ▼
  ┌─────────────┐      ┌─────────────────┐
  │ L5: Analyser│      │  L4: Auth Mgr   │
  │ (Rust)      │      │  (Go)           │
  └──────┬──────┘      └─────────────────┘
         │ Findings
         ▼
  ┌──────────────┐
  │ L6: CVSS     │  ← Rust — deterministic CVSS 3.1
  └──────┬───────┘
         │ Scored findings
         ▼
  ┌──────────────────────────────┐
  │  L7: Report Generator        │
  │  HTML/PDF (Python+Jinja2)    │
  │  JSON/SARIF (Go)             │
  └──────────────────────────────┘
```

## Component Boundaries and Trust Model

| Boundary | Trust Rule | Enforcement |
|----------|-----------|-------------|
| CLI → Core | CLI is untrusted input. All paths are sanitised before schema parsing. | Rust parser validates before any processing |
| Schema Parser → TestGen | Parser output is typed IR. TestGen cannot receive raw file bytes. | Rust type system — no raw strings cross this boundary |
| OWASP Modules → Target API | Modules only send requests to the configured target URL. No other network access. | Go HTTP client uses per-scan transport with allowlist |
| Report Generator → Filesystem | Reports write only to the configured output directory. | Go path.Clean + chroot-equivalent check |
| Dashboard → Database | Dashboard reads scan history only. Cannot modify scan results. | PostgreSQL row-level security — dashboard user is SELECT-only |
| CITADEL Connector → CITADEL | APIGuard emits events to CITADEL. CITADEL cannot write back to APIGuard scan results. | One-way webhook. No inbound API from CITADEL to scan data. |

## Why Rust + Go?

**Rust** handles everything that touches untrusted input or requires high throughput:
- Schema parser receives untrusted files from any source — memory safety eliminates buffer overflow vulnerabilities
- Response analyser runs regex matching against untrusted API responses at high throughput
- CVSS calculator must be deterministic and correct — Rust's type system enforces this

**Go** handles everything that requires concurrency and HTTP:
- Goroutines naturally handle concurrent module execution (10 OWASP modules running in parallel)
- `net/http` and the ecosystem (chi, zerolog) are mature
- Single binary deployment simplifies CI/CD integration

See [ADR-001](../../adrs/ADR-001-rust-for-parsing.md) and [ADR-002](../../adrs/ADR-002-go-for-http-and-orchestration.md) for the full decision records.
