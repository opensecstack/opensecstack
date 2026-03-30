# APIGuard Changelog

All notable changes to APIGuard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- JWT secret rotation support (`auth.previous_jwt_secret`) for zero-downtime key rotation
- Refresh token revocation: `GET /auth/refresh` (list) and `DELETE /auth/refresh` (revoke all)
- Token type validation — enforced `typ: "access"` claim to prevent token confusion attacks
- Atomic rate limiting via Redis Lua sliding-window script with in-memory fallback
- Trusted proxy support for correct client IP resolution behind load balancers
- CITADEL webhook integration — HMAC-SHA256 signed audit events, 3-attempt exponential backoff
- SHA-256 API key hashing with constant-time comparison (`hmac.Equal`)
- Audit log for all API key lifecycle events
- `revoked_refresh_tokens` database table
- `api_keys` table with hashed keys, scopes, and metadata

### Changed
- Rate limiter upgraded from simple in-memory counter to atomic Redis Lua script
- CORS now defaults to deny-all in production; origins must be explicitly allowlisted
- API key subject claims now embed SHA-256 hash for identity traceability

### Fixed
- Sequence handling in PostgreSQL migrations
- Audit log query ordering

---

## [0.1.0] - 2025-Q1

### Added
- **OpenAPI 3.x parser** (Rust) — safe deserialization with billion-laughs mitigation (128-depth limit, 10MB max, 10k alias limit)
- **Swagger 2.0 parser** (Rust) — full parameter and definition resolution
- **GraphQL schema parser** (Rust) — type and field extraction
- **OWASP API Top 10 test modules** (A1–A10):
  - A1: Broken Object Level Authorization (BOLA)
  - A2: Broken Authentication
  - A3: Mass Assignment
  - A4: Rate Limiting
  - A5: Function-Level Authorization
  - A6: Sensitive Business Flows
  - A7: Server-Side Request Forgery (SSRF)
  - A8: Security Misconfiguration
  - A9: Improper Inventory Management
  - A10: Unsafe Consumption of APIs
- **CVSS 3.1 scoring** (Rust) — deterministic, full formula implementation
- **Report formats**: HTML, PDF, JSON, SARIF
- **SARIF output** — integrates with GitHub Security tab and code scanning
- **Custom rules** — YAML/TOML rule definitions with module system
- **CLI binary** — `apiguard scan`, `apiguard report`, `apiguard version`
- **REST API** (~20 endpoints): auth, scans, findings, API keys, audit log, health
- **JWT authentication** with HMAC-SHA256, configurable TTL
- **Redis-based rate limiting** with per-IP sliding window
- **Structured logging** with zerolog (JSON output)
- **PostgreSQL persistence** — scan history, findings, audit trail
- **Multi-stage Docker build** (Rust → Go → Alpine, ~50MB final image)
- **Docker Compose** for development, testing, and production
- **GitHub Actions CI** — lint (golangci-lint, cargo clippy), unit tests, integration tests, Docker build
- **React dashboard** — scan management, findings triage, API key management
- **opensecstack Go SDK** — typed APIGuard client with zero external HTTP dependencies
- **opensecstack Python SDK** — typed APIGuard client with thread-safe token caching
- Non-root runtime user in production container (`apiguard:apiguard`)
- Health endpoint `/health` and version endpoint `/version`
- `.env.example` with 43 documented configuration variables

### Security
- Rust used for all untrusted-input processing (schema parsing, response analysis, CVSS)
- YAML alias depth and count limits prevent billion-laughs and quadratic-expansion attacks
- CORS default deny-all with explicit origin allowlisting
- Parameterized SQL queries throughout (pgx)
- SHA-256 hashing for all stored API keys
- Security headers middleware (HSTS, X-Frame-Options, X-Content-Type-Options, etc.)
