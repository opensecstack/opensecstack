# APIGuard Changelog

All notable changes to APIGuard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE).
- Access-token denylist with a `POST /api/v1/auth/logout` endpoint for immediate token invalidation on sign-out.
- `sinauth.ts` client and `AuthCallback` page added to the web dashboard for popup-based SSO login.

- `citadel.require_approval` config flag (default `false`) — gates a real two-person approval flow for scan initiation.
- `POST /api/v1/scans/{id}/approve`, `POST /api/v1/scans/{id}/reject`, `GET /api/v1/scans/{id}/approval` endpoints for two-person Separation-of-Duties sign-off on pending scans.
- `scan_approvals` table (migration `008_create_scan_approvals`) and `pending_approval` scan status.

### Changed

- Backend auth handler now forwards authentication events to the CITADEL WORM audit chain.
- Scan creation now derives the real authenticated user's identity and sinauth bearer token and forwards them to CITADEL as the Kerkese `Actor`/`ActorToken`, replacing a previous bug where scan creation submitted a hardcoded `UserID: 0` placeholder.

### Fixed

- Scan creation no longer submits a hardcoded `UserID: 0` to CITADEL MARSHAL — the real authenticated caller's sinauth identity is used instead.

---

## [1.0.0] - 2026-05-10

### Added
- JWT secret rotation support (`auth.previous_jwt_secret`) for zero-downtime key rotation
- `POST /api/v1/admin/auth/secrets/rotate` — live secret rotation without server restart
- Refresh token revocation: `GET /auth/refresh` (list) and `DELETE /auth/refresh` (revoke all)
- Token type validation — enforced `typ: "access"` claim to prevent token confusion attacks
- Atomic rate limiting via Redis Lua sliding-window script with in-memory fallback
- Trusted proxy support for correct client IP resolution behind load balancers (`APIGUARD_RATELIMIT_TRUSTED_PROXIES`)
- CITADEL webhook integration — HMAC-SHA256 signed audit events, 3-attempt exponential backoff
- SHA-256 API key hashing with constant-time comparison (`hmac.Equal`)
- Audit log for full API key lifecycle: `api_key_created`, `api_key_used`, `api_key_revoked`
- Audit events for auth lifecycle: `user_login`, `user_logout`, `jwt_secret_rotated`
- `revoked_refresh_tokens` database table
- `api_keys` table with hashed keys, scopes, and metadata
- `cmd/apiguard` binary — `server`, `scan`, `report`, `rule validate`, `rule test`, `version` commands
- `cmd/migrate` — standalone migration runner (`up` / `down`) with `schema_migrations` tracking
- CITADEL `hard_stop` webhook handler — cancels in-flight scans and initiates graceful shutdown

### Changed
- Rate limiter upgraded from simple in-memory counter to atomic Redis Lua script with graceful fallback
- All 6 rate limiters now respect trusted proxy CIDRs for correct per-client-IP accounting
- CORS now defaults to deny-all in production; origins must be explicitly allowlisted
- API key subject claims embed SHA-256 hash for identity traceability and revocation checking

### Fixed
- Sequence handling in PostgreSQL migrations
- Audit log query ordering
- Stale "Planned" notice removed from API Inventory documentation (endpoints are implemented)

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
