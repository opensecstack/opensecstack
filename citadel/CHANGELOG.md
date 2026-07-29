# CITADEL Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Gate 2 (AuthZ) rewrite — optional Permify-snapshot soft-check.**
  `gate2AuthZ` (`internal/marshal/marshal.go`) now composes two checks
  via `combineChecks`: the existing `rbacMap` check (permanent,
  unconditionally enforced — unchanged and never weakened), and a new
  Permify-snapshot check (`enforce: cfg.EnforcePermifyAuthz`, default
  `false`) backed by a new `PermifySnapshot` interface. An
  unknown/unsynced role-action pair is always treated as PASS; a
  known-deny only `WARN`s until `EnforcePermifyAuthz` is explicitly
  enabled. See [ADR-007](./adrs/007-permify-gate2-snapshot.md).
- **`internal/permifysync` package** — a `time.Ticker`-driven goroutine
  that periodically refreshes a local `permify_role_action_snapshot`
  table from the same Permify instance/schema sinauth's `internal/authz`
  writes to, and exposes a fast in-memory `Snapshot.Allowed(role,
  actionType)` read used by Gate 2. No live per-request call to Permify.
- **Migration `005_permify_policy_snapshot.sql`** — creates
  `permify_role_action_snapshot` (`role`, `action_type`, `allowed`,
  `synced_at`).
- New config (`CitadelConfig`): `PermifyURL`
  (`CITADEL_CITADEL_PERMIFY_URL`, default `""`), `EnforcePermifyAuthz`
  (`CITADEL_CITADEL_ENFORCE_PERMIFY_AUTHZ`, default `false`),
  `PermifySyncInterval` (`CITADEL_CITADEL_PERMIFY_SYNC_INTERVAL`,
  default `5m`).
- **ADR-007** — Permify-derived Gate 2 snapshot check.

## [1.0.0] — 2026-04-08

### Added
- **MARSHAL Decision Engine** — 5-gate cryptographic governance engine enforcing Zero-Trust authorization on every privileged operation
- **WORM Hash Chain** — append-only audit log with SHA-256 chain hashing, resistant to retrospective falsification
- **TripleHash Model** — composite 128-byte digest combining SHA-256, SHA-512, and BLAKE3 for defense-in-depth against algorithmic compromise
- **NDS Protocol** — dual-signature Separation of Duties enforcement on privileged actions
- **REST API** with endpoints:
  - `GET /api/v1/health` — server health with version info and database connectivity
  - `POST /api/v1/marshal/evaluate` — submit actions for MARSHAL 5-gate evaluation
  - `POST /api/v1/worm/emit` — append cryptographically signed entries to the WORM chain
  - `GET /api/v1/worm/verify` — verify integrity of the WORM chain
- **Version tracking** — build-time injection of version, git commit, and build date via ldflags
- **Structured logging** — zerolog-based JSON logging with service and component context
- **Graceful shutdown** — SIGINT/SIGTERM handling with 30-second connection draining
- **Security headers** — X-Content-Type-Options, X-Frame-Options, Content-Security-Policy on all responses
- **PostgreSQL persistence** — connection pooling, session management, WORM storage
- **Database migrations** — initial schema for WORM chain and MARSHAL state
- **Benchmarks** — performance baselines for MARSHAL evaluation, WORM chain operations, and PostgreSQL append
- **Docker support** — multi-stage build with non-root user, build-arg version injection
- **Configuration** — environment-based configuration with insecure settings warnings

### Performance (Intel Core i7-7600U, Go 1.24.4)
- TripleHash computation: 1.52 µs/event (100-byte payload)
- WORM chain step: 427 ns with zero allocations
- Synchronous WORM append (PostgreSQL 16): 4.22 ms
- MARSHAL 5-gate evaluation: 7.55 µs mean (in-memory mock store)
- Chain verification (1,000 entries): 10.19 ms
