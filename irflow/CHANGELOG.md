# IRFlow Changelog

All notable changes to this project will be documented in this file.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC).
- `auth.Config.Pepper` + `auth.NewHasher(cfg)` — thin wrapper around `github.com/opensecstack/sdk/password` for Argon2id API-key hashing. New config key `IRFLOW_AUTH_PEPPER` (≥ 16 bytes). Empty pepper at startup logs a warning; future features that need hashing (API keys, SSO token binding) call `auth.NewHasher` at their own init time and surface typed errors there

## [1.0.0] — 2026-04-08

First production release of IRFlow. The engine now covers the full incident
lifecycle with enforced governance, webhook ingestion, playbook automation,
JWT-based API access, Prometheus observability, and a real integration test
suite.

### Added

**Platform basics (Phase 1)**
- `serve` command wires config → `pgxpool.Pool` → `PGStore`/`PGPlaybookStore` → `incident.Service`/`playbook.Service` → `api.Server`
- `migrate` command applies `migrations/*.sql` inside transactions and records applied versions in `schema_migrations`
- `GET /api/v1/stats` returns real aggregation by severity / status / source
- `GET /api/v1/health` returns liveness; `GET /api/v1/health/detail` includes DB ping + version/commit/built metadata
- Version tracking (`Version`, `GitCommit`, `BuildDate`) injected via ldflags

**Playbook subsystem (Phase 2)**
- `playbooks` and `playbook_executions` tables (migration `002_playbooks.sql`) with JSONB `trigger`, `steps`, and `step_results`
- `POST/GET/PATCH/DELETE /api/v1/playbooks` + `POST /api/v1/playbooks/{id}/execute`
- `GET /api/v1/playbooks/{id}/executions` and `GET /api/v1/executions/{id}` for inspection
- Executor performs graph traversal via `OnSuccess`/`OnFailure`, honours per-step timeouts, protects against cycles (≤ 100 steps per run), and dispatches step types (`action`, `notify`, `wait`, `enrich`, `scan`, `conditional`) with a clean contract for Phase 4 client injection
- Playbook executions are async — `/execute` returns `202 Accepted` and the executor runs in a detached goroutine with a 1-hour deadline

**Webhook ingestion (Phase 3)**
- `POST /api/v1/webhooks/apiguard` — `critical` severity → P1 incident, `high` → P2, lower ack'd without creating
- `POST /api/v1/webhooks/citadel` — `HARD_STOP` → P1 incident, other events ack'd
- `POST /api/v1/webhooks/threatflow` — attaches IOCs to a named incident; bundle without `incident_id` is queued (202) for future correlation
- HMAC-SHA256 signature verification with 5-minute clock skew window (`X-Irflow-Signature`, `X-Irflow-Timestamp`) and per-source secret resolution
- Configurable `MaxBodySize` (default 1 MiB) and `ClockSkewTolerance`; empty secret → 503 (fail-closed)

**Governance integration (Phase 4)**
- `internal/governance.CitadelClient` — MARSHAL `Evaluate` and WORM `Emit`, HMAC-signed via `X-Citadel-Signature`
- `internal/governance.NIS2Client` — `/auth/token` exchange with cached JWT (refresh 60s before expiry), `PATCH` to `/assessments/{id}/controls/{ref}` on Article 21(2)(b) Incident Handling
- Incident `Service` accepts optional clients via functional options (`WithMarshal`, `WithWORM`, `WithNIS2`, `WithLogger`, `WithMetrics`)
- `SubmitAction` calls MARSHAL first; `REFUSE`/`HARD_STOP` outcomes return typed sentinel errors (HTTP 403) and prevent local persistence
- `Create` emits a WORM anchor synchronously (failure logs but never blocks) and kicks off NIS2 notification in a goroutine so Compass latency never impacts HTTP response

**Auth + RBAC (Phase 5)**
- Hand-rolled HS256 JWT (`internal/auth`) — `Issue`, `Verify`, claim validation with `exp`/`nbf` checks, rejects `alg: none`
- Canonical roles: `admin`, `operator`, `verifier`, `viewer`, `service`
- Chi middleware: `Middleware` (token → claims in context), `RequireWrite`, `RequireDelete`, `RequireRole`
- `AuditLog` middleware records every request (`request_id`, `user_id`, `role`, `method`, `path`, `status`, `duration`, `remote`) — positioned before auth so rejections also appear
- Zero-value safety: missing secret auto-enables dev mode with a loud `Warn` log (prevents silent fail-open behind a mis-spelled env var)
- `irflow auth issue --user … --role … --ttl …` CLI for local dev tokens

**Observability (Phase 6)**
- `internal/metrics` Prometheus-backed catalog: HTTP (requests_total, request_duration_seconds, requests_in_flight), incidents_created_total, actions_submitted_total, playbook_executions_total, playbook_steps_total, webhooks_received_total, governance_calls_total, db_pool_connections + Go/process runtime
- `GET /metrics` exposed publicly
- Per-route cardinality controlled via chi `RoutePattern` (not raw URL path)
- DB pool gauges refreshed every 15 s from `pool.Stat()`
- All services accept an optional `*metrics.Metrics`; nil → no-op

**Integration testing (Phase 7)**
- Full HTTP E2E suite in `cmd/irflow` that boots the real stack behind `httptest.Server` against a live PostgreSQL
- `PGStore` / `PGPlaybookStore` integration tests covering CRUD, pagination + filters, JSONB round-trip, FK cascades, stats aggregation
- Migration runner integration test validates `schema_migrations` bookkeeping + table existence
- Harness skips cleanly when `IRFLOW_TEST_DB_URL` is unset — CI jobs without Docker keep passing
- `make compose-test-up` / `make test-integration` / `make compose-test-down` developer workflow
- All integration tests gated behind the `integration` build tag

**Release infrastructure (Phase 8)**
- `.env.example` enumerating every configuration variable
- `SECURITY.md` covering vulnerability reporting and the auth/webhook threat model
- `CONTRIBUTING.md` documenting dev workflow, coding conventions, and testing expectations
- `ROADMAP.md` outlining post-1.0 direction
- `docs/api.md` refreshed to match the v1.0.0 endpoint catalog

### Changed

- `api.NewServer` now takes a single `api.Options` struct so future phases can add dependencies without breaking callers
- `migrations/001_initial.sql` — ID columns changed from `UUID` to `VARCHAR(50)` to match the application-layer `inc-`/`act-`/`ioc-` format; fixed a silent-insert bug where app-generated IDs did not satisfy the UUID type
- Health endpoint JSON now includes `version`, `commit`, `built`, and `db` fields

### Security

- Webhook endpoints fail closed when a source's HMAC secret is missing (503, not 200)
- Auth middleware rejects `alg: none` tokens explicitly (`ErrUnsupportedAlg`)
- CITADEL/NIS2/webhook body sizes are bounded (`io.LimitReader`) to prevent DoS
- Timestamp replay window (±5 min) on all webhook signatures

### Performance

Benchmarks pending — ops baseline will land in the next point release alongside load-testing results.
