# Changelog

All notable changes to OpenCSIRT are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

## [1.0.0] — 2026-05-10

Phase 3 v1.0.0. Feature complete.

### Added

- **Go HTTP API on `:8088`** (`chi` router, `pgx` for Postgres,
  `zerolog` logging, Prometheus metrics). Endpoints grounded in
  [api/openapi.yaml](api/openapi.yaml) and `internal/api/`:
  `POST /api/v1/auth/login`, `GET /api/v1/health`,
  `GET|POST /api/v1/constituencies` and `/{id}`,
  `GET|POST /api/v1/incidents`, `GET /api/v1/incidents/{id}`,
  `POST /api/v1/incidents/{id}/close`,
  `GET|POST /api/v1/advisories` and `/{id}`,
  `POST /api/v1/advisories/{id}/publish`,
  `POST /api/v1/integrations/irflow/incident`,
  `GET /api/v1/metrics` (Prometheus exposition, JWT-gated),
  `GET /api/v1/metrics/snapshot` (JSON dashboard view).
- **Incident lifecycle** — `open → triaged → contained → closed` state
  machine in
  [`migrations/0001_init.up.sql`](migrations/0001_init.up.sql) and
  enforced in `internal/incident/`. Sources: `irflow`, `manual`,
  `abuse_mailbox`, `peer_csirt`. Severity: `low|medium|high|critical`.
  Incident opened and closed transitions emit CITADEL evidence events.
- **CSAF 2.0 advisory authoring** — `internal/advisory/` calls the
  Python subsystem at `OPENCSIRT_ADVISORY_SERVICE_URL` (default
  `http://localhost:8089`) for document generation and validation.
  States: `draft → published → withdrawn`. TLP enforced on read:
  `CLEAR`, `GREEN`, `AMBER`, `RED`. NoopClient fallback path when
  the subsystem is unreachable so incident triage stays unblocked.
- **Python advisory subsystem on `:8089`** — FastAPI service in
  [python/](python/), CSAF 2.0 schema validation, generation
  templates. Stateless; talks to nothing but the Go core.
- **PostgreSQL 16 schema** ([migrations/0001_init.up.sql](migrations/0001_init.up.sql)):
  `constituencies`, `incidents`, `advisories`, `peer_csirts`,
  `citadel_outbox`, `audit_log`. Migrations applied by the Go API on
  boot.
- **CITADEL outbox state machine** (`internal/citadel/`) — every
  state change writes a row; the watcher emits to CITADEL with HMAC-
  SHA256 signing (±5-minute replay window) and only marks rows `sent`
  on confirmed CITADEL 2xx. Event types declared in
  [`internal/citadel/events.go`](internal/citadel/events.go):
  `opencsirt.incident_opened`, `opencsirt.incident_closed`,
  `opencsirt.advisory_published`, `opencsirt.escalation_sent`. Key
  rotation supported via `OPENCSIRT_CITADEL_HMAC_SECRETS`
  (comma-separated) and `OPENCSIRT_CITADEL_KEY_ID`. Dry-run via
  `OPENCSIRT_CITADEL_DRY_RUN` (defaults to `true` in dev).
- **JWT auth with 6 roles** ([`internal/auth/auth.go`](internal/auth/auth.go)):
  `viewer < external_peer < analyst < operator < csirt_lead < admin`.
  HS256, sha256(pepper + password) credential hashing. Login
  returns `503 issuer_disabled` when `OPENCSIRT_USERS` is empty.
- **ThreatFlow IOC ingest** — periodic pull
  (`OPENCSIRT_THREATFLOW_INTERVAL`, default 60 s) of IOC bundles
  attached to incidents and merged into outbound advisories.
- **IRFlow incident webhook** — HMAC-SHA256 inbound at
  `/api/v1/integrations/irflow/incident`. Validates `OPENCSIRT_IRFLOW_WEBHOOK_SECRET`
  with a ±5-minute replay window; converts the IRFlow incident into
  an OpenCSIRT incident with `source = 'irflow'`.
- **NIS2 Compass notifier** — pushes Article 23 incident
  notifications to `OPENCSIRT_NIS2COMPASS_API_URL` when an incident
  has severity `high` or `critical`.
- **VertGuard CVE subscriber** — pulls vulnerability advisories from
  `OPENCSIRT_VERTGUARD_API_URL` and embeds them into outbound CSAF
  documents as `vulnerabilities[*].cve`.
- **Prometheus metrics** ([`internal/metrics/metrics.go`](internal/metrics/metrics.go)):
  `opencsirt_incidents_created_total{source,severity}`,
  `opencsirt_incidents_closed_total{severity}`,
  `opencsirt_advisories_published_total{tlp}`,
  `opencsirt_escalations_sent_total`,
  `opencsirt_citadel_events_total{outcome}`,
  `opencsirt_citadel_queue_depth`,
  `opencsirt_iocs_ingested_total{source}`.
- **JSON snapshot** at `/api/v1/metrics/snapshot` — point-in-time
  view consumed by the dashboard overview page.
- **React + Vite + TypeScript dashboard** on `:3088`
  ([web/](web/)) — JWT login, incidents board, advisory editor with
  TLP picker, peer roster, metrics overview.
- **docker-compose** ([deploy/](deploy/)) — `opencsirt-api`,
  `opencsirt-advisory`, `opencsirt-web`, `postgres`. Helm chart
  alongside.
- **Documentation set** under [docs/](docs/) — quick-start,
  configuration, deployment, architecture, api, integration guides
  (CITADEL, IRFlow, ThreatFlow, NIS2 Compass, VertGuard), peer-CSIRT
  handshake protocol, security threat model, operator handbook,
  troubleshooting, FAQ.

### Security

- **Incident-data confidentiality is the highest-tier disclosure
  class** — incident payloads, peer-CSIRT identifiers, TLP:RED
  advisories must never leak. Threat model in
  [docs/security/](docs/security/).
- All API endpoints behind JWT auth except `/api/v1/health` and
  `/api/v1/auth/login`. `/api/v1/metrics` is JWT-gated.
- All inter-platform webhooks (CITADEL, IRFlow) HMAC-SHA256 signed
  with ±5-minute replay window.

## [0.1.0] — 2026-Q1 (preview)

Internal preview — not published.

- Go API skeleton, constituency CRUD only.
- No advisory subsystem, no integrations, no dashboard.

[1.0.0]: https://github.com/opensecstack/opensecstack/releases/tag/opencsirt-v1.0.0
[0.1.0]: https://github.com/opensecstack/opensecstack/releases/tag/opencsirt-v0.1.0
