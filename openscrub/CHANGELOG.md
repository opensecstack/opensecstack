# Changelog

All notable changes to OpenScrub are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **CITADEL WORM emission was silently broken.** `internal/citadel/client.go`
  was posting to `/api/v1/evidence` (and, before that, `/api/v1/events`) —
  neither route ever existed on CITADEL, so every `openscrub.mitigation`
  and `openscrub.rule_change` event failed silently and nothing reached
  the audit trail. The client now posts to CITADEL's real WORM ingest
  endpoint, `POST /api/v1/worm/emit`. Added `Config.ProjectID` /
  `OPENSCRUB_CITADEL_PROJECT_ID` (default `openscrub`), sent as the
  `project_id` field on every emit.

### Added

- **CITADEL MARSHAL governance on manual mitigation-rule creation.**
  `POST /api/v1/rules` (`Rules.Create` in `internal/api/handlers/handlers.go`)
  now builds a real Kerkese from the authenticated operator's identity
  and token and submits it to `POST /api/v1/marshal/evaluate`, blocking
  the request with `403 citadel_refused` on a `REFUSE` / `HARD_STOP`
  decision. This applies **only** to manual/API-driven rule creation —
  the automated ThreatFlow-IOC puller path (`internal/ioc/puller.go`)
  calls the rules service directly, bypassing this handler and the gate
  entirely, by design (automated threat response shouldn't wait on
  human approval). The gate is applied unconditionally in the handler,
  not based on a client-supplied `source` field, so it cannot be
  spoofed by an operator claiming `source: "threatflow"`; a regression
  test covers this. Rule withdrawal (`DELETE`) remains audit-only /
  ungated — it's reversible and already RBAC-authorized. See
  [docs/citadel-integration.md § Governance](docs/citadel-integration.md#governance-manual-rule-creation).
- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

## [1.0.0] — 2026-05-09

Phase 2 v1.0.0. Feature complete.

### Added

- **XDP/eBPF data plane** (kernel 5.15+): LPM-trie blocklist map,
  per-source rate-limit map, SYN-cookie XDP path, `XDP_DROP` /
  `XDP_PASS` decisions at NIC ingress, no userspace copy on the drop
  path. PERCPU stats counters expose `packets_passed`,
  `packets_dropped`, `packets_ratelimited`, `packets_malformed`, and
  `syn_cookies_sent`.
- **Rust + Aya loader** (`rust/dataplane/`): pins maps to
  `/sys/fs/bpf/openscrub/`, owns the lifecycle of the kernel program,
  and exposes a line-delimited JSON RPC server on
  `/run/openscrub/dataplane.sock` (see `rust/dataplane/src/ipc.rs` for
  the wire protocol — kept in lockstep with
  `internal/dataplane/uds.go`).
- **Go HTTP API on `:8087`** (`chi` router, `pgx` for Postgres,
  `zerolog`, `viper`, Prometheus metrics). Endpoints, every one of which
  is grounded in `api/openapi.yaml` and `internal/api/`:
  `POST /api/v1/auth/login`, `GET /api/v1/health`,
  `GET /api/v1/metrics` (Prometheus exposition),
  `GET /api/v1/metrics/snapshot` (JSON dashboard view),
  `GET|POST|DELETE /api/v1/rules`, `GET /api/v1/mitigations`.
- **`/api/v1/metrics/snapshot` JSON endpoint** — point-in-time view
  consumed by the dashboard overview page; counters are monotonic
  since process start so the frontend derives rates client-side.
  Now populates `syn_cookies_sent` (was previously decoded as 0).
- **PostgreSQL 16 schema** (`migrations/`): `rules`,
  `ioc_ingest_log`, `mitigations`. Migrations live in the top-level
  `migrations/` directory, applied by the loader on boot.
- **Migration 0002** — drops the `ON DELETE CASCADE` on
  `mitigations.rule_id`, re-adds it as `ON DELETE SET NULL` so a rule
  delete or TTL sweep can no longer destroy in-flight CITADEL evidence.
  Adds rule-snapshot columns (`rule_cidr`, `rule_type`, `rule_source`)
  captured at insert time and a `(pending|sent|failed)` state machine
  with retry bookkeeping.
- **Migration 0003** — adds `start_packets_dropped` /
  `start_bytes_dropped` columns on `mitigations`. The new
  rules-side `MitigationLifecycle` (see below) records the global
  drop counters at rule-create time so finalize can write a
  best-effort `(end - start)` delta as the per-window counter.
- **Mitigation lifecycle** (`internal/rules/mitigation_lifecycle.go`):
  inserts a `mitigations` row when a rule is created (and on startup
  for any active rule that has no open row), finalizes it on rule
  delete or TTL expiry. Closes a v1.0.0-blocking gap where migration
  0002's snapshot/state-machine columns existed but no caller wrote
  rows, leaving the CITADEL watcher idle. Per-rule counters remain a
  best-effort attribution in v1.0.0; per-rule PERCPU_HASH lands in
  v1.1 (migration 0004).
- **CITADEL evidence emitter + watcher** (`internal/citadel/`):
  every `rule_change` is async-emitted inline; mitigation rows are
  scanned by the watcher (`mitigation_watcher.go`) and emitted as
  `openscrub.mitigation` events (HMAC-SHA256 signed, ±5-minute replay
  window). The watcher only marks a row `sent` after a confirmed
  CITADEL 2xx; transient failures keep the row `pending` and bump
  `attempts`.
- **ThreatFlow IOC puller** (`internal/ioc/`): pulls malicious-IP
  IOCs every 15 min (configurable), reconciles into the BPF
  blocklist map via the rules service, and writes one
  `ioc_ingest_log` row per cycle.
- **OpenAPI 3.1 contract** at `api/openapi.yaml` (1.0.0-rc.1).
- **React + Vite + TypeScript dashboard** (`web/`): JWT login,
  rules list / add, mitigations list, metrics overview. i18n
  shqip + anglisht.
- **docker-compose** (`deploy/docker-compose.yml`): `openscrub-api`,
  `openscrub-dataplane`, `postgres`, `prometheus`. The dataplane runs
  with an explicit minimum cap set (`CAP_BPF`, `CAP_NET_ADMIN`,
  `CAP_SYS_RESOURCE`) — **not** `privileged: true` — and joins host
  networking via `network_mode: host`.
- **Helm chart** at `deploy/helm/openscrub/`.
- **Documentation set** under `docs/`.
- **Integration tests** at `tests/integration/`.

### Changed

- **Stats DTO** (`internal/dataplane/client.go`) now carries
  `SynCookiesSent` and the JSON decode no longer silently drops the
  field. Source of truth is `rust/dataplane/src/stats.rs`; the Rust
  IPC server's `stats` op now serialises it on the wire and the Go
  side surfaces it through `/api/v1/metrics/snapshot`.

### Security

- **Kernel attack surface** is the highest-tier disclosure class —
  XDP map injection, rule poisoning, loader privilege escalation, and
  IOC source compromise are enumerated in
  [docs/security/threat-model.md](docs/security/threat-model.md).
- Loader uses `CAP_BPF` + `CAP_NET_ADMIN` only. No `CAP_SYS_ADMIN`
  required on kernel ≥5.8; no `privileged: true`.
- All API endpoints behind JWT auth except `/api/v1/health` and
  `/api/v1/auth/login`. `/api/v1/metrics` is JWT-gated — counters
  reveal operational state, so Prometheus scrapers must present a
  long-lived "readonly" Bearer token (see
  [deploy/prometheus.yml](deploy/prometheus.yml)).

## [0.1.0] — 2026-Q1 (preview)

Internal preview — not published.

- XDP loader + Go API skeleton.
- Static-CIDR rules only, no IOC pull, no dashboard.

[1.0.0]: https://github.com/opensecstack/opensecstack/releases/tag/openscrub-v1.0.0
[0.1.0]: https://github.com/opensecstack/opensecstack/releases/tag/openscrub-v0.1.0
