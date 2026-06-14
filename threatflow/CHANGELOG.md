# Changelog

All notable changes to ThreatFlow are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC).

## [1.0.0] — 2026-04-19

First production release. Every scaffold endpoint from v0.1.0 is now backed
by real persistence, governance, and ecosystem integration.

### Added — Data layer
- PostgreSQL schema with 10 tables: `feeds`, `iocs`, `ttp_tags`, `sightings`,
  `stix_bundles`, `stix_objects`, `ioc_correlations`, `webhook_subscribers`,
  `webhook_deliveries`, `api_keys`
- Migration runner embedded via `go:embed`; `threatflow migrate` CLI with
  `--rollback`, `--target`, `--status`, `--force` flags
- SHA-256 `pattern_hash` dedup on `iocs`; GIN indexes on tags + JSONB
- Full-text search index on `(value || description)` via `to_tsvector`
- Connection pool via pgx/v5 with configurable max open / idle limits

### Added — IOC lifecycle
- Real CRUD endpoints: `GET/POST /api/v1/iocs`, `GET /api/v1/iocs/{id}`
- Filters: `?type`, `?value`, `?tag`, `?min_confidence`, `?q` (FTS),
  `?limit`, `?offset`
- Upsert with dedup by `pattern_hash`; merges tags and keeps
  `max(confidence)` on repeat ingestion
- Soft-delete (revoke) endpoint; revoked rows excluded from `/match`

### Added — STIX 2.1
- Bundle parser + validator (`type`, `id` prefix, `spec_version`, per-object
  validation, `objects` array)
- Pattern parser extracts `(type, value)` from equality-form STIX patterns;
  MATCHES / LIKE / compound patterns are persisted as-is but skip IOC
  extraction
- Bundle importer writes `stix_bundles` (dedup by `bundle_hash`) +
  `stix_objects` (dedup by `stix_id`)
- Endpoints: `GET /api/v1/stix/bundles`, `POST /api/v1/stix/bundles`,
  `GET /api/v1/stix/bundles/{id}` (envelope + raw objects)
- Deterministic STIX IDs for bundles + indicators derived via SHA-256 so
  polling the same feed is idempotent

### Added — Feed polling
- `internal/feed/` package with a `Poller` interface
- TAXII 2.1 client — signed GET to collection objects endpoint, returns a
  STIX bundle for the importer
- CSV poller — auto-detects column layouts (abuse.ch urlhaus, AlienVault
  OTX, generic type/value pairs); strips `#` comment banners
- MISP JSON poller — parses `{"response": [events]}` or bare-array forms,
  filters to `to_ids=true` attributes, maps MISP types to STIX
- Scheduler — ticks every minute, polls feeds whose `last_poll_at + interval`
  has elapsed, records success/failure in `feeds.last_poll_count /
  error_count`
- Feed CRUD: `GET/POST /api/v1/feeds`, `GET/PATCH/DELETE /api/v1/feeds/{id}`

### Added — MITRE ATT&CK mapping
- `internal/attack/` package with 19 embedded techniques (initial access,
  execution, C2, exfil, impact, credential access, defense evasion)
- Rule-based auto-tagger — 16 rules mapping IOC type + tags to techniques
  (e.g. `[phishing]` → T1566+T1566.002, `[c2]` on domain → T1071.004)
- Feed-provided extraction — STIX `kill_chain_phases` + `external_references`
  with `source_name: mitre-attack`
- `TTPStore.UpsertMany` wraps a transaction so a bundle's mappings land
  atomically; on conflict `(ioc_id, technique_id)` the higher-confidence
  row wins, and `feed` > `auto` > existing on source precedence
- Endpoints: `GET /api/v1/techniques` (summary + catalogue),
  `GET /api/v1/iocs/{id}/techniques`

### Added — CITADEL governance + WORM
- `internal/citadel/` connector with HMAC-SHA256 signing
  (`X-CITADEL-KEY / -TS / -SIG`) — identical wire format to APIGuard +
  NIS2 Compass so one connector key serves all three
- MARSHAL gate on every mutation (`IOC_INGEST`, `STIX_BUNDLE_IMPORT`,
  `FEED_CREATE`, `FEED_TOGGLE`, `FEED_DELETE`); fail-open / fail-closed
  configurable via `THREATFLOW_CITADEL_FAIL_CLOSED`
- WORM emission — bounded async queue (64 in-flight), drop-on-saturation,
  graceful drain on shutdown
- Chain anchor verification — warns if `prev_hash` does not match the
  previous response's `chain_hash`
- No-op mode when `THREATFLOW_CITADEL_API_URL` is empty so dev environments
  run without the governance service

### Added — Correlation engine
- `internal/correlate/` with 5 rules, hooked into every IOC upsert:
  - `duplicate`        — same (type, value) across feeds (conf 90)
  - `resolves-to`      — URL host matches a known domain IOC (conf 80)
  - `subdomain-of`     — domain ends with a shorter registered domain (conf 85)
  - `same-network`     — two `ipv4-addr` in the same `/24` (conf 60)
  - `shares-cve`       — two IOCs carry the same CVE id (conf 75)
- Bidirectional `ForIOC` lookup annotates each match with direction
  (`inbound` / `outbound`) and counterparty metadata
- Endpoints: `GET /api/v1/iocs/{id}/correlations`, `GET /api/v1/correlations`

### Added — Ecosystem integration
- Outbound webhook dispatcher — HMAC-SHA256 signed payloads
  (`X-ThreatFlow-Signature`) with GitHub-style header format
- Per-subscriber filters — `event_types[]`, `min_confidence`, `enabled`
  toggle; enforced SQL-side via `MatchingSubscribers`
- Retry with exponential backoff (0.5s / 1s / 2s); every attempt logged to
  `webhook_deliveries` keyed on `(subscriber_id, event_id)` for idempotency
- Event types: `ioc.created`, `ioc.updated`, `ioc.revoked`,
  `bundle.imported`, `sighting.reported`
- Sighting ingestion — `POST /api/v1/sightings` accepts either `ioc_id` or
  `(type, value)`; emits `sighting.reported` to subscribers so IRFlow can
  trigger a playbook the moment APIGuard reports a hit
- Match endpoint — cheap `GET /api/v1/match?type=X&value=Y` for ecosystem
  services; cached in Redis for 10 minutes
- Webhook CRUD + delivery history + stats (admin-only)

### Added — Auth + caching + rate limit
- JWT HS256 tokens issued via `POST /api/v1/auth/token`; lifetime
  configurable via `THREATFLOW_AUTH_TTL_MINUTES` (default 60)
- API keys — SHA-256 hashed, `tf_<64-hex>` format, shown once at creation;
  `api_keys` table with role + expiry; bootstrap keys via env var for
  first-boot admin
- RBAC — `viewer` < `analyst` < `operator` < `admin`; reads need any role,
  mutations need operator, webhook + API key admin needs admin
- Redis-backed match cache with TTL + invalidation on upsert/revoke; no-op
  mode when `THREATFLOW_CACHE_REDIS_URL` is empty
- Per-IP token-bucket rate limiter (default 50 rps + 100 burst) with
  background GC of idle visitors

### Added — Testing
- `//go:build integration` tests for every store (pattern dedup, correlation
  bidirectional JOIN, TTP batch upsert, platform sighting counts)
- Full-stack E2E test exercising the paper flow end-to-end:
  JWT → STIX bundle → `/match` → sighting → HMAC-signed webhook delivery
- Edge-case tests for STIX parser (empty body, Unicode values, malformed
  IDs) and feed pollers (empty CSV, context cancellation, non-2xx)
- Make targets: `test`, `test-integration`, `test-e2e`, `test-all`,
  `test-cover`, `test-cover-integration`, `bench`

### Added — Observability
- zerolog structured JSON logging with component tags
  (`api`, `scheduler`, `citadel`, `webhook`, `correlate`, `cache`, ...)
- Request ID + real IP middleware via chi
- Delivery status counts on `/api/v1/webhooks/stats`
- Feed-level poll metrics in `last_poll_at`, `last_poll_count`, `error_count`
- Cache hit/miss counters exposed via `cache.Cache.Stats()`

### Known limitations
- TAXII 2.1 pagination (`more` / `next`) fetches only the first page
- Custom HTTP headers + per-feed API keys are in config but not stored on
  the `feeds` row — set via env if needed
- No "poll-now" trigger endpoint; scheduler minimum interval is 60 seconds
- `accuracy_ratio` column exists but is not updated by the correlation
  feedback loop (planned for 1.1)

## [0.1.0] — 2026-03-31

### Added
- Project scaffold: Cobra CLI, chi HTTP router, zerolog structured logging
- `threatflow serve` command — starts HTTP API on port 8091
- `threatflow version` command — prints version, commit, build date
- Health endpoint: `GET /api/v1/health`
- Version endpoint: `GET /api/v1/version`
- IOC endpoints (scaffold): `GET /api/v1/iocs`, `POST /api/v1/iocs`,
  `GET /api/v1/iocs/{id}`
- STIX bundle endpoints (scaffold): `GET /api/v1/stix/bundles`,
  `POST /api/v1/stix/bundles`
