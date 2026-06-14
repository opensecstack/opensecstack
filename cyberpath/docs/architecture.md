# CyberPath Architecture

> Status: scaffold. This document captures the design intent for
> v1.0.0 and v1.0.0. Concrete code references will land as the
> directories under `internal/`, `web/`, and `rust/` populate.

## High-level topology

```
                  ┌──────────────────────────────────┐
                  │   Learner (browser, shqip/en)    │
                  │   React + Vite frontend  :3006   │
                  │   • lesson runner                │
                  │   • quiz UI                      │
                  │   • xterm.js browser terminal    │
                  └─────────────┬────────────────────┘
                                │ HTTPS + WebSocket
                                ▼
                  ┌──────────────────────────────────┐
                  │      CyberPath API (Go)  :8086   │
                  │  ─────────────────────────────   │
                  │  chi router · pgx · zerolog ·    │
                  │  viper · prometheus              │
                  │                                  │
                  │  internal/path/    (Module 1)    │
                  │  internal/quiz/    (Module 2)    │
                  │  internal/lab/     (Module 3+4)  │
                  │  internal/cert/    (Module 5)    │
                  │  internal/citadel/ (Module 6)    │
                  │  internal/coverage/(Module 7)    │
                  │  internal/content/ (Module 8)    │
                  └──────┬─────────────┬─────────────┘
                         │             │
                         │             │  WebSocket relay
                         │             ▼
                         │      ┌──────────────────────┐
                         │      │  Lab runtime         │
                         │      │  ─────────────────── │
                         │      │  v1.0.0: Docker      │
                         │      │    (per-session      │
                         │      │     containers)      │
                         │      │  v1.0.0: wasmtime    │
                         │      │    (Rust host +      │
                         │      │     pre-built lab    │
                         │      │     images)          │
                         │      └──────────────────────┘
                         │
                         ▼
                  ┌──────────────────────────────────┐
                  │   PostgreSQL (per-platform)      │
                  │   ─────────────────────────────  │
                  │   users · paths · modules ·      │
                  │   lessons · quizzes · progress · │
                  │   completions · certifications · │
                  │   lab_sessions · content_versions│
                  └──────────────────────────────────┘

                  Outbound integrations (HMAC-SHA256 signed):

                  ┌────────────┐   cyberpath.completion (async, WORM)
                  │  CITADEL   │ ◄────────────────────────────────────
                  └────────────┘

                  ┌────────────┐   GET coverage / GET recommend
                  │ NIS2       │ ◄────────────────────────────────────
                  │ Compass    │       (Compass calls CyberPath)
                  └────────────┘

                  ┌────────────┐   incident → recommended track
                  │  IRFlow    │ ────────────────────────────────────►
                  └────────────┘       (CyberPath consumes IRFlow signals)
```

## Components

### Backend (Go)

Same stack as VertGuard and APIGuard for ecosystem consistency:

- **chi** — HTTP router, middleware
- **pgx** — PostgreSQL driver and connection pool
- **zerolog** — structured JSON logging
- **viper** — config (env vars + YAML)
- **prometheus/client_golang** — metrics, `/metrics` exposed on the
  API port (deliberately unauthenticated, matches ecosystem
  convention)
- **opensecstack/sdk** — auth + Argon2id password hashing
- **circuit breaker** — outbound integrations (CITADEL, NIS2
  Compass, IRFlow) wrapped with the same breaker pattern VertGuard
  uses

### Frontend (React + TypeScript + Vite)

- React 18+, TypeScript strict
- Vite for dev/build
- TanStack Query for API state
- xterm.js for the browser terminal (lab sessions)
- i18n: shqip (`sq`) + anglisht (`en`), source language is shqip,
  English is the maintained translation

### Wasm sandbox (v1.0.0+)

- **wasmtime** as the host runtime
- Pre-built lab images registered in `labs/labs.yaml` with SHA-256
  checksums
- No host filesystem access by default
- Per-session isolation: each lab session is a fresh wasmtime
  instance
- Resource caps via wasmtime fuel + memory limits
- Sandbox host functions are enumerated and reviewed; no ad-hoc
  imports

## PostgreSQL schema overview

| Table | Purpose | Key columns |
|---|---|---|
| `users` | Learner identity | `id`, `email`, `display_name`, `argon2_hash`, `created_at` |
| `paths` | A learning track | `id`, `slug`, `title_sq`, `title_en`, `audience`, `nis2_measure`, `cert_offered`, `created_at` |
| `modules` | Logical grouping inside a path | `id`, `path_id`, `order`, `title_sq`, `title_en` |
| `lessons` | Atomic content unit | `id`, `module_id`, `order`, `content_version_id`, `has_lab`, `has_quiz` |
| `quizzes` | Question bank reference | `id`, `lesson_id`, `bank_ref`, `randomise`, `pass_threshold` |
| `progress` | In-flight learner state | `id`, `user_id`, `lesson_id`, `started_at`, `last_seen_at` |
| `completions` | Immutable completion record | `id`, `user_id`, `lesson_id`, `content_version_id`, `score`, `completed_at`, `evidence_hash` |
| `certifications` | Per-track certificates | `id`, `user_id`, `path_id`, `issued_at`, `signature`, `expires_at` |
| `lab_sessions` | Lab session telemetry | `id`, `user_id`, `lab_id`, `runtime` (`docker` \| `wasmtime`), `started_at`, `ended_at`, `resource_metrics` |
| `content_versions` | Immutable content snapshots | `id`, `lesson_id`, `revision`, `content_hash`, `created_at` |

Notes:

- `completions.content_version_id` is the load-bearing audit field —
  every completion references the exact lesson revision the learner
  saw. Module 8 enforces that revisions are append-only.
- `completions.evidence_hash` is the BLAKE3 hash of the canonical
  evidence body submitted to CITADEL; reproducible for audit
  verification.
- `certifications.signature` is Ed25519 over the canonical
  certification body. Signing key lives in a KMS-backed secret
  store; key rotation procedure documented in
  `docs/operator-handbook.md` (lands with v1.0.0).
- The `docker` value of `lab_sessions.runtime` is the v1.0.0
  stop-gap runtime and is **out of scope for the v1.0.0 security
  audit** (per `docs/security/pentest-scope.md`); v1.0.0+ deployments
  run the `wasmtime` runtime.

## Integration arrows

### CITADEL — `cyberpath.completion`

Async, fire-and-forget from the API request lifecycle. Bounded
queue + circuit breaker + 10s drain on shutdown (same pattern as
VertGuard's `internal/citadel/` client). Schema in
[citadel-integration.md](./citadel-integration.md).

### NIS2 Compass — coverage + recommend

Synchronous, NIS2 Compass is the caller. Two endpoints:

- `GET /api/v1/cyberpath/coverage/{user_id}` — which Article 21
  measures has this user produced training evidence for, and
  through which tracks
- `GET /api/v1/cyberpath/recommend?gap=<measure>` — for a given
  Article 21 measure with a documented gap, which tracks address it

Schemas in [nis2-integration.md](./nis2-integration.md).

### IRFlow — incident → track recommendation

CyberPath consumes IRFlow signals (HMAC-signed webhook,
inbound). Incident type → recommended track mapping is configurable
per deployment. Default mapping ships in v1.0.0.

### opensecstack/sdk

Shared primitives: auth middleware, Argon2id password hashing,
HMAC-signed webhook helpers. Same dependency as the rest of the Go
platforms.

## Environments and configuration

Configuration is layered (env vars override YAML, viper
convention). Required env vars (target shape — final names confirmed
at v0.0.1):

```bash
CYBERPATH_DB_URL=postgres://...
CYBERPATH_HTTP_ADDR=:8086
CYBERPATH_CITADEL_API_URL=https://citadel.internal
CYBERPATH_CITADEL_KEY_SECRET=<hmac secret>
CYBERPATH_CITADEL_PROJECT_ID=<project id>
CYBERPATH_NIS2COMPASS_API_URL=https://nis2.internal
CYBERPATH_IRFLOW_API_URL=https://irflow.internal
CYBERPATH_IRFLOW_KEY_SECRET=<hmac secret>
CYBERPATH_LAB_RUNTIME=docker      # docker | wasmtime
CYBERPATH_CERT_SIGNING_KEY=<KMS reference>
```

## Observability

- `/metrics` (Prometheus) on the API port, unauthenticated (matches
  ecosystem convention)
- Structured JSON logs via zerolog
- Request IDs propagated via `X-Request-Id`
- CITADEL emitter exports queue depth, emit success/failure
  counters, and emit latency histogram

## Related

- [README.md](../README.md)
- [ROADMAP.md](../ROADMAP.md)
- [module-list.md](./module-list.md)
- [citadel-integration.md](./citadel-integration.md)
- [nis2-integration.md](./nis2-integration.md)
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
