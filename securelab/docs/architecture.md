# SecureLab Architecture

> Status: scaffold. This document captures the design intent for
> v0.1.0 and v1.0.0. Concrete code references will land as the
> directories under `securelab/`, `payload-engine/`, and `web/`
> populate.

## High-level topology

```
                   ┌─────────────────────────────────────────┐
                   │    Operator (browser — authorised only)  │
                   │    React + Vite dashboard  :3007         │
                   │    • scenario library browser            │
                   │    • execution console                   │
                   │    • ATT&CK coverage heatmap             │
                   │    • detection validation results        │
                   │    • fuzzing campaign reports            │
                   └───────────────┬─────────────────────────┘
                                   │ HTTPS (isolated segment only)
                                   ▼
    ┌──────────────────────────────────────────────────────────┐
    │               SecureLab API (Python / FastAPI)  :8087   │
    │  ────────────────────────────────────────────────────    │
    │  FastAPI · SQLAlchemy · Celery · structlog ·             │
    │  prometheus-client · opensecstack/sdk                    │
    │                                                          │
    │  securelab/scenario_engine/    (Module 1)               │
    │  securelab/attack_library/     (Module 2)               │
    │  securelab/mitre_mapper/       (Module 3)               │
    │  securelab/detection_validator/(Module 4, v1.0.0)       │
    │  securelab/payload_fuzzer/     (Module 5, v1.0.0)       │
    │  securelab/citadel_emitter/    (Module 6, v1.0.0)       │
    │  securelab/irflow_adapter/     (Module 7, v1.0.0)       │
    └──────┬─────────────────────────────┬────────────────────┘
           │                             │
           │ PyO3 (in-process)           │ Celery tasks
           ▼                             ▼
  ┌────────────────────┐      ┌──────────────────────────┐
  │  Payload Engine    │      │  Celery Worker           │
  │  (Rust)            │      │  (async scenario exec,   │
  │                    │      │   detection polling,     │
  │  • encoding        │      │   CITADEL emission)      │
  │  • mutation        │      │                          │
  │  • fuzzing         │      │  broker: Redis           │
  │  • size variation  │      └──────────────────────────┘
  └────────────────────┘
           │
           ▼
  ┌────────────────────┐
  │  PostgreSQL        │
  │  (per-platform)    │
  │                    │
  │  scenarios ·       │
  │  executions ·      │
  │  steps ·           │
  │  results ·         │
  │  detection_events ·│
  │  audit_log ·       │
  │  scenario_versions │
  └────────────────────┘

  Outbound integrations (from isolated egress network, HMAC-signed):

  ┌────────────┐   securelab.simulation (async, WORM)
  │  CITADEL   │ ◄─────────────────────────────────────
  └────────────┘

  ┌────────────┐   GET alerts (detection polling, read-only)
  │  OpenScrub │ ◄─────────────────────────────────────────
  └────────────┘

  ┌────────────┐   GET anomalies (detection polling, read-only)
  │  APIGuard  │ ◄─────────────────────────────────────────────
  └────────────┘

  ┌────────────┐   GET ioc-matches (detection polling, read-only)
  │ ThreatFlow │ ◄───────────────────────────────────────────────
  └────────────┘

  ┌────────────┐   POST results + coverage gaps
  │  IRFlow    │ ◄──────────────────────────────
  └────────────┘
```

## Components

### API server (Python / FastAPI)

- **FastAPI** — HTTP router, request validation (Pydantic v2),
  OpenAPI generation
- **SQLAlchemy 2** — ORM and async database access (asyncpg driver)
- **Alembic** — database migrations
- **Celery** — async task queue for scenario execution, detection
  polling, and CITADEL emission; broker is Redis
- **structlog** — structured JSON logging; request IDs propagated
  via `X-Request-Id`
- **prometheus-client** — metrics on `/metrics`, unauthenticated
  (matches ecosystem convention; restrict by firewall in production)
- **opensecstack/sdk** — auth middleware, Argon2id password hashing,
  HMAC-signed webhook helpers

### Payload engine (Rust)

Compiled as a native extension and called from Python via PyO3
bindings. The Rust boundary is a deliberate performance and safety
choice: payload generation involves byte-level manipulation that
benefits from zero-cost abstractions, and keeping this code in a
memory-safe language with a well-reviewed `unsafe` policy reduces
the attack surface of the engine itself.

- **Encoding variants:** Base64 (standard, URL-safe, chunked),
  URL encoding (full, partial, double), hex, Unicode escapes
- **Byte mutation strategies:** bit-flip, byte-swap, null-byte
  injection, length variation, boundary-value generation
- **Fuzzing campaigns:** generate N variants from a base payload
  using configurable mutation strategies; bounded output size
- `deny(unsafe_code)` in the crate root; unsafe blocks require
  explicit maintainer sign-off

### Dashboard (React + TypeScript + Vite)

- React 18+, TypeScript strict
- Vite for dev/build
- TanStack Query for API state management
- ATT&CK coverage heatmap (D3-based navigator-style layer view)
- Execution console (live log streaming via Server-Sent Events)
- Detection validation results viewer with pass/fail/inconclusive
  status per step

## PostgreSQL schema overview

| Table | Purpose | Key columns |
|---|---|---|
| `operators` | Authorised operators | `id`, `email`, `display_name`, `argon2_hash`, `role`, `created_at` |
| `scenarios` | Scenario definitions | `id`, `slug`, `title`, `description`, `author`, `current_version_id`, `created_at` |
| `scenario_versions` | Immutable scenario snapshots | `id`, `scenario_id`, `version`, `content_hash`, `yaml_content`, `created_at` |
| `attack_primitives` | Attack library entries | `id`, `slug`, `title`, `mitre_technique`, `mitre_sub_technique`, `tactic`, `platform`, `created_at` |
| `executions` | Scenario execution records | `id`, `scenario_id`, `scenario_version_id`, `operator_id`, `target_scope`, `mode` (`dry_run` \| `live`), `status`, `started_at`, `completed_at`, `evidence_hash` |
| `execution_steps` | Per-step execution records | `id`, `execution_id`, `step_index`, `primitive_id`, `status`, `payload_hash`, `dispatched_at`, `completed_at` |
| `detection_events` | Detection assertions per step | `id`, `step_id`, `source` (`openscrub` \| `apiguard` \| `threatflow`), `verdict` (`detected` \| `not_detected` \| `inconclusive`), `event_id`, `captured_at` |
| `fuzzing_campaigns` | Fuzzing campaign records | `id`, `execution_id`, `strategy`, `variant_count`, `detected_count`, `detection_rate`, `created_at` |
| `audit_log` | Append-only operator action log | `id`, `operator_id`, `action`, `resource_type`, `resource_id`, `detail_json`, `created_at` |

Notes:

- `executions.scenario_version_id` is the load-bearing audit field —
  every execution references the exact scenario version that was
  executed. Scenarios are content-hashed on write; the hash is stored
  in `scenario_versions.content_hash`.
- `executions.evidence_hash` is the BLAKE3 hash of the canonical
  evidence body submitted to CITADEL; reproducible for audit
  verification.
- `audit_log` is INSERT-only at the database level; enforced via
  Postgres row-level security (`USING (false)` on UPDATE/DELETE for
  the API service role).
- `execution_steps.payload_hash` references the payload content-
  addressed store; the payload bytes are not stored in the database
  row.

## Security boundaries

SecureLab has explicit trust boundaries that operators must maintain:

```
  ┌───────────────────────────────────────────────────────────┐
  │  ISOLATED NETWORK SEGMENT (mandatory)                     │
  │                                                           │
  │  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐  │
  │  │  SecureLab  │    │  Postgres   │    │   Redis     │  │
  │  │  API :8087  │    │  :5432      │    │  :6379      │  │
  │  └──────┬──────┘    └─────────────┘    └─────────────┘  │
  │         │                                                 │
  │  ┌──────▼──────┐                                         │
  │  │  Celery     │                                         │
  │  │  Worker     │                                         │
  │  └──────┬──────┘                                         │
  │         │ (egress allow-list only)                       │
  └─────────┼─────────────────────────────────────────────── ┘
            │
            │  Firewall: allow-list to specific IPs/ports only
            ▼
  ┌─────────────────────────────────────────────────────────┐
  │  INTEGRATION ENDPOINTS (operator-controlled)            │
  │  CITADEL · OpenScrub · APIGuard · ThreatFlow · IRFlow   │
  └─────────────────────────────────────────────────────────┘
```

**Trust boundary rules:**

1. The API port (8087) and dashboard port (3007) must not be
   reachable from the public internet. Bind to `127.0.0.1` or
   an isolated VLAN.
2. The Postgres and Redis ports must not be reachable from outside
   the isolated network segment.
3. Outbound from the Celery worker to integration endpoints must be
   allow-listed by IP and port at the firewall level. No general
   internet egress.
4. The operator's browser must be on the same isolated network
   segment or accessing via an authenticated VPN/jump host.

## Integration arrows

### CITADEL — `securelab.simulation`

Async, fire-and-forget from the Celery worker after a live execution
completes. Bounded queue + circuit breaker + 10s drain on shutdown.
Schema in [citadel-integration.md](./citadel-integration.md).

A live execution is not considered complete until the CITADEL
emission succeeds or the circuit breaker marks it `evidence_pending`.
Dry-run executions do not emit to CITADEL.

### OpenScrub — detection polling

Read-only. The detection validator polls
`GET /api/v1/alerts?technique={id}&since={ts}` for technique-tagged
alert events within the configured detection window. HMAC-SHA256
signed request. No write access.

### APIGuard — detection polling

Read-only. Polls `GET /api/v1/anomalies?correlation_id={exec_id}`
to correlate request-anomaly events with execution steps. HMAC-SHA256
signed. No write access.

### ThreatFlow — detection polling

Read-only. Polls `GET /api/v1/ioc-matches?execution_id={exec_id}`
for IOC match events correlated to the simulation execution. HMAC-SHA256
signed. No write access.

### IRFlow — push results

SecureLab is the caller. Pushes execution results and ATT&CK coverage
gaps via `POST /api/v1/securelab/results` on IRFlow. HMAC-SHA256
signed. IRFlow uses the gap summary to drive incident-response
recommendations.

### opensecstack/sdk

Shared primitives: auth middleware, Argon2id password hashing,
HMAC-signed webhook helpers. Same dependency pattern as the rest of
the Python platforms.

## Observability

- `/metrics` (Prometheus) on the API port, unauthenticated
  (matches ecosystem convention; restrict by firewall in production)
- Structured JSON logs via structlog
- Request IDs propagated via `X-Request-Id`
- Execution state machine transitions logged at INFO level
- CITADEL emitter exports: queue depth, emit success/failure
  counters, emit latency histogram
- Detection validator exports: poll latency, verdict distribution
  (detected/not_detected/inconclusive/timeout) per integration

## Go 1.22 Architecture (v1.0.0)

The v1.0.0 implementation uses Go 1.22 for the backend API, replacing the Python/FastAPI scaffold. The ASCII diagram below shows the Go-based architecture.

```
                    ┌──────────────────────────────────┐
                    │    Operator (browser)             │
                    │    React/TypeScript dashboard     │
                    │    :3000 (nginx in production)    │
                    └────────────┬─────────────────────┘
                                 │ HTTPS
                                 ▼
                    ┌──────────────────────────────────┐
                    │    SecureLab API (Go 1.22)        │
                    │    chi router · pgx · zap         │
                    │    :8080                          │
                    │                                  │
                    │    /cmd/securelab/                │
                    │    /internal/scenarios/           │
                    │    /internal/runner/              │
                    │    /internal/detection/           │
                    │    /internal/citadel/             │
                    └──────┬───────────────────────────┘
                           │
              ┌────────────┼────────────────────┐
              ▼            ▼                    ▼
   ┌────────────────┐ ┌──────────┐  ┌──────────────────────┐
   │ Rust payload-  │ │PostgreSQL│  │  Detection monitor   │
   │ gen crate      │ │:5432     │  │  (polls platforms)   │
   │ (payload-gen/) │ │          │  │                      │
   │                │ │runs ·    │  │  → OpenScrub         │
   │ generate_bola  │ │envs ·    │  │  → APIGuard          │
   │ generate_jwt   │ │audit_log │  │  → ThreatFlow        │
   │ mass_assign    │ └──────────┘  └──────────────────────┘
   │ fuzzer         │
   │ encoder        │       ┌────────────────────┐
   └────────────────┘       │  CITADEL           │
                            │  securelab.        │
                            │  run_completed     │
                            │  (HMAC-SHA256)     │
                            └────────────────────┘

  Test environments (--internal Docker network, never reaches prod):

  ┌───────────────────────────────────────────────────────────┐
  │  securelab-test-net  (internal: true — no external route) │
  │                                                           │
  │  ┌─────────────┐         ┌─────────────┐                 │
  │  │ target-api  │         │  target-db  │                 │
  │  │ :9090       │         │  :5432      │                 │
  │  │ (intentional│         │             │                 │
  │  │  OWASP vulns│         │             │                 │
  │  │  for testing│         │             │                 │
  │  └─────────────┘         └─────────────┘                 │
  └───────────────────────────────────────────────────────────┘
```

### Key Go packages

- **chi** (`github.com/go-chi/chi`) — lightweight, idiomatic HTTP router
- **pgx** (`github.com/jackc/pgx/v5`) — PostgreSQL driver with native protocol support
- **zap** (`go.uber.org/zap`) — structured, leveled logging
- **encoding/json** — JSON serialization (standard library)
- **crypto/hmac + crypto/sha256** — CITADEL event signing

### Rust integration

The `rust/payload-gen` crate is compiled as a standalone library and called from Go via subprocess or shared library binding. It provides:
- `generate_bola_payloads(count)` — sequential IDs and UUIDs
- `generate_jwt_none_token(claims)` — unsigned JWT tokens
- `generate_mass_assignment_payload(base, extra_fields)` — merged JSON
- `mutate(input, iterations)` — byte-level fuzzing mutations
- Encoding helpers: base64, URL, double-URL, Unicode escape

## Related

- [README.md](../README.md)
- [ROADMAP.md](../ROADMAP.md)
- [SECURITY.md](../SECURITY.md)
- [docs/deployment.md](deployment.md)
- [docs/scenario-spec.md](scenario-spec.md)
- [docs/citadel-integration.md](citadel-integration.md)
- [docs/mitre-attack-mapping.md](mitre-attack-mapping.md)
- [docs/safety-controls.md](safety-controls.md)
