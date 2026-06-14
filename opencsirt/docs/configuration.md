# OpenCSIRT Configuration

> Status: v1.0.0. Source of truth for the API:
> [`internal/config/config.go`](../internal/config/config.go). If
> this page disagrees with the code, the code wins — please file a
> docs bug.

The OpenCSIRT API process reads configuration from the environment
exclusively. `config.FromEnv()` returns the populated `Config`
struct and runs `Validate()` before the server starts.

`Validate()` enforces the following outside `OPENCSIRT_DEV_MODE`:

- `OPENCSIRT_JWT_SECRET` must be ≥ 32 bytes.
- `OPENCSIRT_PASSWORD_PEPPER` must be set and must not contain the
  literal `do-not-use-in-prod`.
- `OPENCSIRT_DB_URL` must be set.

`OPENCSIRT_DEV_MODE=true` relaxes all three checks. Never enable it
in production.

---

## Server

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_HTTP_ADDR` | string (host:port) | `:8088` | no | REST API bind address. |
| `OPENCSIRT_NODE` | string | `opencsirt-0` | no | Node identifier embedded in CITADEL evidence. |
| `OPENCSIRT_DEV_MODE` | bool (`1`/`true`/`yes`/`on`) | `false` | no | Relaxes `Validate()` (JWT length, pepper, DB URL). Never enable in production. |

---

## Database

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_DB_URL` | string (pgx URL) | empty | yes for prod | Postgres connection string. Empty fails `Validate()` outside dev mode. |
| `OPENCSIRT_DB_MAX_CONNS` | int (>0) | `16` | no | Caps the `pgxpool` size. Tune alongside Postgres `max_connections`. |

---

## Auth (JWT verifier + login issuer)

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_JWT_SECRET` | string | empty | yes for prod | HS256 secret. Must be ≥ 32 bytes outside dev mode. Multiple secrets supported via the `parseSecrets` helper for rotation (comma-separated). |
| `OPENCSIRT_JWT_ISSUER` | string | `opencsirt` | no | Expected `iss` claim. |
| `OPENCSIRT_TOKEN_TTL` | duration (Go: `12h`, `15m`) | `12h` | no | Access-token lifetime issued by `/api/v1/auth/login`. |
| `OPENCSIRT_USERS` | CSV of `user:role:sha256hex` | empty | no | Login issuer credential list. Empty disables `/auth/login` (operators mint JWTs out-of-band). The hash is `sha256(pepper + password)`. |
| `OPENCSIRT_PASSWORD_PEPPER` | string | empty | yes for prod | Mixed into every login hash. `Validate()` refuses to boot if empty or containing `do-not-use-in-prod` outside dev mode. |

Roles (from [`internal/auth/auth.go`](../internal/auth/auth.go)):
`viewer`, `external_peer`, `analyst`, `operator`, `csirt_lead`,
`admin`.

---

## CITADEL evidence emitter

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_CITADEL_API_URL` | string (URL) | empty | no | CITADEL base URL. Empty disables emission (the outbox is still written, just never drained). |
| `OPENCSIRT_CITADEL_HMAC_SECRETS` | CSV of strings | empty | no | HMAC-SHA256 rotation list `primary,next,previous`. Signs with `[0]`. |
| `OPENCSIRT_CITADEL_KEY_ID` | string | `opencsirt-1` | no | `X-Key-ID` header value on outbound CITADEL events. |
| `OPENCSIRT_CITADEL_DRY_RUN` | bool | `true` | no | When true, builds and signs events but does not POST. Default-on so first-boot does not spam an unconfigured CITADEL. |

See [citadel-integration.md](citadel-integration.md) for the wire
envelope and rotation procedure.

---

## ThreatFlow IOC puller

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_THREATFLOW_API_URL` | string (URL) | empty | no | ThreatFlow base URL. Empty disables IOC pull. |
| `OPENCSIRT_THREATFLOW_INTERVAL` | duration | `60s` | no | Pull cadence. |

See [threatflow-integration.md](threatflow-integration.md).

---

## NIS2 Compass

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_NIS2COMPASS_API_URL` | string (URL) | empty | no | NIS2 Compass base URL. Empty disables Article 23 push. Outbound notifications fire on advisory publish for incidents with severity `high` or `critical`. |

See [nis2-integration.md](nis2-integration.md).

---

## IRFlow webhook receiver

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` | string | empty | yes if IRFlow is connected | HMAC-SHA256 secret used to verify `POST /api/v1/integrations/irflow/incident`. Empty rejects all webhook calls (401). |

See [irflow-integration.md](irflow-integration.md).

---

## VertGuard

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_VERTGUARD_API_URL` | string (URL) | empty | no | VertGuard base URL for cross-CSIRT AI threat intelligence. Empty disables the integration. |

See [vertguard-integration.md](vertguard-integration.md).

---

## Python advisory service

The Python advisory subsystem listens on port 8089 and is called
by the Go API for CSAF 2.0 generation, IOC enrichment, YARA
matching, and ML triage. See [architecture.md](architecture.md#why-two-languages).

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_ADVISORY_SERVICE_URL` | string (URL) | `http://localhost:8089` | no | Base URL the Go API uses to call the Python subsystem. |
| `OPENCSIRT_ADVISORY_SERVICE_JWT` | string | empty | yes for prod | Long-lived service JWT presented by the Go API to the Python subsystem. The Python subsystem verifies it with `OPENCSIRT_JWT_SECRET`. |

The Python process itself reads the following env vars:

| Variable | Type | Default | Description |
|---|---|---|---|
| `OPENCSIRT_PY_HOST` | string | `0.0.0.0` | Bind host for the advisory subsystem. |
| `OPENCSIRT_PY_PORT` | int | `8089` | Bind port for the advisory subsystem. |
| `OPENCSIRT_PY_JWT_SECRET` | string | — | Shared HS256 secret with the Go API. Must match `OPENCSIRT_JWT_SECRET`. |
| `OPENCSIRT_PY_JWT_ISSUER` | string | `opencsirt` | Expected `iss` claim; must match `OPENCSIRT_JWT_ISSUER`. |
| `OPENCSIRT_PY_REDIS_URL` | string | `redis://opencsirt-redis:6379/0` | Redis URL for YARA/ML job queue. |
| `OPENCSIRT_PY_LOG_LEVEL` | string | `INFO` | Python logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

Per-enrichment connector keys (e.g. `VIRUSTOTAL_API_KEY`, `OTX_API_KEY`) are
also read by the Python process. See
[advisory-authoring-guide.md](advisory-authoring-guide.md).

---

## Mitigation / incident timing

| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| `OPENCSIRT_OUTBOX_TICK` | duration | `10s` | no | CITADEL outbox watcher poll interval. Lower = faster CITADEL delivery, higher Postgres load. See [architecture.md](architecture.md#citadel-outbox-state-machine). |

---

## Example `.env` (development)

```bash
OPENCSIRT_DEV_MODE=true
OPENCSIRT_HTTP_ADDR=:8088
OPENCSIRT_DB_URL=postgres://opencsirt:opencsirt@127.0.0.1:5432/opencsirt?sslmode=disable
OPENCSIRT_JWT_SECRET=dev-only-not-for-production
OPENCSIRT_PASSWORD_PEPPER=do-not-use-in-prod
OPENCSIRT_USERS=admin:admin:<sha256hex>,lead:csirt_lead:<sha256hex>
OPENCSIRT_CITADEL_DRY_RUN=true
OPENCSIRT_ADVISORY_SERVICE_URL=http://127.0.0.1:8089
```

For production values, see [deployment.md](deployment.md). Sensitive
secrets (JWT, pepper, CITADEL HMAC, IRFlow webhook, advisory JWT)
must be sourced from a secret manager — never committed to Git.

---

## See also

- [deployment.md](deployment.md)
- [api.md](api.md)
- [architecture.md](architecture.md)
