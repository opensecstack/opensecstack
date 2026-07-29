# CyberPath Configuration Reference

Full reference for every `CYBERPATH_*` environment variable. CyberPath
reads configuration through Viper with the `CYBERPATH_` prefix.
Nested keys use `_` as separator. Precedence: env vars > YAML file >
hard-coded defaults.

For deployment topology, see [deployment.md](deployment.md) and
[deployment-helm.md](deployment-helm.md).

## Configuration file

CyberPath looks for `cyberpath.yaml` in (in order):

1. `$CYBERPATH_CONFIG_PATH` (if set)
2. `./cyberpath.yaml`
3. `/etc/cyberpath/cyberpath.yaml`

Example (every key has an env-var equivalent):

```yaml
server:
  http_addr: ":8086"
  log_level: "info"
db:
  url:        "postgres://cyberpath:cyberpath@localhost:5439/cyberpath?sslmode=require"
  max_open_conns: 25
auth:
  secret: "<32+ bytes>"
  issuer: "cyberpath"
citadel:
  api_url:    "https://citadel.internal:8099"
  key_id:     "cyberpath-prod"
  key_secret: "<hmac>"
  project_id: "prod"
nis2compass:
  api_url:    "https://nis2.internal:8092"
irflow:
  api_url:        "https://irflow.internal:8087"
  webhook_secret: "<hmac>"
sandbox:
  runtime: "docker"          # docker | wasmtime
  cpu_quota: "1.0"
  memory_mib: 512
  network: "none"
content:
  path: "/var/lib/cyberpath/content"
i18n:
  locales: ["sq","en"]
  default: "sq"
```

## Server

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_HTTP_ADDR` | `:8086` | API listen address |
| `CYBERPATH_WEB_PORT` | `3006` | React dashboard port |
| `CYBERPATH_LOG_LEVEL` | `info` | `debug`/`info`/`warn`/`error` |
| `CYBERPATH_SERVER_READ_TIMEOUT` | `30s` | HTTP read timeout |
| `CYBERPATH_SERVER_WRITE_TIMEOUT` | `30s` | HTTP write timeout |
| `CYBERPATH_REQUEST_ID_HEADER` | `X-Request-Id` | Request-id propagation header |

## Database

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_DB_URL` | — | **Required.** Full Postgres DSN; takes precedence over the split fields below |
| `CYBERPATH_DB_HOST` | `localhost` | Host (used when `DB_URL` empty) |
| `CYBERPATH_DB_PORT` | `5439` | Port — CyberPath-specific to avoid clashes |
| `CYBERPATH_DB_NAME` | `cyberpath` | Database name |
| `CYBERPATH_DB_USER` | `cyberpath` | User |
| `CYBERPATH_DB_PASSWORD` | — | **Required** in production |
| `CYBERPATH_DB_SSL_MODE` | `require` | `require` / `verify-full` for prod; `disable` for dev |
| `CYBERPATH_DB_MAX_OPEN_CONNS` | `25` | pgx pool maximum |
| `CYBERPATH_DB_MIGRATE_ON_BOOT` | `true` | Auto-apply migrations on startup |

## Auth

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_AUTH_SECRET` | — | **Required** in prod. HS256 JWT signing key, ≥ 32 random bytes |
| `CYBERPATH_AUTH_TOKEN_TTL` | `8h` | Access-token lifetime |
| `CYBERPATH_AUTH_REFRESH_TTL` | `720h` | Refresh-token lifetime (30 days) |
| `CYBERPATH_AUTH_ISSUER` | `cyberpath` | Expected `iss` claim |
| `CYBERPATH_AUTH_ARGON2_MEMORY_KIB` | `65536` | Argon2id memory cost (64 MiB) |
| `CYBERPATH_AUTH_ARGON2_TIME` | `3` | Argon2id time cost |
| `CYBERPATH_AUTH_ARGON2_PARALLELISM` | `4` | Argon2id parallelism |
| `CYBERPATH_AUTH_DEV_MODE` | `false` | Dev-only relaxed validation; **never** true in prod |

Argon2id parameters match the rest of the ecosystem (`opensecstack/sdk`).

## CITADEL integration (v1.0.0)

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_CITADEL_API_URL` | — | Empty = standalone (no WORM, loud WARN at boot) |
| `CYBERPATH_CITADEL_KEY_ID` | — | Client key identifier |
| `CYBERPATH_CITADEL_KEY_SECRET` | — | HMAC-SHA256 shared secret |
| `CYBERPATH_CITADEL_PROJECT_ID` | — | Project scope for WORM entries |
| `CYBERPATH_CITADEL_QUEUE_MAX` | `1000` | Async emit queue size |
| `CYBERPATH_CITADEL_DRAIN_TIMEOUT` | `10s` | Graceful-shutdown drain window |
| `CYBERPATH_CITADEL_BREAKER_THRESHOLD` | `5` | Failures before breaker opens |
| `CYBERPATH_CITADEL_BREAKER_COOLDOWN` | `30s` | Breaker cooldown |
| `CYBERPATH_CITADEL_WAL_PATH` | `/var/lib/cyberpath/citadel-wal` | On-disk WAL for unflushed events |

Full spec: [citadel-integration.md](citadel-integration.md).

## NIS2 Compass integration (v1.0.0)

Per ADR-014, NIS2 Compass **pulls** from CyberPath — it calls
`GET /api/v1/coverage/{user_id}` and
`GET /api/v1/cyberpath/recommend?gap=<measure>` — CyberPath never
pushes to NIS2 Compass. `CYBERPATH_NIS2COMPASS_API_URL` is used only
for CyberPath's own outbound `/healthz` connectivity check, reported
in `/readyz`'s `integrations.nis2compass` field.

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_NIS2COMPASS_API_URL` | — | Compass base URL, used only for the outbound `/healthz` connectivity check surfaced in `/readyz` |
| `CYBERPATH_NIS2COMPASS_TIMEOUT` | `5s` | Per-request timeout for the health check |

Inbound coverage / recommend calls authenticate via the standard JWT
middleware; no extra config is required for the CyberPath side.
Full spec: [nis2-integration.md](nis2-integration.md).

## IRFlow integration (v1.0.0)

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_IRFLOW_API_URL` | — | IRFlow base URL (optional) |
| `CYBERPATH_IRFLOW_KEY_SECRET` | — | HMAC-SHA256 shared secret |
| `CYBERPATH_IRFLOW_WEBHOOK_SECRET` | — | Inbound webhook verification secret |
| `CYBERPATH_IRFLOW_INCIDENT_TRACK_MAP` | `/etc/cyberpath/irflow-map.yaml` | Path to incident-type → track mapping |

## Lab sandbox

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_LAB_RUNTIME` | `docker` | `docker` (v1.0.0) or `wasmtime` (v1.0.0+) |
| `CYBERPATH_LAB_DEFAULT_TTL` | `2h` | Auto-stop sessions after this |
| `CYBERPATH_LAB_MAX_PER_USER` | `1` | Concurrent labs per learner |
| `CYBERPATH_LAB_MAX_PER_TENANT` | `50` | Concurrent labs per tenant |
| `CYBERPATH_SANDBOX_CPU_QUOTA` | `1.0` | vCPUs per lab session |
| `CYBERPATH_SANDBOX_MEMORY_MIB` | `512` | Memory limit (MiB) |
| `CYBERPATH_SANDBOX_NETWORK` | `none` | `none` / `egress-only` / `lab-net` |
| `CYBERPATH_SANDBOX_PIDS_LIMIT` | `256` | Max processes per session |
| `CYBERPATH_SANDBOX_DOCKER_SOCK` | `/var/run/docker.sock` | Docker socket path (Docker runtime) |
| `CYBERPATH_SANDBOX_WASM_FUEL` | `5000000000` | wasmtime fuel cap per session |
| `CYBERPATH_SANDBOX_WASM_MAX_MEMORY_MIB` | `256` | wasmtime memory cap |
| `CYBERPATH_SANDBOX_IMAGE_REGISTRY` | `ghcr.io/opensecstack` | Lab-image registry |

`network: none` is the default. `egress-only` allows outbound HTTPS
for labs that legitimately need it (e.g. IRFlow lab); `lab-net` joins
a per-tenant Docker network for multi-container exercises.

## Content

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_CONTENT_PATH` | `/var/lib/cyberpath/content` | Track / lesson source root |
| `CYBERPATH_CONTENT_AUTO_RELOAD` | `false` | Watch content path and reload on change (dev only) |
| `CYBERPATH_CONTENT_HASH_ALGO` | `blake3` | Content-versioning hash; immutable per-deployment |
| `CYBERPATH_CONTENT_STRICT_BILINGUAL` | `true` | Refuse to import a track missing `.sq.md` or `.en.md` |

## i18n

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_I18N_LOCALES` | `sq,en` | Comma-separated supported locales |
| `CYBERPATH_I18N_DEFAULT` | `sq` | Fallback locale |
| `CYBERPATH_I18N_MISSING_KEY_BEHAVIOUR` | `fallback` | `fallback` / `error` / `passthrough` |

## Certification (v1.0.0)

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_CERT_SIGNING_KEY` | — | KMS reference (e.g. `kms://...`) for the Ed25519 signing key |
| `CYBERPATH_CERT_KEY_ID` | — | Key identifier embedded in `signed_by` |
| `CYBERPATH_CERT_DEFAULT_EXPIRY_DAYS` | `1095` | Fallback when track has no override (3 years) |
| `CYBERPATH_CERT_PDF_TEMPLATE_PATH` | `/etc/cyberpath/cert-template.pdf` | Background template |

## Observability

| Variable | Default | Description |
|---|---|---|
| `CYBERPATH_METRICS_ENABLED` | `true` | Expose `/metrics` |
| `CYBERPATH_METRICS_PATH` | `/metrics` | Path |
| `CYBERPATH_TRACING_OTLP_ENDPOINT` | — | Optional OTLP endpoint for distributed tracing |
| `CYBERPATH_TRACING_SAMPLE_RATIO` | `0.05` | Trace sampling ratio |

## Full example — production

```bash
# Server
CYBERPATH_HTTP_ADDR=:8086
CYBERPATH_LOG_LEVEL=info

# Database
CYBERPATH_DB_URL=postgres://cyberpath:***@cyberpath-db.internal:5432/cyberpath?sslmode=verify-full

# Auth
CYBERPATH_AUTH_SECRET=***   # openssl rand -base64 48
CYBERPATH_AUTH_DEV_MODE=false

# CITADEL
CYBERPATH_CITADEL_API_URL=https://citadel.internal:8099
CYBERPATH_CITADEL_KEY_ID=cyberpath-prod
CYBERPATH_CITADEL_KEY_SECRET=***
CYBERPATH_CITADEL_PROJECT_ID=prod

# NIS2 Compass + IRFlow
CYBERPATH_NIS2COMPASS_API_URL=https://nis2.internal:8092
CYBERPATH_IRFLOW_API_URL=https://irflow.internal:8087
CYBERPATH_IRFLOW_WEBHOOK_SECRET=***

# Sandbox
CYBERPATH_LAB_RUNTIME=wasmtime
CYBERPATH_SANDBOX_CPU_QUOTA=1.0
CYBERPATH_SANDBOX_MEMORY_MIB=512
CYBERPATH_SANDBOX_NETWORK=none

# Content
CYBERPATH_CONTENT_PATH=/var/lib/cyberpath/content

# Certifications
CYBERPATH_CERT_SIGNING_KEY=kms://aws/eu-west-1/key/abc-123
CYBERPATH_CERT_KEY_ID=cyberpath-cert-2027a
```

## Full example — dev (docker-compose)

```bash
CYBERPATH_HTTP_ADDR=:8086
CYBERPATH_LOG_LEVEL=debug
CYBERPATH_DB_URL=postgres://cyberpath:cyberpath_dev@db:5432/cyberpath?sslmode=disable
CYBERPATH_AUTH_SECRET=dev-secret-32-chars-minimum-replace-me
CYBERPATH_LAB_RUNTIME=docker
CYBERPATH_SANDBOX_DOCKER_SOCK=/var/run/docker.sock
CYBERPATH_CONTENT_PATH=/content
CYBERPATH_CITADEL_API_URL=         # empty = standalone (loud WARN)
CYBERPATH_NIS2COMPASS_API_URL=     # empty = no inbound restriction beyond JWT
```

## Validation at startup

CyberPath validates on boot:

| Check | Failure action |
|---|---|
| `DB_URL` (or split fields) reachable | Process exits with descriptive error |
| `AUTH_SECRET` ≥ 32 bytes (prod) | Refuse to start |
| `CONTENT_PATH` exists, contains ≥ 1 valid track | WARN (server starts; tracks endpoint returns empty) |
| `LAB_RUNTIME=wasmtime` but Wasm module not built (v0.1.x) | Refuse to start |
| `LAB_RUNTIME=docker` but Docker socket unreadable | Refuse to start lab module (other modules continue) |
| `CITADEL_API_URL` unset in prod | WARN — standalone mode |
| `CERT_SIGNING_KEY` unset in prod | WARN — certifications disabled |

`AUTH_DEV_MODE=true` in production refuses to start.

## See also

- [quick-start.md](quick-start.md)
- [api.md](api.md)
- [deployment.md](deployment.md)
- [deployment-helm.md](deployment-helm.md)
- [troubleshooting.md](troubleshooting.md)
- [architecture.md](architecture.md)
