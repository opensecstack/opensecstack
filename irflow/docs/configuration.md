# IRFlow Configuration Reference

Full reference for every `IRFLOW_*` environment variable. For the
canonical example file, see [../.env.example](../.env.example). For
deployment-flavoured settings (Kubernetes, docker-compose, secret
manager wiring), see [deployment.md](./deployment.md).

IRFlow reads configuration through Viper. The precedence order is:

1. Environment variables (`IRFLOW_*`) — highest
2. YAML file at `$IRFLOW_CONFIG_PATH` if set
3. Hard-coded defaults (below) — lowest

## Server

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_SERVER_HOST` | `0.0.0.0` | Bind address. Keep `0.0.0.0` behind a private ingress; bind `127.0.0.1` only for single-host deployments with an on-box ingress. |
| `IRFLOW_SERVER_PORT` | `8083` | HTTP port. Matches the port matrix in [../../docs/deployment-topology.md](../../docs/deployment-topology.md). |
| `IRFLOW_SERVER_READ_TIMEOUT` | `15s` | Read timeout for incoming requests. |
| `IRFLOW_SERVER_WRITE_TIMEOUT` | `15s` | Write timeout. Webhook endpoints with large IOC bundles may need this raised. |

## Database

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_DB_HOST` | `localhost` | PostgreSQL host. |
| `IRFLOW_DB_PORT` | `5432` | Port. |
| `IRFLOW_DB_NAME` | `irflow` | Database name. |
| `IRFLOW_DB_USER` | `irflow` | Login role. |
| `IRFLOW_DB_PASSWORD` | — | **Required** in production. |
| `IRFLOW_DB_SSL_MODE` | `disable` | Production should be `require` or `verify-full`. |

IRFlow pings the DB every 15 s to update `irflow_db_pool_connections`
metric series — no special tuning needed beyond a standard production
connection pool.

## Authentication

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_AUTH_SECRET` | — | HS256 JWT signing secret, **≥ 32 random bytes**. Empty enables dev mode with a loud warning. |
| `IRFLOW_AUTH_TOKEN_TTL` | `8h` | Maximum token lifetime enforced at verification. |
| `IRFLOW_AUTH_ISSUER` | `irflow` | Expected `iss` claim; rejected if mismatched. |
| `IRFLOW_AUTH_DEV_MODE` | `false` | Forces dev mode even if `AUTH_SECRET` is set. **Never true in production.** |
| `IRFLOW_AUTH_PEPPER` | — | Server-side pepper (≥ 16 bytes) for API-key / password hashing via `sdk/go/password`. Rotating this invalidates every stored hash. |

Generate suitable secrets:

```bash
openssl rand -base64 32   # for IRFLOW_AUTH_SECRET
openssl rand -base64 24   # for IRFLOW_AUTH_PEPPER
```

## CITADEL (governance)

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_CITADEL_API_URL` | `http://localhost:8082` | Base URL of the CITADEL service. Empty = **local-only mode** (no MARSHAL evaluation, no WORM emission). |
| `IRFLOW_CITADEL_KEY_ID` | — | CITADEL client key identifier. |
| `IRFLOW_CITADEL_KEY_SECRET` | — | HMAC shared secret for signing Kerkese payloads. |
| `IRFLOW_CITADEL_PROJECT_ID` | — | CITADEL project under which governance decisions are recorded. |
| `IRFLOW_CITADEL_DRY_RUN` | `true` | When `true`, CITADEL returns EXECUTE for every call. Flip to `false` only after verifying the chain is up. |

Local-only mode is intended for CI and unit-test environments —
production deployments must configure CITADEL. See
[../../docs/security-maturity.md](../../docs/security-maturity.md) for
the reasoning.

## NIS2 Compass (Article 23 notification)

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_NIS2_API_URL` | `http://localhost:8081` | Base URL of NIS2 Compass. |
| `IRFLOW_NIS2_API_KEY` | — | Bearer token minted by NIS2 Compass's key-management CLI. |
| `IRFLOW_NIS2_ASSESSMENT_ID` | — | Target assessment that receives the notification. |
| `IRFLOW_NIS2_MEASURE_REF` | `b` | Article 21(2) measure reference; `b` = Incident Handling. |

NIS2 notifications fire on a detached goroutine — a slow Compass never
blocks incident creation. Failures are logged and surface via
`irflow_governance_calls_total{target="nis2",result="failure"}`.

## Webhooks (inbound)

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_WEBHOOK_SECRET` | — | Legacy shared-fallback secret. Deprecated; set per-source instead. |
| `IRFLOW_WEBHOOK_APIGUARD_SECRET` | — | HMAC secret for `/api/v1/webhooks/apiguard`. Empty → endpoint returns 503. |
| `IRFLOW_WEBHOOK_CITADEL_SECRET` | — | HMAC secret for `/api/v1/webhooks/citadel`. |
| `IRFLOW_WEBHOOK_THREATFLOW_SECRET` | — | HMAC secret for `/api/v1/webhooks/threatflow`. |
| `IRFLOW_WEBHOOK_CALLBACK_URL` | — | Reserved for v1.2 outbound webhooks. |
| `IRFLOW_WEBHOOK_MAX_BODY_SIZE` | `1048576` | 1 MiB — raise for bulky IOC bundles. |
| `IRFLOW_WEBHOOK_CLOCK_SKEW_TOLERANCE` | `5m` | Replay window on `X-Irflow-Timestamp`. |

See [webhook-spec.md](./webhook-spec.md) for the signing scheme.

## Integration testing

| Variable | Default | Notes |
|---|---|---|
| `IRFLOW_TEST_DB_URL` | — | Connection string for `make test-integration`; matches the `docker-compose.test.yml` Postgres on port 54832. Unset = integration tests skip. |

## Precedence and validation

At startup, `config.Load()` validates:

- Required fields for the mode you're in (e.g. CITADEL secret required
  when `CITADEL_API_URL` is set).
- Pepper ≥ 16 bytes when present.
- Auth secret length ≥ 32 bytes when present.

Invalid configuration fails loud — the process exits with a
descriptive error before any HTTP listener starts. There is no silent
fallback; if a required value is missing, IRFlow refuses to run.

## YAML alternative

```yaml
server:
  host: 0.0.0.0
  port: 8083

db:
  host: postgres.internal
  name: irflow
  user: irflow
  password: ${DB_PASSWORD}   # still resolved from env
  ssl_mode: require

auth:
  secret: ${IRFLOW_AUTH_SECRET}
  token_ttl: 8h
  issuer: irflow

citadel:
  api_url: https://citadel.internal
  project_id: prod
```

Pass `IRFLOW_CONFIG_PATH=/etc/irflow/irflow.yaml` to load. Environment
variables still override matching YAML keys.

## Related

- [.env.example](../.env.example) — copy-paste starter
- [Deployment](./deployment.md) — how these knobs map onto K8s / docker-compose
- [RBAC guide](./rbac-guide.md) — what AUTH_SECRET actually protects
