# SecureLab Configuration

SecureLab uses a layered configuration model: environment variables
override `config.yaml` values, which override compiled-in defaults.
This follows the same convention as other platforms in the ecosystem
(viper-style, adapted for Python / pydantic-settings).

> **Security note:** Never commit secrets (HMAC keys, database
> passwords, API tokens) to version control. Use environment
> variables, a secrets manager, or Docker secrets. The `config.yaml`
> file is for non-secret deployment configuration only.

## Environment variables

### Core

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_HTTP_ADDR` | No | `127.0.0.1:8087` | API server bind address. Must be a private or loopback address in `strict` isolation mode. |
| `SECURELAB_DB_URL` | Yes | — | PostgreSQL DSN. Example: `postgres://securelab:pass@host:5432/securelab` |
| `SECURELAB_REDIS_URL` | Yes | — | Redis DSN. Example: `redis://host:6379/0` |
| `SECURELAB_SECRET_KEY` | Yes | — | Application secret key for session signing. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `SECURELAB_ENV` | No | `production` | `development` \| `production`. Development mode enables debug logging and relaxes some rate limits. |
| `SECURELAB_LOG_LEVEL` | No | `info` | `debug` \| `info` \| `warning` \| `error` |

### Isolation and access control

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_ISOLATION_MODE` | No | `strict` | `strict` \| `permissive`. **Do not set `permissive` without reading SECURITY.md.** Strict mode enforces target scope validation on every execution step and refuses to bind to public interfaces. |
| `SECURELAB_ALLOW_PUBLIC_BIND` | No | `false` | Set `true` to allow binding `SECURELAB_HTTP_ADDR` to a public interface in strict mode. Requires explicit operator acknowledgement. |
| `SECURELAB_TARGET_CIDR_ALLOWLIST` | No | — | Comma-separated list of CIDRs that scenarios are permitted to target. Steps targeting hosts outside this list are rejected. Example: `192.168.100.0/24,10.10.0.0/16` |
| `SECURELAB_MAX_CONCURRENT_EXECUTIONS` | No | `3` | Maximum number of live scenario executions running simultaneously. |
| `SECURELAB_DRY_RUN_ONLY` | No | `false` | Set `true` to prevent any live execution from being dispatched, regardless of request body. Useful for initial setup validation. |

### Authentication

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_AUTH_TOKEN_TTL_S` | No | `3600` | Operator session token TTL in seconds. |
| `SECURELAB_AUTH_MAX_ATTEMPTS` | No | `5` | Maximum failed login attempts before account lockout. |
| `SECURELAB_AUTH_LOCKOUT_S` | No | `900` | Lockout duration in seconds after max failed attempts. |
| `SECURELAB_MFA_REQUIRED` | No | `false` | Enforce TOTP MFA for all operator logins. Recommended `true` in production. |

### CITADEL integration

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_CITADEL_API_URL` | No | — | CITADEL API base URL. If unset, CITADEL emission is disabled. |
| `SECURELAB_CITADEL_KEY_SECRET` | No | — | HMAC-SHA256 secret for signing `securelab.simulation` events. |
| `SECURELAB_CITADEL_PROJECT_ID` | No | — | CITADEL project identifier for event routing. |
| `SECURELAB_CITADEL_QUEUE_SIZE` | No | `1000` | Max in-memory event queue depth before backpressure. |
| `SECURELAB_CITADEL_CIRCUIT_BREAKER_THRESHOLD` | No | `5` | Consecutive failures before opening the circuit breaker. |

### OpenScrub integration (v1.0.0)

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_OPENSCRUB_API_URL` | No | — | OpenScrub API base URL. If unset, OpenScrub detection validation is disabled. |
| `SECURELAB_OPENSCRUB_KEY_SECRET` | No | — | HMAC-SHA256 secret for OpenScrub API requests. |
| `SECURELAB_OPENSCRUB_POLL_INTERVAL_S` | No | `5` | Poll interval for detection events during validation window. |
| `SECURELAB_OPENSCRUB_DETECTION_WINDOW_S` | No | `60` | Default window (seconds) after step dispatch to poll for detection. Overridable per scenario. |

### APIGuard integration (v1.0.0)

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_APIGUARD_API_URL` | No | — | APIGuard API base URL. If unset, APIGuard detection validation is disabled. |
| `SECURELAB_APIGUARD_KEY_SECRET` | No | — | HMAC-SHA256 secret for APIGuard API requests. |
| `SECURELAB_APIGUARD_DETECTION_WINDOW_S` | No | `60` | Default detection window in seconds. |

### ThreatFlow integration (v1.0.0)

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_THREATFLOW_API_URL` | No | — | ThreatFlow API base URL. |
| `SECURELAB_THREATFLOW_KEY_SECRET` | No | — | HMAC-SHA256 secret. |
| `SECURELAB_THREATFLOW_DETECTION_WINDOW_S` | No | `120` | Detection window for IOC match events (longer than others — IOC propagation is slower). |

### IRFlow integration (v1.0.0)

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_IRFLOW_API_URL` | No | — | IRFlow API base URL. |
| `SECURELAB_IRFLOW_KEY_SECRET` | No | — | HMAC-SHA256 secret. |

### Payload engine (Rust, v1.0.0)

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_PAYLOAD_MAX_SIZE_BYTES` | No | `65536` | Maximum payload size the Rust engine will generate. Prevents unbounded allocation. |
| `SECURELAB_PAYLOAD_FUZZING_MAX_VARIANTS` | No | `10000` | Maximum variants per fuzzing campaign. |
| `SECURELAB_PAYLOAD_STORE_PATH` | No | `./payload-store` | Path to the content-addressed payload store. Must be writable by the API and worker processes. |

## Config file (`config.yaml`)

Non-secret deployment configuration can be placed in `config.yaml`
alongside the application. Environment variables take precedence.

```yaml
# config.yaml — non-secret deployment configuration
# Secrets (keys, passwords, DSNs) must be in environment variables.

http_addr: "127.0.0.1:8087"
env: production
log_level: info

isolation:
  mode: strict
  allow_public_bind: false
  target_cidr_allowlist:
    - "192.168.100.0/24"
  max_concurrent_executions: 3
  dry_run_only: false

auth:
  token_ttl_s: 3600
  max_attempts: 5
  lockout_s: 900
  mfa_required: true

citadel:
  queue_size: 1000
  circuit_breaker_threshold: 5

openscrub:
  poll_interval_s: 5
  detection_window_s: 60

apiguard:
  detection_window_s: 60

threatflow:
  detection_window_s: 120

payload:
  max_size_bytes: 65536
  fuzzing_max_variants: 10000
  store_path: "/var/securelab/payload-store"
```

## Minimum configuration for v0.1.0 (no detection validation)

```bash
SECURELAB_DB_URL=postgres://securelab:pass@localhost:5432/securelab
SECURELAB_REDIS_URL=redis://localhost:6379/0
SECURELAB_SECRET_KEY=<generate with secrets.token_hex(32)>
SECURELAB_ISOLATION_MODE=strict
SECURELAB_TARGET_CIDR_ALLOWLIST=192.168.100.0/24
```

## Minimum configuration for v1.0.0 (full detection validation)

Add to the above:

```bash
SECURELAB_CITADEL_API_URL=https://citadel.internal
SECURELAB_CITADEL_KEY_SECRET=<hmac secret>
SECURELAB_CITADEL_PROJECT_ID=securelab-prod

SECURELAB_OPENSCRUB_API_URL=https://openscrub.internal
SECURELAB_OPENSCRUB_KEY_SECRET=<hmac secret>

SECURELAB_APIGUARD_API_URL=https://apiguard.internal
SECURELAB_APIGUARD_KEY_SECRET=<hmac secret>

SECURELAB_THREATFLOW_API_URL=https://threatflow.internal
SECURELAB_THREATFLOW_KEY_SECRET=<hmac secret>

SECURELAB_IRFLOW_API_URL=https://irflow.internal
SECURELAB_IRFLOW_KEY_SECRET=<hmac secret>

SECURELAB_MFA_REQUIRED=true
```

## Configuration validation

On startup, SecureLab validates its configuration and refuses to
start if required values are missing or if isolation constraints are
violated. Check the startup logs:

```bash
uv run uvicorn securelab.main:app --host 127.0.0.1 --port 8087
```

A misconfigured startup exits with a structured error:

```json
{
  "error": "configuration_error",
  "detail": "SECURELAB_DB_URL is required",
  "code": "E001"
}
```

## Go 1.22 backend — environment variables (v1.0.0)

The v1.0.0 Go implementation uses the following `SECURELAB_*` environment variable names. All are prefixed `SECURELAB_`.

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_HTTP_ADDR` | No | `127.0.0.1:8080` | HTTP listen address. Do not expose to `0.0.0.0` without TLS. |
| `SECURELAB_DEV_MODE` | No | `false` | Enable development mode: verbose logging, relaxed CORS. |
| `SECURELAB_DB_URL` | Yes | — | PostgreSQL DSN. |
| `SECURELAB_JWT_SECRET` | Yes | — | HMAC secret for JWT signing. Minimum 32 characters. |
| `SECURELAB_JWT_EXPIRY` | No | `24h` | JWT token lifetime. Go duration format. |
| `SECURELAB_CITADEL_URL` | No | — | CITADEL API base URL. |
| `SECURELAB_CITADEL_HMAC_SECRET` | No | — | HMAC-SHA256 secret for CITADEL event signing. |
| `SECURELAB_CITADEL_DRY_RUN` | No | `true` | When `true`, CITADEL events are logged but not sent. |
| `SECURELAB_OPENSCRUB_URL` | No | — | OpenScrub API base URL. |
| `SECURELAB_OPENSCRUB_API_KEY` | No | — | OpenScrub API key. |
| `SECURELAB_APIGUARD_URL` | No | — | APIGuard API base URL. |
| `SECURELAB_APIGUARD_API_KEY` | No | — | APIGuard API key. |
| `SECURELAB_THREATFLOW_URL` | No | — | ThreatFlow API base URL. |
| `SECURELAB_THREATFLOW_API_KEY` | No | — | ThreatFlow API key. |
| `SECURELAB_DETECTION_WINDOW` | No | `60s` | Detection window per step. Go duration format. |
| `SECURELAB_BLOCKED_TARGETS` | No | `production,prod,live` | Comma-separated blocked URL keywords. |
| `SECURELAB_MAX_CONCURRENT_RUNS` | No | `3` | Maximum concurrent scenario runs. |
| `SECURELAB_DEFAULT_STEP_TIMEOUT` | No | `5m` | Default per-step execution timeout. |

See `.env.example` for a complete example with comments, and `securelab.yaml.example` for the YAML config file format.

## Related

- [docs/deployment.md](deployment.md) — isolation architecture
- [docs/quick-start.md](quick-start.md) — local setup
- [docs/safety-controls.md](safety-controls.md) — safety controls
- [SECURITY.md](../SECURITY.md) — isolation and access control policy
