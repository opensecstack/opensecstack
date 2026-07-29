# SecureLab Configuration

SecureLab (Go 1.22, `cmd/server`) is configured entirely through
environment variables, all prefixed `SECURELAB_`. There is no
`config.yaml` file — configuration is env-var only (see
`internal/config/config.go`).

> **Security note:** Never commit secrets (JWT secret, CITADEL HMAC
> secrets, database DSN) to version control. Use environment
> variables, a secrets manager, or Docker secrets.

## Environment variables read by `internal/config`

| Variable | Required | Default | Description |
|---|:-:|---|---|
| `SECURELAB_HTTP_ADDR` | No | `:8085` | HTTP listen address. The shipped `docker-compose.yml` overrides this to `0.0.0.0:8080` inside the container, published as `127.0.0.1:8080` on the host. |
| `SECURELAB_DEV_MODE` | No | `false` | Boolean. When `true`, `Validate()` skips the production strictness checks below. |
| `SECURELAB_DB_URL` | Yes | — | PostgreSQL DSN. Required in all modes. |
| `SECURELAB_DB_MAX_CONNS` | No | `8` | Max PostgreSQL connections in the pool. |
| `SECURELAB_JWT_SECRET` | Yes (unless `DEV_MODE=true`) | — | HMAC secret for JWT signing. Must be at least 32 bytes in production mode. |
| `SECURELAB_JWT_ISSUER` | No | `securelab` | JWT `iss` claim. |
| `SECURELAB_TOKEN_TTL` | No | `12h` | JWT token lifetime, Go duration format. |
| `SECURELAB_CITADEL_API_URL` | No | — | CITADEL API base URL. When set and `CITADEL_DRY_RUN=false`, run-completion events are forwarded to CITADEL. |
| `SECURELAB_CITADEL_HMAC_SECRETS` | Required if `CITADEL_DRY_RUN=false` and `CITADEL_API_URL` is set | — | Comma-separated list of HMAC-SHA256 secrets for signing CITADEL events; the first is used to sign. |
| `SECURELAB_CITADEL_DRY_RUN` | No | `true` | When `true`, CITADEL emission is skipped even if a URL is configured. |
| `SECURELAB_NODE` | No | `securelab-0` | Node identifier used in internal bookkeeping. |
| `SECURELAB_OUTBOX_TICK` | No | `10s` | Outbox processing interval, Go duration format. |
| `SECURELAB_MAX_CONCURRENT_SCENARIOS` | No | `3` | Maximum concurrent scenario executions. |
| `SECURELAB_SCENARIO_TIMEOUT` | No | `5m` | Default per-scenario execution timeout. |
| `SECURELAB_SINAUTH_URL` | No | `http://localhost:8100` | sinauth SSO base URL for RS256 token validation. |

## Detection-platform URLs (read directly by `cmd/server`)

These are read via `os.Getenv` in `cmd/server/main.go`, not through
`internal/config`, and wire the detection monitor to the platforms it
polls:

| Variable | Description |
|---|---|
| `SECURELAB_OPENSCRUB_URL` | OpenScrub API base URL. Empty disables OpenScrub polling. |
| `SECURELAB_APIGUARD_URL` | APIGuard API base URL. Empty disables APIGuard polling. |
| `SECURELAB_THREATFLOW_URL` | ThreatFlow API base URL. Empty disables ThreatFlow polling. |

> **Note:** `.env.example` and `docker-compose.yml` also define
> `SECURELAB_*_API_KEY` variables and a `SECURELAB_CITADEL_HMAC_SECRET`
> (singular) for these integrations. The current `cmd/server` build
> does not read API-key or singular-secret variables for these three
> integrations — only the URL and the plural
> `SECURELAB_CITADEL_HMAC_SECRETS`. Treat `internal/config/config.go`
> as the source of truth for what the running binary actually
> consumes.

## Minimum configuration (dry-run, no detection validation)

```bash
SECURELAB_DB_URL=postgres://securelab:changeme@localhost:5432/securelab?sslmode=disable
SECURELAB_JWT_SECRET=<32+ random bytes, e.g. openssl rand -hex 32>
SECURELAB_CITADEL_DRY_RUN=true
```

## Full configuration (CITADEL + detection validation enabled)

Add to the above:

```bash
SECURELAB_CITADEL_API_URL=https://citadel.internal
SECURELAB_CITADEL_HMAC_SECRETS=<hmac secret>
SECURELAB_CITADEL_DRY_RUN=false

SECURELAB_OPENSCRUB_URL=https://openscrub.internal
SECURELAB_APIGUARD_URL=https://apiguard.internal
SECURELAB_THREATFLOW_URL=https://threatflow.internal

SECURELAB_SINAUTH_URL=https://auth.sin.to
```

## Configuration validation

On startup, `Config.Validate()` fails fast if:

- `SECURELAB_DB_URL` is unset (always required).
- `SECURELAB_DEV_MODE` is not `true` and `SECURELAB_JWT_SECRET` is
  shorter than 32 bytes.
- `SECURELAB_DEV_MODE` is not `true`, `SECURELAB_CITADEL_DRY_RUN` is
  `false`, and no `SECURELAB_CITADEL_HMAC_SECRETS` is set.

A failed validation logs the error(s) and the process exits — see
`internal/config/config.go` for the exact error strings.

## Related

- [docs/deployment.md](deployment.md) — isolation architecture
- [docs/quick-start.md](quick-start.md) — local setup
- [docs/safety-controls.md](safety-controls.md) — safety controls
- [SECURITY.md](../SECURITY.md) — isolation and access control policy
- `.env.example` — example environment file (see note above on
  variables it defines that the binary does not yet consume)
