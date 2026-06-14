# NIS2 Compass — Configuration Reference

## Overview

All runtime configuration for NIS2 Compass is injected through environment variables. There are no configuration files read at application startup in production. The only file-based configuration is `alembic.ini`, which is used exclusively by the Alembic migration runner and references the same `NIS2_DB_*` environment variables described in this document.

This approach means that the same container image can be deployed in development, staging, and production without modification. The environment provides the secrets; the image provides the behaviour.

---

## Application Environment Variables

The following variables are consumed by the Flask application at startup. Variables marked **Yes** in the Required column must be present or the application will not start correctly.

| Variable | Required | Default | Description |
|---|---|---|---|
| `NIS2_DB_URL` | Yes (prod) | — | Full SQLAlchemy database URL. When set, this overrides all individual `NIS2_DB_*` component variables. Format: `postgresql+psycopg2://user:password@host:port/dbname` |
| `NIS2_DB_HOST` | No | `localhost` | PostgreSQL hostname. Ignored if `NIS2_DB_URL` is set. |
| `NIS2_DB_PORT` | No | `5432` | PostgreSQL port number. Ignored if `NIS2_DB_URL` is set. |
| `NIS2_DB_USER` | No | `nis2compass` | PostgreSQL username for the application database user. Ignored if `NIS2_DB_URL` is set. |
| `NIS2_DB_PASSWORD` | Yes | — | Password for the `nis2compass` PostgreSQL user. Required whether using `NIS2_DB_URL` or the individual `NIS2_DB_*` variables. |
| `NIS2_DB_NAME` | No | `nis2compass` | PostgreSQL database name. Ignored if `NIS2_DB_URL` is set. |
| `NIS2_REDIS_URL` | Yes (prod) | — | Redis connection URL. Format: `redis://:password@host:port/db`. Example: `redis://:s3cret@redis:6379/0` |
| `NIS2_SECRET_KEY` | Yes | — | Flask application secret key. Used to sign session cookies. Must be a cryptographically random string of at least 32 characters. |
| `NIS2_JWT_SECRET` | Yes | — | Secret used to sign and verify JWT tokens. Minimum 32 characters. Rotating this value invalidates all existing tokens. |
| `NIS2_ENV` | No | `production` | Deployment environment name. Accepts `development` or `production`. Controls environment-specific behaviour such as error detail verbosity. |
| `NIS2_DEBUG` | No | `false` | Enables Flask debug mode, including the interactive debugger and auto-reloader. Must be `false` in all non-local deployments. |
| `NIS2_PORT` | No | `8090` | TCP port the API process binds to inside the container. The Docker Compose files map this to port 8090 on the host. |
| `NIS2_LOG_LEVEL` | No | `INFO` | Application log level. Accepts `DEBUG`, `INFO`, `WARNING`, or `ERROR`. Use `DEBUG` only in local development. |
| `NIS2_MAX_UPLOAD_BYTES` | No | `20971520` | Maximum size in bytes of an artifact file upload. Default is 20 MB (20 × 1024 × 1024). Increase with caution — larger values increase memory pressure under concurrent uploads. |
| `NIS2_JWT_TTL` | No | `3600` | JWT token lifetime in seconds. Default is 1 hour. Rotating this value does not invalidate existing tokens — tokens remain valid until their embedded `exp` claim expires. |
| `NIS2_RATE_LIMIT` | No | `100` | Maximum number of requests per minute per source IP address for the sliding-window rate limiter. Requests exceeding this limit receive a 429 response with a `Retry-After` header. |
| `POSTGRES_PASSWORD` | Yes (prod Compose) | — | PostgreSQL superuser (`postgres`) password. Consumed by the `postgres` service in `docker-compose.yml` to initialise the database cluster. Not read by the Flask application directly. |
| `REDIS_PASSWORD` | Yes (prod Compose) | — | Redis authentication password. Passed to the `redis` service via `redis-server --requirepass`. Must match the password component of `NIS2_REDIS_URL`. |

---

## Alembic / Migration Variables

The `migrate` service and the `migrations/env.py` script consume the `NIS2_DB_*` component variables directly. The `alembic.ini` file defines the connection URL as an interpolated template:

```
sqlalchemy.url = postgresql+psycopg2://%(DB_USER)s:%(DB_PASSWORD)s@%(DB_HOST)s:%(DB_PORT)s/%(DB_NAME)s
```

`migrations/env.py` maps environment variables to these template placeholders at runtime:

| Environment Variable | Alembic Placeholder | Default in env.py |
|---|---|---|
| `NIS2_DB_USER` | `%(DB_USER)s` | `nis2compass` |
| `NIS2_DB_PASSWORD` | `%(DB_PASSWORD)s` | `nis2compass` |
| `NIS2_DB_HOST` | `%(DB_HOST)s` | `localhost` |
| `NIS2_DB_PORT` | `%(DB_PORT)s` | `5432` |
| `NIS2_DB_NAME` | `%(DB_NAME)s` | `nis2compass` |

The migration runner does not use `NIS2_DB_URL`. Always provide the individual `NIS2_DB_*` variables to the `migrate` service, even when the application itself uses `NIS2_DB_URL`.

---

## Generating Secrets

Use the commands below to generate cryptographically random values for each secret variable. Run these once per deployment and store the results in your secret manager (Vault, AWS Secrets Manager, Doppler, or similar). Do not commit them to version control.

```bash
# NIS2_SECRET_KEY — 64 hex characters (256 bits of entropy)
openssl rand -hex 32

# NIS2_JWT_SECRET — 64 hex characters (256 bits of entropy)
openssl rand -hex 32

# NIS2_DB_PASSWORD and REDIS_PASSWORD — 48 hex characters (192 bits of entropy)
openssl rand -hex 24
```

Generate a separate value for each variable. Do not reuse the same random string across multiple secrets.

---

## Development Defaults

The `docker-compose.dev.yml` file uses hardcoded values for all secrets. These are shown below for reference. They must never be used in any environment accessible from outside localhost.

> **Warning:** The values in this table are public knowledge — they appear in the open-source repository. Any deployment that uses them is trivially compromised.

| Variable | Hardcoded development value |
|---|---|
| `NIS2_DB_URL` | `postgresql+psycopg2://nis2compass:nis2compassdev@postgres:5432/nis2compass` |
| `NIS2_REDIS_URL` | `redis://:redisdev@redis:6379/0` |
| `NIS2_DB_PASSWORD` | `nis2compassdev` |
| `REDIS_PASSWORD` | `redisdev` |
| `NIS2_SECRET_KEY` | `dev-secret-key-do-not-use-in-production` |
| `NIS2_JWT_SECRET` | `dev-jwt-secret-32-chars-minimum-ok` |
| `NIS2_ENV` | `development` |
| `NIS2_DEBUG` | `true` |

In development, PostgreSQL is exposed on host port `5433` and Redis on host port `6380` to avoid conflicts with any locally installed instances. pgAdmin is available at `http://localhost:5051` (email: `dev@opensecstack.local`, password: `pgadmindev`).

---

## Production `.env` Template

The following template can be used as the basis for a `.env` file loaded by Docker Compose in production. Replace every placeholder value with a real secret generated using the commands in the [Generating Secrets](#generating-secrets) section above.

Add `.env` to `.gitignore` before creating this file. Never commit it.

```dotenv
# NIS2 Compass — Production environment variables
# Generated: see docs/configuration.md — Generating Secrets

# PostgreSQL superuser password (used by the postgres service to initialise the cluster)
POSTGRES_PASSWORD=REPLACE_WITH_STRONG_RANDOM_VALUE

# Application database user password
# Must match the password embedded in NIS2_DB_URL
NIS2_DB_PASSWORD=REPLACE_WITH_STRONG_RANDOM_VALUE

# Full SQLAlchemy database URL for the Flask application
# Constructed from the NIS2_DB_PASSWORD above
NIS2_DB_URL=postgresql+psycopg2://nis2compass:REPLACE_WITH_STRONG_RANDOM_VALUE@postgres:5432/nis2compass

# Redis password — must match the password in NIS2_REDIS_URL
REDIS_PASSWORD=REPLACE_WITH_STRONG_RANDOM_VALUE

# Full Redis connection URL for the Flask application
NIS2_REDIS_URL=redis://:REPLACE_WITH_STRONG_RANDOM_VALUE@redis:6379/0

# Flask application secret key — minimum 32 characters, cryptographically random
NIS2_SECRET_KEY=REPLACE_WITH_STRONG_RANDOM_VALUE

# JWT signing secret — minimum 32 characters, cryptographically random
NIS2_JWT_SECRET=REPLACE_WITH_STRONG_RANDOM_VALUE

# Optional overrides (defaults shown)
# NIS2_ENV=production
# NIS2_DEBUG=false
# NIS2_PORT=8090
# NIS2_LOG_LEVEL=INFO
# NIS2_MAX_UPLOAD_BYTES=20971520
# NIS2_JWT_TTL=3600
# NIS2_RATE_LIMIT=100
```
