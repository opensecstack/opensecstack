# SecureLab Quick Start

> **ACCESS CONTROL WARNING:** SecureLab contains offensive tooling.
> Before following any step in this guide, confirm that:
>
> 1. You are running SecureLab in an **isolated network segment** with
>    no routing to production systems or the public internet.
> 2. You have **explicit written authorisation** to execute scenarios
>    against the target systems in your configuration.
> 3. You have read [docs/deployment.md](deployment.md) and understand
>    the isolation requirements.
>
> If any of these conditions are not met, stop here.

This guide walks through running SecureLab locally for development
and initial evaluation. For production deployment, see
[docs/deployment.md](deployment.md).

## Prerequisites

| Tool | Minimum version | Purpose |
|---|---|---|
| Go | 1.22 | API server (`cmd/securelab`) |
| Rust + Cargo | 1.77 | `payload-gen` crate (standalone, unit-tested; not yet wired into the API) |
| Node.js | 20+ | Web dashboard (`web/`, React + Vite + TS) |
| Docker + Docker Compose | 24+ | Postgres + full container stack |
| `curl` | any | API smoke tests in this guide |

## Step 1 — Clone and configure

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

# Copy the example environment file
cp .env.example .env
```

Open `.env` and set the minimum required values (see
[docs/configuration.md](configuration.md) for the full list):

```bash
SECURELAB_DB_URL=postgres://securelab:changeme@localhost:5432/securelab?sslmode=disable
SECURELAB_JWT_SECRET=change-this-to-a-random-secret-at-least-32-chars
SECURELAB_CITADEL_URL=https://citadel.internal
SECURELAB_CITADEL_HMAC_SECRET=change-this-citadel-hmac-secret
SECURELAB_CITADEL_DRY_RUN=true
```

## Step 2 — Start the backing services

```bash
# Start Postgres via the dev compose file (see docker-compose.dev.yml)
docker compose -f docker-compose.dev.yml up -d
```

## Step 3 — Build and start the API server

```bash
go run ./cmd/server
```

Database migrations (embedded `*.sql` files under
`internal/db/migrations`) run automatically against `SECURELAB_DB_URL`
on every server start — there is no separate migration step. The
server listens on `SECURELAB_HTTP_ADDR` (default `:8085`; set
`SECURELAB_HTTP_ADDR=127.0.0.1:8080` to match the Docker Compose
default used elsewhere in this guide).

The `rust/payload-gen` crate builds independently and is not required
to start the API server:

```bash
cargo build -p payload-gen --release
```

## Step 6 — Health check

```bash
curl http://localhost:8080/health
```

Expected response shape (see `internal/api/handlers/health.go`):

```json
{
  "status": "ok",
  "db": true,
  "uptime_seconds": 12,
  "version": "1.0.0"
}
```

## Step 7 — List available scenarios

```bash
curl -H "Authorization: Bearer <your-jwt>" \
  http://localhost:8080/api/v1/scenarios
```

Requires an `analyst` role or higher (see
[docs/api.md](api.md) for authentication and RBAC details).

## Step 8 — Run your first scenario

```bash
curl -X POST http://localhost:8080/api/v1/scenarios/<scenario-id>/run \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <your-jwt>" \
     -d '{"environment_id": "env_test_01"}'
```

Requires an `operator` role or higher. See
[docs/scenario-spec.md](scenario-spec.md) for the YAML scenario
format and [docs/attack-library.md](attack-library.md) for built-in
attack types.

## Step 9 — View ATT&CK coverage

```bash
curl -H "Authorization: Bearer <your-jwt>" \
  http://localhost:8080/api/v1/coverage
```

See [docs/mitre-attack-coverage.md](mitre-attack-coverage.md).

## Step 10 — Open the dashboard

For local frontend development:

```bash
cd web
npm install
npm run dev
```

Navigate to `http://localhost:3085` (Vite dev server). In the
Docker Compose stack, the built dashboard is served on
`http://localhost:3000`.

## Next steps

- **Author a scenario:** [docs/scenario-authoring.md](scenario-authoring.md)
- **Configure detection validation:** [docs/configuration.md](configuration.md)
- **Deploy to a production-equivalent isolated environment:**
  [docs/deployment.md](deployment.md)
- **Understand ATT&CK coverage tracking:**
  [docs/mitre-attack-coverage.md](mitre-attack-coverage.md)
- **Emit evidence to CITADEL:**
  [docs/citadel-integration.md](citadel-integration.md)

## Common issues

**`go run ./cmd/server` fails to bind:**
Check that nothing else on the host is already bound to
`SECURELAB_HTTP_ADDR`.

**`cargo build -p payload-gen` fails:**
Ensure Rust 1.77+ is installed (`rustup update stable`). The
`payload-gen` crate has no Python/PyO3 dependency — it is a plain
Rust library.

**Server fails to apply migrations on startup:**
Verify `SECURELAB_DB_URL` is correct and that the Postgres container
is healthy (`docker compose -f docker-compose.dev.yml ps`).
