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
| Python | 3.12 | API server and scenario engine |
| Rust + Cargo | 1.77 | Payload engine |
| Docker + Docker Compose | 24+ | Postgres + Redis + container stack |
| `uv` | latest | Python dependency management (recommended) |
| `curl` | any | API smoke tests in this guide |

## Step 1 — Clone and configure

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

# Copy the example environment file
cp .env.example .env
```

Open `.env` and set the minimum required values:

```bash
# Database + broker
SECURELAB_DB_URL=postgres://securelab:securelab@localhost:5432/securelab
SECURELAB_REDIS_URL=redis://localhost:6379/0

# Isolation — strict mode enforces target scope validation.
# Do not set to 'permissive' without reading SECURITY.md § Isolation escape.
SECURELAB_ISOLATION_MODE=strict

# Integration endpoints — leave empty to skip integration validation.
# Detection validation (Module 4, v1.0.0) requires these to be set.
SECURELAB_CITADEL_API_URL=
SECURELAB_CITADEL_KEY_SECRET=
SECURELAB_OPENSCRUB_API_URL=
SECURELAB_OPENSCRUB_KEY_SECRET=
SECURELAB_APIGUARD_API_URL=
SECURELAB_APIGUARD_KEY_SECRET=
SECURELAB_THREATFLOW_API_URL=
SECURELAB_THREATFLOW_KEY_SECRET=
SECURELAB_IRFLOW_API_URL=
SECURELAB_IRFLOW_KEY_SECRET=
```

## Step 2 — Start the backing services

```bash
# Start Postgres and Redis only (no SecureLab API yet)
docker compose up -d securelab-postgres securelab-redis

# Wait for health checks to pass
docker compose ps
```

Expected output: both `securelab-postgres` and `securelab-redis`
show status `healthy`.

## Step 3 — Build the Python package and Rust payload engine

```bash
# Install Python dependencies
uv pip install -e ".[dev]"

# Build the Rust payload engine (PyO3 native extension)
cargo build -p payload-engine --release

# Or use the Makefile shortcut
make build
```

## Step 4 — Run database migrations

```bash
uv run alembic upgrade head
```

## Step 5 — Start the API server

```bash
make run
```

This starts the API server on `127.0.0.1:8087` with
`SECURELAB_ISOLATION_MODE=strict`.

In a second terminal, start the Celery worker:

```bash
uv run celery -A securelab.worker worker --loglevel=info
```

## Step 6 — Health check

```bash
curl http://localhost:8087/api/v1/health
```

Expected response:

```json
{
  "status": "ok",
  "db": "ok",
  "redis": "ok",
  "version": "1.0.0"
}
```

## Step 7 — List available scenarios

```bash
curl http://localhost:8087/api/v1/scenarios
```

Expected response (with example scenarios loaded):

```json
{
  "scenarios": [
    {
      "id": "01HX...",
      "slug": "T1059.001-powershell-exec",
      "title": "PowerShell Command Execution",
      "mitre_technique": "T1059.001",
      "tactic": "execution",
      "version": "1.0.0",
      "step_count": 3
    }
  ],
  "total": 1
}
```

## Step 8 — Fire your first scenario (dry run)

A dry run generates the execution plan and validates scope without
dispatching any payloads. Always run dry first.

```bash
curl -X POST http://localhost:8087/api/v1/scenarios/T1059.001-powershell-exec/execute \
     -H "Content-Type: application/json" \
     -H "Authorization: Bearer <your-token>" \
     -d '{
       "dry_run": true,
       "target_scope": ["192.168.100.0/24"],
       "notes": "Initial dry-run — quick start guide"
     }'
```

Expected response:

```json
{
  "execution_id": "01HY...",
  "scenario_id": "01HX...",
  "scenario_version": "1.0.0",
  "mode": "dry_run",
  "status": "completed",
  "plan": [
    {
      "step": 1,
      "primitive": "powershell-encoded-command",
      "target": "192.168.100.10",
      "payload_preview": "[redacted in dry-run]",
      "estimated_detection_window_s": 30
    }
  ]
}
```

## Step 9 — View ATT&CK coverage

```bash
curl http://localhost:8087/api/v1/coverage
```

Expected response:

```json
{
  "total_techniques": 1,
  "techniques_with_scenarios": 1,
  "techniques_with_passing_executions": 0,
  "coverage_pct": 0.0,
  "tactics": {
    "execution": { "total": 1, "covered": 1, "validated": 0 }
  }
}
```

Coverage percentage (`coverage_pct`) is computed from execution
results with `detection_verdict: detected`, not from the existence
of scenarios. A scenario with no passing live execution does not
count as validated coverage.

## Step 10 — Open the dashboard

Navigate to `http://localhost:3007` in a browser on the same
isolated network segment. The dashboard shows the scenario library,
ATT&CK coverage heatmap, and execution history.

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

**`make run` fails with "public interface" error:**
The API refuses to start if `SECURELAB_HTTP_ADDR` resolves to a
public interface in `strict` isolation mode. Set it to `127.0.0.1:8087`
or a private VLAN address.

**`cargo build -p payload-engine` fails:**
Ensure Rust 1.77+ is installed (`rustup update stable`) and that
the `pyo3` Python headers are available (set `PYO3_PYTHON` to the
path of your Python 3.12 binary).

**Celery worker connects but does not pick up tasks:**
Verify `SECURELAB_REDIS_URL` in `.env` matches the Redis container's
address and that the worker is using the same Redis URL as the API
server.

**`alembic upgrade head` fails:**
Verify `SECURELAB_DB_URL` is correct and that `securelab-postgres`
is healthy (`docker compose ps`). The database must exist and the
service role must have CREATE TABLE privileges.
