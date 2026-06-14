# NIS2 Compass

NIS2 Compass is a compliance management platform within the OpenSecStack suite that helps organisations subject to the EU NIS2 Directive (Directive 2022/2555) assess, track, and demonstrate adherence to the ten cybersecurity risk-management measures defined in Article 21(2). It provides a structured assessment workflow, a canonical control-template library derived from the directive text, and a REST API (port 8090) that exposes assessment state for integration with dashboards, ticketing systems, and audit toolchains.

---

## Quick Start (Development)

Prerequisites: Docker >= 24 and Docker Compose v2.

```bash
# 1. Clone the repository and enter the nis2compass directory.
git clone https://github.com/opensecstack/opensecstack.git
cd opensecstack/nis2compass

# 2. Start all services (API, Postgres, Redis, pgAdmin) with dev secrets.
docker compose -f docker-compose.dev.yml up --build

# 3. The seed service runs automatically after migrations.
#    To re-run seeds manually:
docker compose -f docker-compose.dev.yml run --rm seed

# 4. Access the API.
curl http://localhost:8090/health

# 5. Access pgAdmin (optional).
#    URL:      http://localhost:5051
#    Email:    dev@opensecstack.local
#    Password: pgadmindev
```

The development Compose file exposes Postgres on `localhost:5433` and Redis on `localhost:6380` for direct inspection.

---

## Authentication

NIS2 Compass authenticates users via sinauth SSO using OpenID Connect (authorization_code + PKCE).
RS256-signed tokens are validated against the sinauth JWKS endpoint via `app/sinauth.py`.
The web dashboard uses `sinauth.ts` for popup-based login and handles the OIDC callback.
See the [sinauth integration guide](../sinauth/docs/integration/nis2compass.md) for setup details.

---

## Environment Variables

### Production (`docker-compose.yml`)

All variables marked **required** must be set; the Compose file will refuse to start if they are absent.

| Variable | Required | Description |
|---|---|---|
| `POSTGRES_PASSWORD` | Yes | PostgreSQL superuser (`postgres`) password |
| `NIS2_DB_PASSWORD` | Yes | Password for the `nis2compass` application database user |
| `REDIS_PASSWORD` | Yes | Redis authentication password |
| `NIS2_SECRET_KEY` | Yes | Flask/application secret key (use a long random string) |
| `NIS2_JWT_SECRET` | Yes | JWT signing secret — minimum 32 characters |

### Development (`docker-compose.dev.yml`)

Hardcoded dev secrets are used. Do not deploy the dev Compose file to any environment accessible from outside localhost.

| Variable | Value |
|---|---|
| `NIS2_DB_PASSWORD` | `nis2compassdev` |
| `REDIS_PASSWORD` | `redisdev` |
| `NIS2_SECRET_KEY` | `dev-secret-key-do-not-use-in-production` |
| `NIS2_JWT_SECRET` | `dev-jwt-secret-32-chars-minimum-ok` |
| `NIS2_ENV` | `development` |
| `NIS2_DEBUG` | `true` |

---

## Database Schema

Five core tables are created by Alembic migrations and extended by the seed scripts.

| Table | Purpose |
|---|---|
| `control_templates` | Reference library of all 10 NIS2 Article 21(2) measures. Seeded by `seeds/01_nis2_controls.py`. Not organisation-specific. |
| `organisations` | Registered entities undergoing NIS2 assessment. Stores industry sector, country, size, and NIS2 entity type (`essential` / `important`). |
| `assessments` | One assessment per organisation per assessment cycle. Tracks framework version, assessor, and lifecycle status (`draft` → `in_progress` → `completed`). |
| `controls` | Per-assessment control entries, one row per Article 21(2) measure. Stores compliance status, evidence links, and reviewer notes. |
| `audit_log` | Immutable append-only log of all status changes and user actions against assessments and controls. |

---

## Running Migrations Manually

Migrations use Alembic. The `migrate` service in both Compose files runs `alembic upgrade head` automatically on startup.

To run migrations outside Docker:

```bash
# Install dependencies.
pip install alembic psycopg2-binary sqlalchemy

# Export connection variables.
export NIS2_DB_HOST=localhost
export NIS2_DB_PORT=5433        # 5433 when using dev Compose port mapping
export NIS2_DB_USER=nis2compass
export NIS2_DB_PASSWORD=nis2compassdev
export NIS2_DB_NAME=nis2compass

# Apply all pending migrations.
cd nis2compass
alembic upgrade head

# Check current migration state.
alembic current

# Roll back one revision.
alembic downgrade -1
```

---

## Running Seeds

Seeds are idempotent — re-running them will not create duplicate rows.

```bash
# Install the only runtime dependency.
pip install psycopg2-binary

# Export connection variables (same as above).
export NIS2_DB_HOST=localhost
export NIS2_DB_PORT=5433
export NIS2_DB_USER=nis2compass
export NIS2_DB_PASSWORD=nis2compassdev
export NIS2_DB_NAME=nis2compass

cd nis2compass

# Seed 1: insert the 10 NIS2 Article 21(2) control templates.
python seeds/01_nis2_controls.py
# Output: Seeded 10 control templates.

# Seed 2: insert sample organisation, assessment, and 10 controls.
python seeds/02_sample_org.py
# Output: Seeded sample organisation, assessment, and 10 controls.
```

Seed 2 depends on the tables created by Seed 1 being present. Always run `01_nis2_controls.py` before `02_sample_org.py`, or run them in sequence via the `seed` service in `docker-compose.dev.yml`.

---

## API

The NIS2 Compass API listens on **port 8090** (both development and production).

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Liveness check — returns `{"status": "ok"}` |
| `/api/v1/controls` | GET | List all control templates |
| `/api/v1/organisations` | GET | List organisations |
| `/api/v1/organisations/{id}/assessments` | GET | List assessments for an organisation |
| `/api/v1/assessments/{id}/controls` | GET | List controls for an assessment |
| `/api/v1/assessments/{id}/controls/{ref}` | PATCH | Update control status and evidence |

Full OpenAPI specification is available at `http://localhost:8090/docs` when the API is running.

---

## Documentation Index

Detailed documentation lives in the `docs/` directory. The table below lists every document, sorted by topic.

| Document | Description |
|---|---|
| [quick-start.md](docs/quick-start.md) | Zero-to-first-assessment guide covering prerequisites, stack startup, and initial API calls |
| [user-guide.md](docs/user-guide.md) | End-user guide covering core concepts, organisations, assessments, and control workflows |
| [assessment-workflow.md](docs/assessment-workflow.md) | Step-by-step walkthrough of the complete NIS2 Article 21(2) compliance assessment process |
| [architecture.md](docs/architecture.md) | System overview — Flask API, PostgreSQL, Redis, Alembic migrations, and the CITADEL WORM audit subsystem |
| [schema-reference.md](docs/schema-reference.md) | Complete PostgreSQL 16 schema reference including ENUM types, tables, indexes, and constraints |
| [api-reference.md](docs/api-reference.md) | Full REST API reference with endpoints, request/response schemas, and JWT authentication details |
| [nis2-controls-reference.md](docs/nis2-controls-reference.md) | Canonical reference for all ten NIS2 Article 21(2) cybersecurity risk-management measures (a)-(j) |
| [security-model.md](docs/security-model.md) | Security architecture — authentication, secret management, database hardening, and CITADEL WORM audit chain |
| [audit-log.md](docs/audit-log.md) | Design, implementation, and operational use of the CITADEL WORM append-only audit log |
| [configuration.md](docs/configuration.md) | Environment variable reference for all runtime configuration across development, staging, and production |
| [deployment.md](docs/deployment.md) | Production deployment guide using Docker Compose, including TLS, secrets, and hardening steps |
| [migrations.md](docs/migrations.md) | Alembic database migration guide — migration chain, standard procedures, rolling upgrades, and emergency rollback |
| [integrations.md](docs/integrations.md) | Guide for connecting NIS2 Compass with external systems (ticketing, dashboards, SIEM) via the REST API |
| [runbook.md](docs/runbook.md) | Operations runbook — health checks, monitoring, backup, restore, and on-call procedures |
| [troubleshooting.md](docs/troubleshooting.md) | Common failure modes with symptoms, diagnosis steps, and resolutions |
| [versioning.md](docs/versioning.md) | Versioning policy, backwards compatibility guarantees, deprecation process, and SDK compatibility |
| [faq.md](docs/faq.md) | Frequently asked questions about NIS2 Compass, compliance scope, and operational concerns |
