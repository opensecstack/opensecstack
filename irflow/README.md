# IRFlow

**IRFlow** is the incident response workflow engine for the [OpenSecStack](https://github.com/opensecstack/opensecstack) ecosystem. It manages the full incident lifecycle — from detection through containment, eradication, recovery, and closure — while enforcing CITADEL governance and NIS2 Art. 23 compliance at every step.

## Key Features

- **CITADEL Governance** — every mutation (create, transition, action) is submitted as a MARSHAL Kerkese with dual-control verification and WORM-sealed audit trail.
- **NIS2 Art. 23 Compliance** — automatic notification-deadline tracking based on severity, with alerts when thresholds approach.
- **Structured Playbooks** — status-machine workflow (`open -> investigating -> contained -> eradicating -> recovering -> closed`) with guarded transitions.
- **IOC Enrichment** — attach indicators of compromise (IP, domain, hash, URL) with confidence scores and STIX bundles.
- **Timeline** — append-only chronological log of every action and event for post-incident review.
- **Multi-source Intake** — incidents can originate from APIGuard, CITADEL, ThreatFlow, or manual creation.

## Architecture

```
                    +-----------+
                    |  APIGuard |
                    +-----+-----+
                          |
  +----------+      +-----v-----+      +-----------+
  | ThreatFlow+----->   IRFlow   +----->  CITADEL   |
  +----------+      |  :8083    |      |  MARSHAL   |
                    +-----+-----+      +-----------+
                          |
                    +-----v-----+
                    | NIS2Compass|
                    +-----------+
```

## API Endpoints

| Method | Path                                  | Description                       |
|--------|---------------------------------------|-----------------------------------|
| GET    | `/healthz`                            | Health check                      |
| POST   | `/api/v1/incidents`                   | Create incident                   |
| GET    | `/api/v1/incidents`                   | List incidents (paginated)        |
| GET    | `/api/v1/incidents/{id}`              | Get incident                      |
| PATCH  | `/api/v1/incidents/{id}`              | Patch incident                    |
| DELETE | `/api/v1/incidents/{id}`              | Delete incident                   |
| POST   | `/api/v1/incidents/{id}/actions`      | Submit governed action            |
| GET    | `/api/v1/incidents/{id}/actions`      | List actions                      |
| POST   | `/api/v1/incidents/{id}/iocs`         | Add IOC enrichment                |
| GET    | `/api/v1/incidents/{id}/iocs`         | List IOCs                         |
| GET    | `/api/v1/incidents/{id}/timeline`     | Get timeline                      |

## Configuration

IRFlow reads configuration from environment variables (prefix `IRFLOW_`), a `irflow.yaml` file, or CLI flags.

| Variable                      | Default         | Description                       |
|-------------------------------|-----------------|-----------------------------------|
| `IRFLOW_SERVER_HOST`          | `0.0.0.0`      | Listen address                    |
| `IRFLOW_SERVER_PORT`          | `8083`          | Listen port                       |
| `IRFLOW_DB_HOST`              | `localhost`     | PostgreSQL host                   |
| `IRFLOW_DB_PORT`              | `5432`          | PostgreSQL port                   |
| `IRFLOW_DB_NAME`              | `irflow`        | Database name                     |
| `IRFLOW_DB_USER`              | `irflow`        | Database user                     |
| `IRFLOW_DB_PASSWORD`          |                 | Database password                 |
| `IRFLOW_DB_SSL_MODE`          | `disable`       | PostgreSQL SSL mode               |
| `IRFLOW_CITADEL_API_URL`     | `http://localhost:8082` | CITADEL endpoint          |
| `IRFLOW_CITADEL_KEY_ID`      |                 | CITADEL API key ID                |
| `IRFLOW_CITADEL_KEY_SECRET`  |                 | CITADEL API key secret            |
| `IRFLOW_CITADEL_PROJECT_ID`  |                 | CITADEL project ID                |
| `IRFLOW_CITADEL_DRY_RUN`    | `true`          | Skip actual CITADEL calls         |
| `IRFLOW_NIS2_API_URL`        | `http://localhost:8081` | NIS2 Compass endpoint     |
| `IRFLOW_NIS2_API_KEY`        |                 | NIS2 Compass API key              |
| `IRFLOW_WEBHOOK_SECRET`      |                 | Webhook HMAC secret               |
| `IRFLOW_WEBHOOK_CALLBACK_URL`|                 | Webhook callback URL              |

## Quick Start

```bash
# Build
make build

# Run database migrations (PostgreSQL must be running)
psql -U irflow -d irflow -f migrations/001_initial.sql

# Start the server
make run

# Or with Docker
docker build -t irflow .
docker run -p 8083:8083 irflow
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](docs/api.md) | IRFlow REST API reference |

## Development

```bash
make test    # run tests with race detector
make lint    # run golangci-lint
```

## Licence

AGPL-3.0 — see [LICENSE](LICENSE).
