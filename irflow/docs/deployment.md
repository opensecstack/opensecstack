# Deploying IRFlow

This document covers running IRFlow in production. For development
setup, see the root [CONTRIBUTING.md](../CONTRIBUTING.md). For the API
surface, see [api.md](./api.md).

## System requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 512 MiB | 1 GiB per replica |
| PostgreSQL | 14 | 16 |
| Go (for building) | 1.24 | 1.24 |
| Disk (ephemeral) | 100 MiB | 500 MiB |

IRFlow is I/O-bound on PostgreSQL. Size the DB for your incident
volume; IRFlow itself scales horizontally with no coordination.

## Configuration summary

Full reference: [../.env.example](../.env.example). The settings that
most deployments need to change:

| Variable | Required? | Notes |
|---|---|---|
| `IRFLOW_DB_*` | Required | Host, port, credentials for PostgreSQL |
| `IRFLOW_AUTH_SECRET` | Required in production | HS256 JWT signing key, ≥ 32 random bytes |
| `IRFLOW_AUTH_PEPPER` | Required when you enable API-key hashing | ≥ 16 random bytes, separate from `AUTH_SECRET` |
| `IRFLOW_CITADEL_API_URL` | Empty = local-only mode (no MARSHAL, no WORM) | Set this in production |
| `IRFLOW_CITADEL_KEY_SECRET` | Required when CITADEL is enabled | HMAC-SHA256 shared secret |
| `IRFLOW_NIS2_*` | Required for NIS2-significant orgs | `API_URL`, `API_KEY`, `ASSESSMENT_ID`, `MEASURE_REF` |
| `IRFLOW_WEBHOOK_*_SECRET` | Per-source, required for that source to be enabled | Empty secret → 503 on that endpoint |

Leaving `IRFLOW_AUTH_SECRET` empty auto-enables dev mode with a loud
warning — never run that way in production.

## Local docker-compose (dev and integration tests)

The shipped [docker-compose.test.yml](../docker-compose.test.yml) starts
a fresh Postgres on port 54832 for integration tests. A production-style
compose file looks like:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: irflow
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: irflow
    volumes:
      - postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD", "pg_isready", "-U", "irflow"]
      interval: 5s

  irflow-migrate:
    image: irflow:1.0.0
    depends_on: { postgres: { condition: service_healthy } }
    environment:
      IRFLOW_DB_HOST: postgres
      IRFLOW_DB_PASSWORD: ${DB_PASSWORD}
    command: ["migrate"]
    restart: "no"

  irflow:
    image: irflow:1.0.0
    depends_on:
      irflow-migrate: { condition: service_completed_successfully }
    env_file: [./irflow.env]
    ports: ["8083:8083"]

volumes:
  postgres-data: {}
```

## Kubernetes

A minimum production deployment needs:

1. **A Deployment** of the IRFlow image with 2+ replicas behind a
   Service. IRFlow is stateless; replicas share the same database.
2. **A migration Job** that runs `irflow migrate` before rolling out
   a new image version.
3. **A Secret** with all sensitive values (`IRFLOW_AUTH_SECRET`,
   `IRFLOW_CITADEL_KEY_SECRET`, `IRFLOW_WEBHOOK_*_SECRET`,
   `IRFLOW_DB_PASSWORD`, `IRFLOW_AUTH_PEPPER`).
4. **A ConfigMap** for non-sensitive config (hostnames, timeouts).
5. **A PostgreSQL** — managed (RDS, Cloud SQL, AlloyDB) preferred;
   `postgres-operator` or Zalando-postgres if self-hosted.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata: { name: irflow, labels: { app: irflow } }
spec:
  replicas: 2
  selector: { matchLabels: { app: irflow } }
  template:
    metadata: { labels: { app: irflow } }
    spec:
      containers:
      - name: irflow
        image: ghcr.io/opensecstack/irflow:1.0.0
        ports: [{ containerPort: 8083 }]
        envFrom:
        - configMapRef: { name: irflow-config }
        - secretRef:    { name: irflow-secrets }
        livenessProbe:  { httpGet: { path: /health, port: 8083 } }
        readinessProbe: { httpGet: { path: /health/detail, port: 8083 } }
        resources:
          requests: { cpu: "200m", memory: "256Mi" }
          limits:   { cpu: "1000m", memory: "1Gi" }
```

Run migrations as a one-shot Job keyed to the image tag:

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: irflow-migrate-1-0-0 }
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: migrate
        image: ghcr.io/opensecstack/irflow:1.0.0
        command: ["irflow", "migrate"]
        envFrom:
        - configMapRef: { name: irflow-config }
        - secretRef:    { name: irflow-secrets }
```

## Database

Initial migration:

```bash
irflow migrate
# applies migrations/*.sql in order, records versions in schema_migrations
```

The command is idempotent — running it against an up-to-date database
is a no-op with a single informational log line.

For backups, the WORM-sensitive tables are:

- `incidents` — primary records
- `incident_actions` — governed action log, links to CITADEL WORM IDs
- `ioc_enrichments` — IOC history
- `timeline_entries` — append-only per-incident timeline
- `playbooks` + `playbook_executions` — automation definitions and runs

All five are pure INSERT-heavy tables in normal operation. Daily pg_dump
or PITR is sufficient; point-in-time recovery adds forensic replay.

## Observability

Three endpoints matter for ops:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness probe — always 200 when the process is alive |
| `GET /health/detail` | Readiness — 200 when DB ping succeeds, 503 otherwise; includes `version`, `commit`, `built` |
| `GET /metrics` | Prometheus scrape endpoint, no auth |

Suggested alerts:

| Metric | Alert at |
|---|---|
| `irflow_http_requests_total{status="5.."}` rate | > 1% of total for 5 minutes |
| `irflow_governance_calls_total{result="failure"}` rate | > 0 sustained |
| `irflow_db_pool_connections{state="acquired"}` / `state="max"` | > 80% for 10 minutes |
| Absence of `irflow_incidents_created_total` during a normal business day | Upstream producers broken |

See the full metrics catalogue in [api.md § Metrics catalogue](./api.md#metrics-catalogue).

## Security checklist before going live

- [ ] `IRFLOW_AUTH_SECRET` set to ≥ 32 random bytes from a secret manager
- [ ] `IRFLOW_AUTH_PEPPER` set (if any API-key or password hashing is enabled)
- [ ] CITADEL integration enabled (`IRFLOW_CITADEL_*`) — local-only mode disables governance, which is almost never what you want in production
- [ ] NIS2 integration enabled (`IRFLOW_NIS2_*`) if your organisation is in scope
- [ ] All webhook sources configured with per-source secrets (`IRFLOW_WEBHOOK_APIGUARD_SECRET` etc.) — shared fallback secret is a legacy compatibility hook, not a recommendation
- [ ] TLS terminates at your ingress / load balancer
- [ ] PostgreSQL is on a private network, not reachable from the public internet
- [ ] Backups run at least daily, tested at least monthly
- [ ] `/metrics` is scraped by Prometheus but not exposed beyond the monitoring network
- [ ] Replica count ≥ 2 for availability

## Upgrading

IRFlow follows semantic versioning. For `1.x` upgrades:

1. Review [CHANGELOG.md](../CHANGELOG.md) for breaking changes (none within `1.x`).
2. Deploy the new image as a migration Job: `irflow migrate`.
3. Roll the Deployment forward (rolling update; replicas are stateless).
4. Watch `/health/detail` on each new pod — version reflects the new tag.

For `1.x → 2.0` (future), migration may require careful coordination
(e.g. single-writer transitions). The release notes will include an
upgrade runbook.

## Related

- [API reference](./api.md)
- [Architecture](./architecture.md)
- [Playbook authoring](./playbook-authoring.md)
- [Ecosystem deployment topology](../../docs/deployment-topology.md)
