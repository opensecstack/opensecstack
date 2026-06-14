# CyberPath — Deployment

CyberPath supports two first-class deployment paths. Pick the one
that matches your environment:

| Path | Use when | Guide |
|---|---|---|
| Docker Compose (single host) | Pilots, single-team rollouts, air-gapped demos | This document |
| Helm / Kubernetes | Multi-tenant production, HA, multi-AZ | [deployment-helm.md](deployment-helm.md) |

For the local dev path, see [quick-start.md](quick-start.md). For the
full env-var reference, see [configuration.md](configuration.md).

## Topology — single host

```
                Internet / VPN
                      │
                      ▼
            ┌────────────────────┐
            │  Caddy / nginx     │  TLS termination
            │  :443 → :8086,3006 │  reverse proxy
            └────────┬───────────┘
                     │
       ┌─────────────┼──────────────┐
       ▼             ▼              ▼
  ┌─────────┐  ┌──────────┐   ┌──────────┐
  │ api:8086│  │ web:3006 │   │ /metrics │
  │ (Go)    │  │ (Vite)   │   │ scrape   │
  └────┬────┘  └──────────┘   └──────────┘
       │
       ▼
  ┌─────────────────┐       ┌────────────────┐
  │ Postgres 16     │       │ Lab runtime    │
  │ (external,      │       │ (Docker socket │
  │  managed)       │       │  on host)      │
  └─────────────────┘       └────────────────┘
```

The shipped `docker-compose.yml` brings up `api`, `web`, and a
local `db` for development. **For production, run Postgres
externally** (managed RDS, Cloud SQL, on-prem cluster) and disable
the bundled `db` service.

## Step 1 — Provision the host

Minimum:

- 4 vCPU, 8 GiB RAM, 40 GiB disk for ~200 concurrent learners and
  ~10 concurrent Docker labs
- Docker Engine 24+ with the daemon configured for live restore
- A non-root deploy user in the `docker` group
- Firewall: `:443` only; `:8086`/`:3006` not exposed externally

## Step 2 — External Postgres

Provision Postgres 16 with a dedicated database and role:

```sql
CREATE ROLE cyberpath WITH LOGIN PASSWORD '<random>';
CREATE DATABASE cyberpath OWNER cyberpath;
GRANT CONNECT ON DATABASE cyberpath TO cyberpath;
```

Require TLS (`ssl=on` server-side, `sslmode=verify-full` from
CyberPath) and confirm reachability from the deploy host:

```bash
psql "postgres://cyberpath:***@db.internal:5432/cyberpath?sslmode=verify-full" -c "select 1;"
```

Migrations are auto-applied on first boot; ensure the runtime role
has DDL on its schema. For locked-down environments, set
`CYBERPATH_DB_MIGRATE_ON_BOOT=false` and apply
`internal/db/migrations/*.sql` out of band as a privileged role.

## Step 3 — Sealed secrets

Do not commit secrets to the deploy directory. Use one of:

- **`docker compose --env-file`** with the env file owned by
  `root:docker`, mode `0640`, sourced from a secret manager (Vault
  AppRole, AWS Secrets Manager, sops-encrypted file).
- **Filesystem secrets** mounted at `/run/secrets/cyberpath/*`,
  exported into the container env via a small entrypoint shim.

Required keys at minimum:

```
CYBERPATH_DB_URL
CYBERPATH_AUTH_SECRET
CYBERPATH_CITADEL_KEY_SECRET    # if CITADEL configured
CYBERPATH_IRFLOW_WEBHOOK_SECRET # if IRFlow configured
CYBERPATH_CERT_SIGNING_KEY      # KMS reference, v1.0.0+
```

Rotation cadence: `AUTH_SECRET` annually; HMAC secrets quarterly;
KMS-backed cert key per the KMS policy (typically annually).

## Step 4 — TLS termination

Run Caddy or nginx in front of CyberPath. Caddy example:

```caddy
cyberpath.example.com {
    encode zstd gzip

    # API
    reverse_proxy /api/* http://localhost:8086

    # Lab WebSocket
    reverse_proxy /api/v1/labs/*/terminal http://localhost:8086 {
        header_up Host {host}
    }

    # Web UI
    reverse_proxy /* http://localhost:3006

    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains"
        X-Frame-Options "DENY"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "no-referrer"
    }
}
```

`/healthz` is unauthenticated by design; firewall it to internal IPs
or allow it externally — your call. `/metrics` should be
firewalled to the Prometheus scrape source.

## Step 5 — Compose file (production overlay)

Author `docker-compose.prod.yml` alongside the shipped dev compose:

```yaml
services:
  api:
    image: ghcr.io/opensecstack/cyberpath:1.0.0
    restart: unless-stopped
    env_file: /etc/cyberpath/cyberpath.env
    ports:
      - "127.0.0.1:8086:8086"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - /var/lib/cyberpath/content:/var/lib/cyberpath/content:ro
      - /var/lib/cyberpath/citadel-wal:/var/lib/cyberpath/citadel-wal
    logging:
      driver: json-file
      options: { max-size: "50m", max-file: "10" }
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://localhost:8086/readyz"]
      interval: 30s
      timeout: 5s
      retries: 3

  web:
    image: ghcr.io/opensecstack/cyberpath-web:1.0.0
    restart: unless-stopped
    ports:
      - "127.0.0.1:3006:3006"
    environment:
      - CYBERPATH_API_URL=https://cyberpath.example.com
```

Bring up:

```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
docker compose ps
curl -sf https://cyberpath.example.com/readyz | jq .
```

## Step 6 — Log shipping

CyberPath emits structured JSON via zerolog on stdout. Pick a
shipper:

- **Vector / Fluent Bit** — tail the docker `json-file` log path,
  ship to Loki / Elasticsearch / S3.
- **journald driver** — switch the `logging.driver` to `journald`
  and use `systemd-journal-remote`.

Example Vector source:

```toml
[sources.cyberpath]
type    = "docker_logs"
include_containers = ["cyberpath-api-1", "cyberpath-web-1"]
```

Ensure JSON parsing happens on the shipper, not in CyberPath; the
emitted records are already structured.

## Step 7 — Prometheus scrape

`/metrics` is unauthenticated and on the API port (matches ecosystem
convention). Scrape config:

```yaml
scrape_configs:
  - job_name: cyberpath
    metrics_path: /metrics
    static_configs:
      - targets: ["cyberpath-host.internal:8086"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
```

Key series to alert on:

- `cyberpath_citadel_queue_depth` — sustained > 800 means CITADEL is
  unreachable; the local WAL is filling
- `cyberpath_lab_session_failures_total` — non-zero rate means a lab
  image isn't pulling or the runtime is broken
- `cyberpath_http_request_duration_seconds{handler="/api/v1/lessons/{id}/complete",quantile="0.99"}` — p99 > 500ms is a DB
  latency canary
- `cyberpath_content_version_mismatch_total` — non-zero means
  imported content drifted from disk; investigate immediately

## Step 8 — Backups

Postgres is the source of truth. Recommended cadence:

```bash
# Logical backup, daily, retained 30d, encrypted at rest
PGPASSWORD=*** pg_dump \
  --host db.internal --user cyberpath \
  --format=custom --compress=9 \
  cyberpath > /backups/cyberpath-$(date +%F).dump.gpg
```

Restore drill (quarterly):

```bash
pg_restore --host db.internal --user cyberpath \
  --dbname=cyberpath --clean --if-exists \
  /backups/cyberpath-YYYY-MM-DD.dump
```

If CITADEL is enabled, the `cyberpath.completion` events are
mirrored immutably upstream; a partial restore can be reconciled
from the CITADEL ledger via `make reconcile-citadel`.

Content directory backup: rsync `/var/lib/cyberpath/content` to a
versioned bucket. Content is append-only by convention (Module 8) so
diff-based backups are small.

## Upgrade

```bash
# Pull new image
docker compose -f docker-compose.yml -f docker-compose.prod.yml pull api web

# Rolling-style restart (compose swaps containers in-place)
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

For schema-breaking releases, the changelog calls out the migration
strategy. Major bumps (e.g. v0.x → v1.0.0) require offline
migration; the upgrade notes ship with the release tag.

Rollback: pin the previous image tag in `docker-compose.prod.yml`
and `up -d`. Schema migrations are forward-compatible across patch
and minor releases per the versioning policy.

## Disaster recovery

Critical state:

- `users`, `paths`, `lessons`, `quizzes`, `progress`, `completions`,
  `certifications`, `lab_sessions`, `content_versions` tables
- The Ed25519 cert signing key (KMS-resident; document the
  emergency unwrap procedure separately)
- The CITADEL local WAL (`CYBERPATH_CITADEL_WAL_PATH`) — flushed on
  next startup

Detailed DR procedure (RPO / RTO targets, failover steps) lands at
`docs/operator-handbook.md` with v1.0.0.

## See also

- [quick-start.md](quick-start.md)
- [configuration.md](configuration.md)
- [deployment-helm.md](deployment-helm.md)
- [troubleshooting.md](troubleshooting.md)
- [citadel-integration.md](citadel-integration.md)
- [architecture.md](architecture.md)
