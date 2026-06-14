# NIS2 Compass — Production Deployment Guide

This guide covers deploying NIS2 Compass to a production environment using Docker Compose. It assumes familiarity with Linux system administration, Docker, and basic PostgreSQL operations.

For local development, use `docker-compose.dev.yml` instead. The development Compose file uses hardcoded secrets and must never be deployed to any environment accessible from outside localhost.

---

## Prerequisites

- Docker Engine >= 24
- Docker Compose v2 (`docker compose` command, not the legacy `docker-compose`)
- A domain name with a valid TLS certificate (Let's Encrypt, or your organisation's CA)
- nginx or Traefik configured as a reverse proxy
- A secrets management approach: a `.env` file (chmod 600), Docker secrets, Kubernetes Secrets, or a vault (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- Outbound internet access from the Docker host to pull images from `ghcr.io`

---

## Infrastructure Requirements

| Component | Minimum RAM | Minimum vCPU | Minimum storage |
|---|---|---|---|
| `nis2compass-api` container | 512 MB | 0.5 vCPU | — |
| `postgres` container | 2 GB | 2 vCPU | 20 GB SSD (scale with artifact volume) |
| `redis` container | 256 MB | 0.25 vCPU | — |
| Reverse proxy (nginx/Traefik) | 128 MB | 0.25 vCPU | — |

Storage sizing note: the 20 GB figure covers the database itself plus WAL segments. Artifact files (policy documents, evidence PDFs, certificates) are referenced by path in the `artifacts` table. If artifacts are stored on the same host, add storage proportional to expected upload volume. Consider mounting a dedicated volume or using object storage (S3, Azure Blob) for artifacts.

The `audit_log` table grows indefinitely (rows are never deleted). Plan for at least 1 GB of audit log storage per year for an active deployment with multiple organisations. See the archival guidance in [audit-log.md](audit-log.md).

---

## Step 1: Prepare Secrets

Generate all required secrets before starting any containers.

```bash
# Generate each secret as a 64-character hex string (256 bits of entropy).
POSTGRES_PASSWORD=$(openssl rand -hex 32)
NIS2_DB_PASSWORD=$(openssl rand -hex 32)
REDIS_PASSWORD=$(openssl rand -hex 32)
NIS2_SECRET_KEY=$(openssl rand -hex 32)
NIS2_JWT_SECRET=$(openssl rand -hex 32)

# Write to a .env file with restricted permissions.
cat > .env <<EOF
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
NIS2_DB_PASSWORD=${NIS2_DB_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
NIS2_SECRET_KEY=${NIS2_SECRET_KEY}
NIS2_JWT_SECRET=${NIS2_JWT_SECRET}
EOF

chmod 600 .env
```

Ensure `.env` is in `.gitignore` before running any `git add` commands:

```bash
echo '.env' >> .gitignore
```

Verify it is ignored:

```bash
git check-ignore -v .env
# Expected output: .gitignore:1:.env    .env
```

If the file has already been committed, remove it from the repository history before proceeding.

---

## Step 2: Configure the Reverse Proxy

The API container listens on port 8090. TLS must be terminated at the reverse proxy. The following nginx configuration handles TLS termination and proxies requests to the API.

```nginx
server {
    listen 80;
    server_name nis2compass.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name nis2compass.example.com;

    ssl_certificate     /etc/ssl/certs/nis2compass.crt;
    ssl_certificate_key /etc/ssl/private/nis2compass.key;

    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header X-Frame-Options           "DENY" always;
    add_header Referrer-Policy           "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass         http://localhost:8090;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Replace `nis2compass.example.com` and the certificate paths with your actual values. Test the nginx configuration before reloading:

```bash
nginx -t
nginx -s reload
```

---

## Step 3: Pull and Start Services

```bash
# Pull the latest images without starting containers.
docker compose --env-file .env pull

# Start all services in detached mode.
docker compose --env-file .env up -d
```

The startup order enforced by `depends_on` conditions is:

1. `postgres` starts and passes its healthcheck (`pg_isready`).
2. `redis` starts and passes its healthcheck.
3. `migrate` runs `alembic upgrade head` and exits with code 0.
4. `nis2compass-api` starts.

Verify all services are healthy:

```bash
docker compose ps
```

Expected output:

```
NAME                    IMAGE                                      STATUS
nis2compass-api         ghcr.io/opensecstack/nis2compass:latest    running (healthy)
nis2compass-migrate-1   python:3.12-slim                           exited (0)
nis2compass-postgres-1  postgres:16-alpine                         running (healthy)
nis2compass-redis-1     redis:7-alpine                             running (healthy)
```

The `migrate` service should show `exited (0)`. Any non-zero exit code means migrations failed — check logs before proceeding.

Tail recent logs for all services:

```bash
docker compose logs --tail=50
```

Tail logs for a specific service:

```bash
docker compose logs --tail=100 nis2compass-api
docker compose logs --tail=100 postgres
```

---

## Step 4: Verify Migrations Ran

```bash
docker compose logs migrate
```

Successful output will contain lines similar to:

```
INFO  [alembic.runtime.migration] Context impl PostgreSQLImpl.
INFO  [alembic.runtime.migration] Will assume transactional DDL.
INFO  [alembic.runtime.migration] Running upgrade  -> 001, Create organisations and assessments tables
INFO  [alembic.runtime.migration] Running upgrade 001 -> 002, Create controls and artifacts tables
INFO  [alembic.runtime.migration] Running upgrade 002 -> 003, Create audit_log table with CITADEL WORM immutability
```

If the output ends with `Running upgrade` lines for each revision and no `ERROR` lines, migrations are complete. If you see `Target database is not up to date` or a Python traceback, resolve the error before starting the API.

To check the current migration state manually:

```bash
docker compose run --rm migrate alembic current
```

---

## Step 5: Verify the API

```bash
curl -s https://nis2compass.example.com/health
```

Expected response:

```json
{"status": "ok"}
```

A `200 OK` with this body confirms the API is running, the database connection is healthy, and Redis is reachable. Any other response or a connection error indicates a configuration problem — check `docker compose logs nis2compass-api`.

---

## Database Backup

### Manual Backup

```bash
docker exec nis2compass-postgres-1 \
  pg_dump -U postgres -d nis2compass -F c -f /tmp/nis2compass_$(date +%Y%m%d_%H%M%S).dump

# Copy the dump file from the container to the host.
docker cp nis2compass-postgres-1:/tmp/nis2compass_*.dump ./backups/
```

The `-F c` flag produces a custom-format archive suitable for selective restore with `pg_restore`.

### Automated Daily Backup (cron example)

```cron
# /etc/cron.d/nis2compass-backup
# Run at 02:00 every day, retain 30 days of backups.
0 2 * * * root \
  docker exec nis2compass-postgres-1 \
    pg_dump -U postgres -d nis2compass -F c \
    -f /tmp/nis2compass_$(date +\%Y\%m\%d_\%H\%M\%S).dump && \
  docker cp nis2compass-postgres-1:/tmp/nis2compass_*.dump /backups/nis2compass/ && \
  find /backups/nis2compass/ -name '*.dump' -mtime +30 -delete
```

Verify that `/backups/nis2compass/` is on a volume separate from the PostgreSQL data volume and is included in your organisation's off-site backup process.

**Regulatory note:** The `audit_log` table is immutable — its contents cannot be modified by the application. However, the backup itself is not immutable. Store backup files in write-once storage (AWS S3 with Object Lock, Azure Blob with immutability policy) to satisfy NIS2 evidence retention requirements. Backup integrity is as important as database integrity for demonstrating compliance to national competent authorities.

---

## Database Restore

```bash
# Stop the API to prevent writes during restore.
docker compose stop nis2compass-api

# Drop and recreate the database (destructive — confirm before running).
docker exec nis2compass-postgres-1 \
  psql -U postgres -c "DROP DATABASE nis2compass;"
docker exec nis2compass-postgres-1 \
  psql -U postgres -c "CREATE DATABASE nis2compass OWNER nis2compass;"

# Restore from the dump file (copy it into the container first).
docker cp ./backups/nis2compass_20260101_020000.dump \
  nis2compass-postgres-1:/tmp/restore.dump

docker exec nis2compass-postgres-1 \
  pg_restore -U postgres -d nis2compass /tmp/restore.dump

# Restart the API.
docker compose start nis2compass-api
```

After restoring, verify that the `alembic_version` table reflects the correct migration head:

```bash
docker compose run --rm migrate alembic current
```

The reported revision must match the highest revision in `migrations/versions/`. If it does not, the dump was taken from a different schema version. Do not run `alembic upgrade head` against a restored database without verifying that the migration scripts are compatible with the restored schema — you risk data corruption.

---

## Upgrading

Never skip migration versions. The upgrade sequence is always:

1. Pull the new image:
   ```bash
   docker compose --env-file .env pull nis2compass-api
   ```

2. Run migrations:
   ```bash
   docker compose --env-file .env run --rm migrate
   ```
   Verify that `alembic current` reports the new head revision.

3. Restart the API container:
   ```bash
   docker compose --env-file .env up -d --no-deps nis2compass-api
   ```

4. Verify the health endpoint returns `{"status": "ok"}`.

If step 2 fails, do not proceed to step 3. Roll back the migration:

```bash
docker compose run --rm migrate alembic downgrade -1
```

Then investigate the failure before retrying.

---

## Monitoring

### Liveness Check

`GET /health` returns `{"status": "ok"}` with HTTP 200 when the API is up and the database connection pool is functional. Configure your uptime monitor or load balancer health probe to hit this endpoint every 30 seconds.

### Recommended Alerts

| Condition | Threshold | Severity | Notes |
|---|---|---|---|
| API 5xx error rate | > 1% over 5 minutes | Critical | Indicates application errors or database connectivity issues |
| Database connection pool exhaustion | Pool wait time > 2 s | Warning | Increase `NIS2_DB_POOL_SIZE` or add API replicas |
| Redis memory usage | > 80% of `maxmemory` | Warning | Rate limiter may start evicting keys; increase Redis memory allocation |
| `audit_log` INSERT failures | Any failure | Critical | A failed audit log write is a security event — the operation that triggered it may have succeeded without a corresponding audit record |
| `migrate` service exit code | Non-zero | Critical | Schema is out of sync; API may be running against an incompatible schema |

Audit log INSERT failures are treated as critical because they indicate either a database connectivity problem or an attempt to operate the system in a state where the compliance record cannot be maintained. The API should fail the originating request if an audit log write fails — do not silently discard audit events.

---

## Horizontal Scaling

The `nis2compass-api` container is stateless. Session-relevant state (rate limiter counters) is stored in Redis, not in container memory. Multiple API replicas can run behind a load balancer without coordination.

Configuration notes:

- Set `NIS2_DB_POOL_SIZE` per replica (default: 10). With three replicas the total PostgreSQL connection count is 30 — ensure `max_connections` in PostgreSQL is set appropriately (default is 100; consider `pgBouncer` for connection pooling at scale).
- Redis must run as a single primary instance. Do not use Redis Cluster for the rate limiter because the sliding-window algorithm depends on atomic operations across a single keyspace. Redis Sentinel (for HA failover) is supported.
- The `backend` Docker network must be reachable by all API replicas. In a multi-host setup, use Docker Swarm overlay networks or Kubernetes Services.

---

## Container Registry

The production image is published to:

```
ghcr.io/opensecstack/nis2compass:latest
```

In production, pin to a specific image digest rather than the mutable `latest` tag to ensure reproducible deployments:

```bash
# Find the digest of the current latest image.
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/opensecstack/nis2compass:latest
# Example output: ghcr.io/opensecstack/nis2compass@sha256:a1b2c3...

# Use the digest in docker-compose.yml.
image: ghcr.io/opensecstack/nis2compass@sha256:a1b2c3...
```

Update the pinned digest as part of your upgrade procedure (Step 1 above). Never run `latest` in production if you require audit trail continuity — a silent image update could change audit log behaviour without a corresponding migration.
