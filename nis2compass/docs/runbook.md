# NIS2 Compass Operations Runbook

This runbook covers routine operations, monitoring, backup, and on-call procedures for NIS2 Compass running in a production Docker Compose environment. All commands assume you are in the `nis2compass/` directory with Docker Compose v2 available.

---

## Health Checks

### API Health Endpoint

The API exposes a liveness endpoint at `GET /health`. A healthy response is:

```json
{"status": "ok"}
```

HTTP status code must be `200`. Any non-200 response indicates the API process is either failing to start or has lost a critical dependency.

**If /health returns non-200:**

1. Inspect the API container logs:
   ```bash
   docker compose logs --tail=100 nis2compass-api
   ```
2. Confirm the `migrate` service completed successfully:
   ```bash
   docker compose ps migrate
   ```
3. Confirm `postgres` and `redis` pass their own health checks:
   ```bash
   docker compose ps postgres
   docker compose ps redis
   ```
4. If the API container is in a crash loop, restart it after resolving the underlying cause:
   ```bash
   docker compose restart nis2compass-api
   ```

### Database Connectivity Check

Connect directly and run a trivial query:

```bash
docker compose exec postgres psql -U postgres -c "SELECT 1;"
```

Expected output: a row containing `1`. A connection refused or authentication error indicates the `postgres` service is unhealthy or the credentials are wrong.

### Redis Connectivity Check

```bash
docker compose exec redis redis-cli ping
```

Expected output: `PONG`. If Redis requires a password (production), pass `-a $REDIS_PASSWORD`:

```bash
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" ping
```

---

## Service Management

### Start All Services

```bash
docker compose up -d
```

### Stop All Services

```bash
docker compose down
```

This stops and removes containers but preserves the `pgdata` volume. To also remove volumes (destructive — data loss):

```bash
docker compose down -v
```

### Restart a Single Service

```bash
docker compose restart nis2compass-api
docker compose restart postgres
docker compose restart redis
```

### View All Logs

```bash
docker compose logs
```

### Tail Logs for a Specific Service

```bash
docker compose logs -f nis2compass-api
docker compose logs -f postgres
docker compose logs -f migrate
```

Limit output to the last N lines:

```bash
docker compose logs --tail=200 -f nis2compass-api
```

---

## Database Operations

### Connect to the Application Database

```bash
docker compose exec postgres psql -U nis2compass -d nis2compass
```

### Check Active Connections

Useful for diagnosing connection pool exhaustion:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT count(*) FROM pg_stat_activity WHERE datname = 'nis2compass';"
```

To see detail per client:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT pid, state, wait_event_type, wait_event, query_start, left(query,80) AS query
   FROM pg_stat_activity
   WHERE datname = 'nis2compass'
   ORDER BY query_start;"
```

### Check Table Sizes

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT relname AS table,
          pg_size_pretty(pg_relation_size(relid)) AS size,
          pg_size_pretty(pg_total_relation_size(relid)) AS total_size
   FROM pg_catalog.pg_statio_user_tables
   ORDER BY pg_total_relation_size(relid) DESC;"
```

The `audit_log` table will grow continuously. Monitor its size as part of routine checks.

### Check Migration State

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT * FROM alembic_version;"
```

The `version_num` column should match the head revision. Cross-reference with:

```bash
docker compose run --rm migrate sh -c \
  "pip install -q alembic psycopg2-binary sqlalchemy && alembic current"
```

### Vacuum Analyze

Run `VACUUM ANALYZE` after bulk data operations or if the query planner is choosing bad plans. This is non-destructive and can run on a live database.

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c "VACUUM ANALYZE;"
```

For the `audit_log` table specifically, after archival operations:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "VACUUM ANALYZE audit_log;"
```

PostgreSQL's autovacuum handles routine maintenance, but manual runs are appropriate after large ingestion events or after the archival procedure described below.

---

## Backup Procedures

### Full Database Backup

```bash
docker compose exec postgres pg_dump -U postgres nis2compass \
  > backup_$(date +%Y%m%d_%H%M%S).sql
```

Store the resulting `.sql` file in a location outside the Docker host. Do not store backups only on the same machine as the database.

### Restore from Backup

Restoring replaces all data. Confirm you have a valid backup file before proceeding.

**Step 1.** Stop the API to prevent writes during restore:

```bash
docker compose stop nis2compass-api
```

**Step 2.** Drop and recreate the application database:

```bash
docker compose exec postgres psql -U postgres -c "DROP DATABASE nis2compass;"
docker compose exec postgres psql -U postgres -c \
  "CREATE DATABASE nis2compass OWNER nis2compass;"
```

**Step 3.** Restore:

```bash
docker compose exec -T postgres psql -U postgres nis2compass < backup_20260101_120000.sql
```

**Step 4.** Verify migration state matches expected head:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT * FROM alembic_version;"
```

**Step 5.** Restart the API:

```bash
docker compose start nis2compass-api
```

### Backup Verification

At least once per month, restore the most recent backup to an isolated test instance and run row-count checks:

```sql
SELECT 'organisations' AS tbl, count(*) FROM organisations
UNION ALL
SELECT 'assessments',          count(*) FROM assessments
UNION ALL
SELECT 'controls',             count(*) FROM controls
UNION ALL
SELECT 'artifacts',            count(*) FROM artifacts
UNION ALL
SELECT 'audit_log',            count(*) FROM audit_log;
```

Compare counts against the production database. A successful restore with matching counts confirms the backup is usable.

### Recommended Backup Schedule

- Daily full backups via `pg_dump`, retained for 30 days.
- After each major schema migration, take an immediate backup before deploying the new API version.
- Store backups in at least two geographically separate locations.

---

## Audit Log Archival

The `audit_log` table is immutable: rows may never be updated or deleted. Over time it will grow large. Archival moves old rows to cold storage without removing them from the audit trail.

### Check Current Audit Log Volume

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT count(*) AS total_rows,
          min(timestamp) AS oldest_entry,
          max(timestamp) AS newest_entry,
          pg_size_pretty(pg_relation_size('audit_log')) AS table_size
   FROM audit_log;"
```

### Archive Rows Older Than Two Years

Create a separate archive table that mirrors the `audit_log` structure:

```sql
CREATE TABLE audit_log_archive (LIKE audit_log INCLUDING ALL);
```

Copy old rows into the archive table:

```sql
INSERT INTO audit_log_archive
SELECT * FROM audit_log
WHERE timestamp < NOW() - INTERVAL '2 years';
```

Optionally export the archive table to a cold storage file:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "\COPY audit_log_archive TO '/tmp/audit_log_archive_2024.csv' WITH CSV HEADER"
```

Then copy the file out of the container:

```bash
docker compose cp postgres:/tmp/audit_log_archive_2024.csv ./audit_log_archive_2024.csv
```

**Do not issue `DELETE FROM audit_log` under any circumstances.** The CITADEL WORM trigger will raise an exception if a DELETE is attempted, but beyond the trigger, deleting audit entries is a compliance violation. Archival copies rows to a secondary store; the originals remain in place. The archive table itself must also be treated as immutable.

---

## Redis Operations

### Check Redis Memory Usage

```bash
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" info memory | grep used_memory_human
```

Key metrics: `used_memory_human` (current), `maxmemory_human` (configured limit). Alert if memory usage exceeds 90% of the configured maximum.

### Flush Rate-Limiter Keys

Rate-limiter keys use the prefix `rate:`. To clear all rate-limit counters without flushing the entire Redis instance:

```bash
docker compose exec redis \
  redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'rate:*' | \
  xargs docker compose exec -T redis redis-cli -a "$REDIS_PASSWORD" DEL
```

Use this only during incident response when the rate limiter is blocking legitimate traffic due to a counter misconfiguration. Do not use as a routine operation.

### Real-Time Redis Monitoring

```bash
docker compose exec redis redis-cli -a "$REDIS_PASSWORD" monitor
```

This prints every command received by Redis in real time. Use it briefly for diagnosis; it generates significant output under load and adds minor latency.

---

## Log Management

NIS2 Compass emits structured JSON logs from the API. Each log line contains the following key fields:

| Field | Type | Description |
|---|---|---|
| `timestamp` | ISO 8601 | Time of the log event |
| `level` | string | `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` |
| `request_id` | UUID | Unique identifier for the HTTP request |
| `method` | string | HTTP method |
| `path` | string | Request path |
| `status_code` | integer | HTTP response status code |
| `duration_ms` | float | Request processing time in milliseconds |
| `actor` | string | Authenticated user or service identity |

To filter error-level log lines from the API:

```bash
docker compose logs nis2compass-api | grep '"level":"ERROR"'
```

### Log Rotation

Configure Docker's `json-file` log driver with size and rotation limits in `docker-compose.yml` under each service:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "100m"
    max-file: "5"
```

This retains up to 500 MB of logs per service (5 files × 100 MB). Adjust based on available disk space and retention requirements.

---

## Certificate Rotation

NIS2 Compass sits behind an nginx reverse proxy for TLS termination. When renewing TLS certificates (e.g., via Certbot or a manual renewal):

1. Replace the certificate and key files at the paths referenced in the nginx configuration.
2. Test the new configuration:
   ```bash
   nginx -t
   ```
3. Reload nginx without dropping existing connections:
   ```bash
   nginx -s reload
   ```

If nginx is running inside Docker:

```bash
docker compose exec nginx nginx -s reload
```

Verify the renewed certificate is being served:

```bash
openssl s_client -connect your.domain:443 -servername your.domain </dev/null 2>/dev/null \
  | openssl x509 -noout -dates
```

---

## Performance Baselines

Expected response times under normal load (p95):

| Operation | Target p95 | Alert Threshold |
|---|---|---|
| GET endpoints (list, read) | < 50 ms | > 200 ms |
| POST / PATCH (write operations) | < 100 ms | > 500 ms |
| Artifact upload (20 MB file) | < 2 s | > 5 s |
| `GET /health` | < 10 ms | > 100 ms |

These baselines assume a single-node Postgres instance with < 10 concurrent users. Establish a new baseline after any significant schema change or data volume increase.

Monitor response times via the `duration_ms` field in structured logs or via an APM tool ingesting those logs.

---

## On-Call Escalation

### Severity Levels

**P1 — Immediate response (page on-call engineer)**

- API is completely down (`GET /health` returns non-200 or connection refused).
- Database is unreachable (Postgres container unhealthy, connection refused on port 5432).
- Audit log insert is failing (errors in logs referencing `audit_log`).

**P2 — Within 1 hour**

- Error rate on API responses exceeds 5% over a 5-minute window.
- Response time exceeds 500 ms p95 for GET endpoints.
- Redis memory usage exceeds 90% of configured maximum.
- Migration service failing on scheduled deployment.

**P3 — Next business day**

- Isolated 500 errors (not sustained, < 1% error rate).
- Individual slow queries exceeding 1 second (investigate and add index or rewrite query).
- Scheduled backup failed (restore must be verified before next backup window).
- Certificate expiry within 14 days.

### Escalation Path

1. Check `GET /health`, container status (`docker compose ps`), and recent logs before escalating.
2. For P1 incidents: attempt restart of the affected service. If the issue persists after one restart cycle, escalate immediately — do not spend time diagnosing before escalating.
3. For security incidents (chain hash verification failure, evidence of audit_log tampering): do not attempt repair. Preserve all state, take a database snapshot, and escalate to the security team immediately.
