# APIGuard Operator Handbook

Production deployment, operations, and maintenance reference.

---

## Production Deployment Checklist

Before going live:

- [ ] PostgreSQL 15+ provisioned with TLS and a dedicated `apiguard` database user
- [ ] Redis 7+ provisioned for scan job queuing
- [ ] `APIGUARD_JWT_SECRET` set to a random 64-byte secret (not the default)
- [ ] `APIGUARD_DB_URL` uses `sslmode=require` or `sslmode=verify-full`
- [ ] TLS termination configured at the load balancer or reverse proxy
- [ ] `APIGUARD_TLS_SKIP_VERIFY=false` (default — never override in production)
- [ ] CORS origins locked to known frontend domain (`dashboard.cors_origins`)
- [ ] `log.format: json` for structured log ingestion
- [ ] Rate limiting configured (`scanner.rate_limit_rps`)
- [ ] CITADEL integration enabled if governance logging is required

---

## PostgreSQL Setup

### Minimum Requirements

- PostgreSQL 15+
- 2 vCPU, 4 GB RAM for up to 50 concurrent scans
- SSD storage — scan evidence JSON can be large

### Database Initialisation

```bash
psql -U postgres -c "CREATE USER apiguard WITH PASSWORD 'strong-password';"
psql -U postgres -c "CREATE DATABASE apiguard OWNER apiguard;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE apiguard TO apiguard;"
```

APIGuard runs migrations automatically on startup when `database.auto_migrate: true`. To run migrations manually:

```bash
apiguard migrate --db-url "postgres://apiguard:pass@localhost:5432/apiguard?sslmode=require"
```

### Connection String Format

```
postgres://apiguard:password@host:5432/apiguard?sslmode=require
```

SSL modes:

| Mode | When to Use |
|------|-------------|
| `disable` | Local development only |
| `require` | TLS required, no certificate verification |
| `verify-ca` | TLS required, verify CA certificate |
| `verify-full` | TLS required, verify CA + hostname (production standard) |

### Connection Pool Tuning

| Setting | Default | Guidance |
|---------|---------|----------|
| `max_open_conns` | 25 | Increase for high scan concurrency |
| `max_idle_conns` | 5 | 20% of `max_open_conns` is a good baseline |
| `conn_max_lifetime_seconds` | 300 | Keep below PostgreSQL `idle_in_transaction_session_timeout` |

---

## Redis Setup

Redis is used for scan job queuing and rate limit counters. A single Redis instance handles up to several hundred concurrent scans.

### Minimum Requirements

- Redis 7+
- 512 MB RAM for typical workloads
- Persistence (`appendonly yes`) if you need job queue durability across restarts

### Configuration

```bash
# .env
APIGUARD_REDIS_URL=redis://redis:6379
```

For Redis with AUTH:

```
APIGUARD_REDIS_URL=redis://:password@redis:6379/0
```

---

## TLS Configuration

APIGuard does not terminate TLS directly. Deploy behind a reverse proxy (nginx, Traefik, Caddy) or a load balancer that handles TLS.

### nginx Example

```nginx
server {
    listen 443 ssl;
    server_name apiguard.example.com;

    ssl_certificate     /etc/ssl/apiguard.crt;
    ssl_certificate_key /etc/ssl/apiguard.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://apiguard:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Set `APIGUARD_TRUSTED_PROXIES` to the IP of the nginx instance so APIGuard logs the real client IP from `X-Forwarded-For`.

---

## API Key Management

API keys are hashed (SHA-256) before storage. The plaintext is shown once on creation and never again.

```bash
# Create an API key via the API
curl -X POST http://localhost:8080/api/v1/api-keys \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"label":"ci-pipeline","scope":"scan:create scan:read"}'
```

Response includes the plaintext key — store it in your secrets manager immediately.

To revoke:

```bash
curl -X DELETE http://localhost:8080/api/v1/api-keys/{id} \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

---

## Backup and Restore

### Database Backup

```bash
# Full backup
pg_dump -U apiguard -h localhost apiguard | gzip > apiguard-$(date +%Y%m%d).sql.gz

# Restore
gunzip -c apiguard-20260330.sql.gz | psql -U apiguard -h localhost apiguard
```

Schedule daily backups. Retain 30 days minimum. For compliance environments, retain 1 year.

### Reports Backup

Reports written to `report.output_dir` are not backed up automatically. Mount the reports directory to persistent storage and include it in your backup schedule.

---

## Log Management

APIGuard writes structured JSON logs to stderr by default.

```yaml
log:
  level: info       # trace | debug | info | warn | error
  format: json      # text | json
  output: stderr    # stderr | stdout | /var/log/apiguard.log
```

### Log Fields

Every log entry includes: `level`, `ts` (RFC3339), `msg`, `trace_id`.

Scan-related logs additionally include: `scan_id`, `target`, `module`.

### Shipping to a Log Aggregator

For Loki, Elasticsearch, or Splunk — collect from stderr via your container runtime log driver (Docker `json-file` or `fluentd`), or use a sidecar log shipper.

---

## Prometheus Metrics

APIGuard exposes a Prometheus metrics endpoint at `GET /metrics`. Key metrics:

| Metric | Type | Description |
|--------|------|-------------|
| `apiguard_scans_total` | Counter | Total scans by status |
| `apiguard_scan_duration_seconds` | Histogram | Scan duration |
| `apiguard_findings_total` | Counter | Total findings by severity |
| `apiguard_http_requests_total` | Counter | HTTP requests by method, path, status |
| `apiguard_http_request_duration_seconds` | Histogram | HTTP request latency |
| `apiguard_db_pool_open_connections` | Gauge | Open DB connections |

---

## Upgrade Procedure

1. Read the CHANGELOG for breaking changes before upgrading
2. Back up the database
3. Pull the new image: `docker pull ghcr.io/opensecstack/apiguard:x.y.z`
4. Stop the running instance
5. Start the new instance — migrations run automatically on startup
6. Verify: `curl /api/v1/health` returns `{"status":"ok","version":"x.y.z"}`
7. If the new instance fails to start, restore from backup and roll back to the previous image

---

## Scaling

APIGuard is stateless at the application layer. The database and Redis are the shared state.

To scale horizontally:

1. Run multiple APIGuard instances pointing to the same PostgreSQL and Redis
2. Put a load balancer in front
3. Ensure all instances share the same `APIGUARD_JWT_SECRET` (otherwise tokens issued by one instance will be rejected by another)
4. Redis handles distributed rate limiting — no additional configuration required

A single instance handles ~20 concurrent scans with the default concurrency settings. Each additional instance adds proportional capacity.

---

## Health Check

```bash
curl http://localhost:8080/api/v1/health
# → {"status":"ok","version":"0.2.0","db":"ok","redis":"ok"}
```

Use this endpoint for load balancer health checks and container liveness probes.

```yaml
# Kubernetes liveness probe
livenessProbe:
  httpGet:
    path: /api/v1/health
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 30
```
