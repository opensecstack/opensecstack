# ThreatFlow Operator Handbook

## Overview

Day-to-day operational guide for ThreatFlow administrators and on-call engineers.

ThreatFlow is a Go-based threat intelligence hub (port 8091) that ingests IOCs from
external and internal sources, normalises them to STIX 2.1 format, and integrates
with CITADEL for governance. This handbook covers the recurring tasks, monitoring
procedures, and operational runbooks that keep ThreatFlow healthy in production.

---

## Daily Checks

Run through these checks at the start of each shift or as part of automated
monitoring:

1. **Verify service health:**
   ```bash
   curl -sf http://localhost:8091/api/v1/health | jq .
   # Expected: {"service":"threatflow","status":"ok"}
   ```

2. **Check feed poll status** (planned endpoint):
   ```bash
   curl -sf http://localhost:8091/api/v1/feeds/status | jq .
   ```

3. **Review ingestion metrics** -- IOCs ingested in the last 24 hours:
   ```bash
   psql threatflow -c "SELECT count(*) AS iocs_last_24h FROM iocs WHERE created_at > now() - interval '24 hours';"
   ```

4. **Check CITADEL connectivity** -- verify WORM events are being written:
   ```bash
   curl -sf $THREATFLOW_CITADEL_API_URL/health | jq .
   ```

5. **Monitor error rate in logs:**
   ```bash
   # Systemd / bare-metal
   journalctl -u threatflow --since "24 hours ago" | grep '"level":"error"' | wc -l

   # Docker
   docker logs threatflow --since 24h 2>&1 | grep '"level":"error"' | wc -l

   # Kubernetes
   kubectl -n opensecstack logs deployment/threatflow --since=24h | grep '"level":"error"' | wc -l
   ```

6. **Database connection pool utilisation:**
   ```bash
   psql threatflow -c "SELECT count(*) AS active FROM pg_stat_activity WHERE datname = 'threatflow' AND state = 'active';"
   ```

---

## Feed Management

### Adding a New Feed

1. Define the feed in the YAML configuration file (`feeds.yaml` or the path set by
   `THREATFLOW_FEED_CONFIG_PATH`):
   ```yaml
   feeds:
     - name: abuse-ch-urlhaus
       type: csv
       url: https://urlhaus.abuse.ch/downloads/csv/
       poll_interval: 1h
       confidence_base: 80
       enabled: true
   ```

2. Specify all required fields:
   - `name` -- unique identifier for the feed
   - `type` -- one of `taxii21`, `csv`, `misp`, `manual`
   - `url` -- source endpoint URL
   - `poll_interval` -- how often to poll (e.g. `15m`, `1h`, `6h`)
   - `confidence_base` -- baseline confidence score (0-100)

3. Test with a dry-run before enabling:
   ```bash
   threatflow feed test --url https://urlhaus.abuse.ch/downloads/csv/ --type csv
   ```

4. Enable the feed -- either restart the service or send SIGHUP for config reload:
   ```bash
   # Option A: restart
   systemctl restart threatflow

   # Option B: config reload (no downtime)
   kill -SIGHUP $(pidof threatflow)
   ```

### Pausing a Feed

- Set `enabled: false` in configuration:
  ```yaml
  feeds:
    - name: alienvault-otx
      enabled: false
  ```

- Or call the management endpoint (planned):
  ```bash
  curl -X PATCH http://localhost:8091/api/v1/feeds/alienvault-otx \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"enabled": false}'
  ```

### Removing a Feed

1. Set `enabled: false` and let existing IOCs age naturally.
2. Optionally purge IOCs from that feed:
   ```bash
   threatflow ioc purge --feed alienvault-otx --dry-run
   threatflow ioc purge --feed alienvault-otx --confirm
   ```

### Feed Health Indicators

| Status | Meaning | Action |
|--------|---------|--------|
| `healthy` | Last poll succeeded, IOCs flowing | None |
| `degraded` | Poll succeeded but 0 new IOCs for >24h | Check source availability |
| `error` | Last 3+ consecutive polls failed | Check URL, credentials, network |
| `stale` | No poll attempt in >2x the configured interval | Check scheduler, restart service |

Feeds with `error_count > 5` are automatically paused. Once VIGIL ships
(CITADEL v2.0, design-stage as of v1.0.0), this will also raise a VIGIL
AMBER alert via CITADEL; today the pause itself is the enforcement
mechanism.

---

## IOC Lifecycle

1. **Ingestion** -- IOC received via API (`POST /api/v1/iocs`) or feed poll
2. **Validation** -- type check, value sanitisation, format verification
3. **Deduplication** -- SHA-256 hash check against existing store
4. **MARSHAL evaluation** -- CITADEL governance gate (if enabled and batch >100 IOCs)
5. **Storage** -- persisted to PostgreSQL with metadata, STIX ID, and confidence score
6. **WORM logging** -- `threatflow.ioc.ingested` event emitted to CITADEL
7. **Correlation** -- cross-referenced with APIGuard findings and IRFlow incidents
8. **ATT&CK mapping** -- automatic TTP classification for the indicator
9. **Aging** -- confidence decreases over time based on `age_decay_factor`
10. **Expiry** -- IOC marked `revoked` after TTL, excluded from active queries
11. **Archival** -- revoked IOCs remain in the database for audit and historical correlation

---

## Confidence Scoring

Each IOC carries a confidence score from 0 to 100.

### Scoring Formula

```
confidence = feed.confidence_base * feed.accuracy_ratio * age_decay_factor
```

Where:
- `confidence_base` -- set per feed in configuration (e.g. 70 for OTX, 90 for internal MISP)
- `accuracy_ratio` -- historical true-positive rate for this feed (starts at 1.0)
- `age_decay_factor` -- `exp(-0.01 * days_since_first_seen)` -- exponential decay

### Confidence Adjustments

| Event | Adjustment |
|-------|-----------|
| Corroborated by 2+ independent feeds | +10 |
| Matched in active IRFlow incident | +20 |
| Each day past TTL expiry | -5 |
| Manually marked false positive | -20 |

### Confidence Thresholds

| Score | Meaning |
|-------|---------|
| 90-100 | High -- verified by multiple sources or manual analysis |
| 70-89 | Medium -- from a trusted feed with good accuracy history |
| 50-69 | Low -- from a new or less-reliable feed |
| 0-49 | Very low -- unverified, single-source, or aged indicators |

The threshold for an actionable IOC is **confidence >= 50**. IOCs below this
threshold are still stored but not included in active STIX bundle exports or
correlation matches.

---

## Deduplication

IOCs are deduplicated using the SHA-256 hash of the normalised STIX pattern string:

```
dedup_key = SHA-256(ioc_type + ":" + ioc_value)
```

When a duplicate is found:
- **Confidence** -- updated to the higher of existing vs. incoming value
- **Source references** -- merged (both feed sources recorded)
- **last_seen** -- updated to the current timestamp
- **No new record** is created; the existing record is updated in place

The `pattern_hash` column in the `iocs` table has a `UNIQUE` constraint
enforcing this at the database level.

---

## Common Operational Tasks

### Ingest a Single IOC via API

```bash
curl -X POST http://localhost:8091/api/v1/iocs \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "type": "ipv4-addr",
    "value": "198.51.100.42",
    "source": "manual",
    "confidence": 90,
    "tags": ["c2", "cobalt-strike"],
    "description": "Known C2 server from IR case 2026-0042"
  }'
```

### Bulk Import IOCs from CSV

```bash
threatflow ioc import --file /path/to/iocs.csv --source manual --confidence 70
```

Expected CSV format:
```csv
type,value,tags,description
ipv4-addr,198.51.100.42,"c2,cobalt-strike","Known C2 server"
domain-name,evil.example.com,"phishing","Phishing domain"
```

### Export STIX 2.1 Bundle

```bash
curl -H "Authorization: Bearer $TOKEN" \
  "http://localhost:8091/api/v1/stix/bundles?since=2026-03-01&type=ipv4-addr" \
  -o bundle.json
```

### Force Feed Re-poll

```bash
threatflow feed poll --name alienvault-otx --force
```

### Purge Expired IOCs

```bash
# Preview what would be deleted
threatflow ioc purge --older-than 90d --dry-run

# Execute the purge
threatflow ioc purge --older-than 90d --confirm
```

### Check IOC Count by Type

```bash
psql threatflow -c "SELECT type, count(*) FROM iocs WHERE NOT revoked GROUP BY type ORDER BY count DESC;"
```

### Check Feed Health

```bash
psql threatflow -c "SELECT name, feed_type, enabled, error_count, last_poll_at, last_poll_count FROM feeds ORDER BY last_poll_at DESC;"
```

### Override IOC Confidence Manually

```bash
curl -X PATCH http://localhost:8091/api/v1/iocs/{id} \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"confidence": 90}'
```

Note: manual confidence overrides require MARSHAL approval
(`ioc_confidence_override` action type) when CITADEL integration is enabled.

---

## Monitoring & Alerting

### Key Metrics

| Metric | Type | Alert Threshold |
|--------|------|----------------|
| `threatflow_iocs_total` | gauge | < previous day count (possible data loss) |
| `threatflow_ingestion_rate` | counter | < 1/min for >1h (feed stall) |
| `threatflow_feed_errors_total` | counter | > 10 in 5min |
| `threatflow_marshal_refused` | counter | > 5 in 1h (governance issue) |
| `threatflow_db_latency_p99` | histogram | > 500ms |
| `threatflow_db_pool_used` | gauge | > 80% of `max_open_conns` (25 default) |
| `threatflow_dedup_rate` | gauge | > 95% (feed may be stale) |
| `threatflow_stix_export_errors` | counter | > 0 in 15min |

### Log Levels

| Level | When to Use |
|-------|-------------|
| `error` | Failed operations: feed poll failure, DB write error, CITADEL timeout |
| `warn` | Degraded state: high dedup rate, slow queries, CITADEL unreachable |
| `info` | Normal operations: feed polled, IOC ingested, bundle exported |
| `debug` | Development only: full request/response, SQL queries, HMAC computation |

Set via environment variable:
```bash
THREATFLOW_LOG_LEVEL=debug   # for investigation
THREATFLOW_LOG_LEVEL=info    # for production (default)
```

### Prometheus Scrape Configuration

```yaml
scrape_configs:
  - job_name: threatflow
    static_configs:
      - targets: ['threatflow:8091']
    metrics_path: /metrics
    scrape_interval: 15s
```

---

## Backup & Recovery

### Database Backup

```bash
# Full backup (custom format, compressed)
pg_dump -Fc threatflow > backup_$(date +%Y%m%d_%H%M%S).dump

# Schema only
pg_dump --schema-only threatflow > schema_$(date +%Y%m%d).sql

# Data only (for migration)
pg_dump --data-only threatflow > data_$(date +%Y%m%d).sql
```

### Automated Backup (cron)

```bash
# Add to crontab: daily backup at 02:00, keep 30 days
0 2 * * * pg_dump -Fc threatflow > /backup/threatflow_$(date +\%Y\%m\%d).dump && find /backup -name "threatflow_*.dump" -mtime +30 -delete
```

### Recovery Steps

1. Stop ThreatFlow:
   ```bash
   systemctl stop threatflow
   ```

2. Restore the database:
   ```bash
   pg_restore -d threatflow --clean --if-exists backup_20260331.dump
   ```

3. Verify data integrity:
   ```bash
   psql threatflow -c "SELECT count(*) FROM iocs;"
   psql threatflow -c "SELECT count(*) FROM feeds;"
   psql threatflow -c "SELECT count(*) FROM stix_bundles;"
   ```

4. Start ThreatFlow:
   ```bash
   systemctl start threatflow
   ```

5. Force re-poll all feeds to catch up:
   ```bash
   threatflow feed poll --all --force
   ```

6. Verify health:
   ```bash
   curl -sf http://localhost:8091/api/v1/health | jq .
   ```

---

## Capacity Planning

| Scale | IOCs | DB Size | Memory | CPU | Pods | DB Connections |
|-------|------|---------|--------|-----|------|---------------|
| Small | <10K | 500MB | 256Mi | 0.25 | 1 | 10 |
| Medium | 10K-100K | 5GB | 512Mi | 0.5 | 2 | 25 |
| Large | 100K-1M | 50GB | 1Gi | 1.0 | 4 | 50 |
| XL | >1M | 200GB+ | 2Gi | 2.0 | 8+ | 100 |

### Scaling Considerations

- **Database**: for >1M IOCs, consider partitioning the `iocs` table by `created_at`
- **Connection pooling**: use PgBouncer in front of PostgreSQL for >4 pods
- **Redis**: enable Redis caching (`THREATFLOW_REDIS_URL`) for hot IOC lookups at
  Medium scale and above
- **Feed concurrency**: at Large scale, increase feed poll workers to avoid queue
  buildup
- **VACUUM**: schedule regular `VACUUM ANALYZE` on the `iocs` table for databases
  with high churn

---

## Configuration Quick Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_PORT` | `8091` | HTTP listen port |
| `THREATFLOW_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `THREATFLOW_DB_URL` | `postgres://...localhost:5432/threatflow` | PostgreSQL connection string |
| `THREATFLOW_DB_MAX_OPEN_CONNS` | `25` | Maximum open DB connections |
| `THREATFLOW_DB_MAX_IDLE_CONNS` | `5` | Maximum idle DB connections |
| `THREATFLOW_CITADEL_API_URL` | *(empty -- disabled)* | CITADEL base URL |
| `THREATFLOW_CITADEL_KEY_ID` | | HMAC connector key ID |
| `THREATFLOW_CITADEL_KEY_SECRET` | | HMAC signing secret |
| `THREATFLOW_CITADEL_PROJECT_ID` | `threatflow` | Project ID for WORM events |
| `THREATFLOW_FEED_CONFIG_PATH` | `feeds.yaml` | Path to feed config file |
| `THREATFLOW_FEED_DEFAULT_TTL` | `60d` | Default IOC time-to-live |
| `THREATFLOW_FEED_MAX_BATCH` | `1000` | Max IOCs per ingestion batch |

See [configuration.md](configuration.md) for the full reference.

---

## Runbook: On-Call Escalation

### Severity Levels

| Severity | Condition | Response Time |
|----------|-----------|---------------|
| P1 -- Critical | Service down, DB unreachable | 15 min |
| P2 -- High | All feeds failing, CITADEL integration broken | 1 hour |
| P3 -- Medium | Single feed failing, degraded performance | 4 hours |
| P4 -- Low | Cosmetic, non-urgent config change | Next business day |

### Escalation Path

1. On-call engineer: check health endpoint, logs, DB connectivity
2. If DB issue: escalate to database team
3. If CITADEL issue: escalate to CITADEL team, check CITADEL health independently
4. If network/DNS issue: escalate to infrastructure team

---

## Related Documentation

| Document | Description |
|----------|-------------|
| [Architecture](architecture.md) | System design, data flow, component interactions |
| [API Reference](api-reference.md) | Complete HTTP API documentation |
| [IOC Feeds](ioc-feeds.md) | Feed sources, ingestion pipeline, deduplication |
| [CITADEL Integration](citadel-integration.md) | MARSHAL governance, WORM logging |
| [Data Model](data-model.md) | Database schema and relationships |
| [Configuration](configuration.md) | Environment variables, config file format |
| [Deployment](deployment.md) | Docker, Kubernetes, production checklist |
| [Troubleshooting](troubleshooting.md) | Common issues and solutions |
