# ThreatFlow Troubleshooting Guide

## Quick Diagnostics

Run these four checks to rapidly assess system state:

```bash
# 1. Service health
curl -sf http://localhost:8091/api/v1/health | jq .

# 2. Application logs (last 50 lines)
journalctl -u threatflow -n 50 --no-pager
# or: docker logs threatflow --tail 50
# or: kubectl -n opensecstack logs deployment/threatflow --tail=50

# 3. Database connectivity
psql threatflow -c "SELECT 1 AS db_ok;"

# 4. CITADEL connectivity
curl -sf $THREATFLOW_CITADEL_API_URL/health | jq .
```

If all four pass, the system is fundamentally healthy. Proceed to the specific
issue sections below.

---

## Common Issues

### Service Won't Start

**Symptom:** `threatflow serve` exits immediately, or the container enters
CrashLoopBackOff.

| Cause | Diagnosis | Fix |
|-------|-----------|-----|
| Missing required env vars | Log shows `Error: loading config: ...` | Set `THREATFLOW_DB_URL` at minimum |
| Invalid config YAML | Log shows `Error: parsing config: ...` | Validate with `threatflow config validate` |
| Port 8091 already in use | Log shows `bind: address already in use` | Change port or kill existing process |
| Cannot resolve DB host | Log shows `dial tcp: lookup db-host: no such host` | Verify DNS/hostname, check network |
| Binary not found | Shell returns `command not found` | Check `$PATH`, verify binary is installed |
| Permission denied | Log shows `permission denied` | Check file permissions, run as correct user |

**Diagnostic commands:**
```bash
# Check what's using port 8091
lsof -i :8091
# or on Windows: netstat -aon | findstr 8091

# Validate config without starting the server
threatflow config validate

# Start with verbose logging to see the exact failure
THREATFLOW_LOG_LEVEL=debug THREATFLOW_LOG_FORMAT=text threatflow serve
```

**Kubernetes-specific:**
```bash
# Check pod events for scheduling or pull errors
kubectl -n opensecstack describe pod -l app=threatflow

# Check previous container logs (after a crash)
kubectl -n opensecstack logs deployment/threatflow --previous

# Verify secrets are mounted
kubectl -n opensecstack get secret threatflow-secrets -o yaml
```

---

### Database Connection Failed

**Symptom:** `pinging db: dial tcp ...: connection refused` or
`pq: password authentication failed`

```
Checklist:
[ ] PostgreSQL is running:
    pg_isready -h localhost -p 5432

[ ] Database exists:
    psql -l | grep threatflow

[ ] User has access:
    psql -U threatflow -d threatflow -c "SELECT 1"

[ ] SSL mode matches server config:
    echo $THREATFLOW_DB_URL
    # Check sslmode parameter: disable, require, verify-ca, verify-full

[ ] Firewall allows connection:
    nc -zv db-host 5432

[ ] Connection pool not exhausted:
    psql -c "SELECT count(*) FROM pg_stat_activity WHERE datname = 'threatflow';"
    # Compare against max_connections in postgresql.conf (default 100)
    # and THREATFLOW_DB_MAX_OPEN_CONNS (default 25)
```

**Common fixes:**
```bash
# Reset password if auth fails
psql -U postgres -c "ALTER USER threatflow WITH PASSWORD 'newpassword';"

# Create database if missing
createdb -U postgres threatflow
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE threatflow TO threatflow;"

# Kill idle connections if pool is exhausted
psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'threatflow' AND state = 'idle' AND state_change < now() - interval '10 minutes';"
```

---

### IOC Ingestion Fails

**Symptom:** `POST /api/v1/iocs` returns 4xx or 5xx errors.

| Status | Cause | Fix |
|--------|-------|-----|
| 400 | Invalid IOC type or value | Check type is one of: `ipv4-addr`, `ipv6-addr`, `domain-name`, `url`, `file`, `email-addr`, `autonomous-system` |
| 400 | Missing required fields | Ensure `type`, `value`, `source` are all present in the request body |
| 409 | Duplicate IOC | Expected behaviour -- IOC already exists with the same `pattern_hash`. The existing record is updated. |
| 413 | Payload too large | STIX bundle exceeds the 10MB body limit. Split into smaller bundles. |
| 415 | Wrong Content-Type | Must be `application/json` |
| 429 | Rate limited | Wait and retry with exponential backoff, or increase rate limit config |
| 500 | Database error | Check DB connectivity, disk space, and table locks |
| 503 | CITADEL MARSHAL refused | Check CITADEL logs for the governance refusal reason (see below) |

**Debugging a 400 error:**
```bash
# Test with minimal valid payload
curl -v -X POST http://localhost:8091/api/v1/iocs \
  -H "Content-Type: application/json" \
  -d '{"type":"ipv4-addr","value":"198.51.100.42","source":"test"}'

# Check the response body for validation details
curl -s -X POST http://localhost:8091/api/v1/iocs \
  -H "Content-Type: application/json" \
  -d '{"type":"bad-type","value":"not-valid"}' | jq .
```

---

### CITADEL Integration Issues

**Symptom:** WORM events not appearing in CITADEL, or MARSHAL always refuses
operations.

```
Checklist:
[ ] CITADEL URL is set and correct:
    echo $THREATFLOW_CITADEL_API_URL

[ ] CITADEL service is reachable:
    curl -sf $THREATFLOW_CITADEL_API_URL/health

[ ] Connector key ID is valid:
    echo $THREATFLOW_CITADEL_KEY_ID
    # Verify key exists and is not expired in CITADEL admin

[ ] HMAC secret matches between ThreatFlow and CITADEL:
    # Verify the base64 encoding is correct
    echo $THREATFLOW_CITADEL_KEY_SECRET | base64 -d | wc -c
    # Should be 32 bytes for HMAC-SHA256

[ ] Clock is synchronised (HMAC signatures are time-sensitive):
    date -u
    # Ensure <5 min drift from CITADEL server (use NTP)

[ ] Project ID exists in CITADEL:
    echo $THREATFLOW_CITADEL_PROJECT_ID
    # Verify project exists in CITADEL project list

[ ] Dry-run mode is not enabled:
    echo $THREATFLOW_CITADEL_DRY_RUN
    # If "true", WORM events and MARSHAL calls are no-ops
```

**MARSHAL REFUSE reasons:**

| Reason | Meaning | Action |
|--------|---------|--------|
| `authority_insufficient` | API key lacks permission for this action | Check key scope in CITADEL admin console |
| `project_frozen` | Project is in a governance freeze period | Wait for freeze to end or request an exception |
| `advisory_block` | AUGUR has an active CRITICAL advisory | Resolve the advisory in CITADEL before proceeding |
| `sod_violation` | Operator and verifier are the same user | Use a different verifier for dual-control operations |
| `mandate_expired` | Role or mandate has expired | Renew the mandate in CITADEL admin |
| `threshold_exceeded` | Batch size exceeds configured limit | Reduce batch via `THREATFLOW_FEED_MAX_BATCH` |

**When CITADEL is completely down:**

If `THREATFLOW_CITADEL_API_URL` is empty, ThreatFlow operates in disabled mode:
- WORM events are silently discarded
- MARSHAL evaluations return implicit EXECUTE
- All IOC operations proceed without governance checks

This is acceptable for development but must not be used in production.

---

### Feed Polling Errors

**Symptom:** Feed status shows "error", no new IOCs ingested.

| Feed Type | Common Issue | Fix |
|-----------|-------------|-----|
| TAXII 2.1 | Authentication failed (401/403) | Verify API key or credentials in feed config |
| TAXII 2.1 | Collection not found (404) | Confirm the collection ID matches the server |
| TAXII 2.1 | Server returns empty collection | Check if the TAXII server has data in the requested time range |
| CSV | Download failed (404) | Verify the URL is accessible: `curl -I <url>` |
| CSV | Parse error (malformed rows) | Check CSV format matches the expected schema (see [ioc-feeds.md](ioc-feeds.md)) |
| MISP | Connection refused | Verify MISP URL and API key, check MISP server status |
| All | DNS resolution failed | Check network settings, proxy configuration |
| All | TLS certificate error | Add the CA certificate, or set `tls_skip_verify: true` (development only) |
| All | Timeout | Increase timeout, check network latency to the feed source |

**Debugging a specific feed:**
```bash
# Test the feed URL directly
curl -v -H "X-OTX-API-KEY: $KEY" https://otx.alienvault.com/api/v1/pulses/subscribed

# Test the feed via ThreatFlow's test command
threatflow feed test --url https://urlhaus.abuse.ch/downloads/csv/ --type csv

# Check feed status in the database
psql threatflow -c "SELECT name, feed_type, enabled, error_count, last_poll_at, last_poll_count FROM feeds WHERE name = 'alienvault-otx';"
```

**Feed returning 0 IOCs:**

This is not always an error. Possible causes:
1. Feed has no new IOCs since the last poll (normal)
2. All IOCs are duplicates (deduplication is working correctly)
3. Feed API key is invalid and the server returns empty results instead of 401
4. Feed source is genuinely empty

Check dedup stats:
```bash
# Check deduplication in logs
journalctl -u threatflow --since "1 hour ago" | grep "deduplicated"

# Check last poll details
psql threatflow -c "SELECT name, last_poll_at, last_poll_count, error_count FROM feeds ORDER BY last_poll_at DESC;"
```

---

### Slow Queries / High Latency

**Symptom:** API responses take >1s, database pool utilisation is high.

**Diagnosis:**
```bash
# 1. Check active queries
psql threatflow -c "SELECT pid, now() - pg_stat_activity.query_start AS duration, query, state FROM pg_stat_activity WHERE datname = 'threatflow' AND state != 'idle' ORDER BY duration DESC;"

# 2. Enable slow query logging in PostgreSQL
psql -c "ALTER SYSTEM SET log_min_duration_statement = 500;"
psql -c "SELECT pg_reload_conf();"

# 3. Check index usage -- unused indexes waste space
psql threatflow -c "SELECT schemaname, relname, indexrelname, idx_scan FROM pg_stat_user_indexes WHERE idx_scan = 0 ORDER BY relname;"

# 4. Check table sizes and bloat
psql threatflow -c "SELECT relname, pg_size_pretty(pg_total_relation_size(relid)) AS total_size, n_live_tup, n_dead_tup FROM pg_stat_user_tables ORDER BY pg_total_relation_size(relid) DESC;"

# 5. Run EXPLAIN ANALYZE on a slow query
psql threatflow -c "EXPLAIN ANALYZE SELECT * FROM iocs WHERE type = 'ipv4-addr' AND NOT revoked ORDER BY confidence DESC LIMIT 100;"
```

**Common fixes:**
- Run `VACUUM ANALYZE` on large tables:
  ```bash
  psql threatflow -c "VACUUM ANALYZE iocs;"
  psql threatflow -c "VACUUM ANALYZE sightings;"
  ```
- Verify required indexes exist (see [data-model.md](data-model.md)):
  - `UNIQUE (pattern_hash)` on `iocs`
  - `idx_iocs_type`, `idx_iocs_value`, `idx_iocs_feed`, `idx_iocs_confidence`
  - `GIN (tags)` for tag filtering
  - `GIN (to_tsvector(...))` for full-text search
- Increase connection pool size if pool is saturated:
  ```bash
  export THREATFLOW_DB_MAX_OPEN_CONNS=50
  ```
- Enable Redis caching for hot IOC lookups (planned, v0.5):
  ```bash
  export THREATFLOW_REDIS_URL=redis://localhost:6379/2
  ```
- For >1M IOCs, partition the `iocs` table by `created_at`

---

### Correlation Engine Not Matching

**Symptom:** IOCs exist in the database but are not linked to APIGuard findings
or IRFlow incidents.

```
Checklist:
[ ] APIGuard integration is enabled:
    echo $THREATFLOW_APIGUARD_URL

[ ] IRFlow integration is enabled:
    echo $THREATFLOW_IRFLOW_URL

[ ] Correlation scheduler is running:
    journalctl -u threatflow | grep "correlation"

[ ] IOC types match:
    APIGuard typically produces url and domain-name types.
    Ensure the IOC store contains matching types.

[ ] Time window:
    Correlation checks the last 30 days by default.
    Older IOCs or incidents may fall outside this window.

[ ] Both services are healthy:
    curl -sf http://localhost:8090/health   # APIGuard
    curl -sf http://localhost:8093/health   # IRFlow
```

---

### IOC Confidence Scores Unexpectedly Low

**Symptom:** IOCs from a trusted feed have confidence below expected threshold.

**Cause:** The `age_decay_factor` reduces confidence over time using the formula:
```
confidence = base * accuracy_ratio * exp(-0.01 * days_since_first_seen)
```

A 30-day-old IOC with `confidence_base=70` and `accuracy_ratio=1.0` would have:
`70 * 1.0 * exp(-0.01 * 30) = 70 * 0.74 = 51.8`

**Fixes:**
```bash
# Option 1: Re-ingest the IOC (resets last_seen, updates confidence)
curl -X POST http://localhost:8091/api/v1/iocs \
  -H "Content-Type: application/json" \
  -d '{"type":"ipv4-addr","value":"198.51.100.42","source":"manual","confidence":90}'

# Option 2: Manual confidence override
curl -X PATCH http://localhost:8091/api/v1/iocs/{id} \
  -H "Content-Type: application/json" \
  -d '{"confidence": 90}'
```

Note: manual overrides require MARSHAL approval when CITADEL is enabled.

---

### STIX Bundle Import/Export Errors

**Symptom:** Bundle ingestion returns errors, or exported bundles are incomplete.

| Issue | Cause | Fix |
|-------|-------|-----|
| `invalid bundle: missing type` | Bundle JSON lacks `"type":"bundle"` | Ensure the root object has `type` and `id` fields |
| `object count mismatch` | Bundle `objects` array count differs from header | Regenerate the bundle from source |
| `unsupported STIX version` | Bundle uses STIX 1.x format | Convert to STIX 2.1 before import |
| `duplicate stix_id` | Object already exists in the database | Expected -- the existing object is preserved |
| Export returns empty bundle | No IOCs match the filter criteria | Broaden the `since` date or `type` filter |

**Validate a STIX bundle before import:**
```bash
# Check bundle structure
cat bundle.json | jq '.type, .id, (.objects | length)'

# Verify all objects have required fields
cat bundle.json | jq '.objects[] | select(.type == null or .id == null)'
# Should return nothing if all objects are valid
```

---

## Debug Mode

Enable verbose logging for deep investigation:

```bash
THREATFLOW_LOG_LEVEL=debug THREATFLOW_LOG_FORMAT=text threatflow serve
```

Debug output includes:
- Full HTTP request/response headers
- SQL queries with bind parameters
- CITADEL HMAC computation details (key ID, timestamp, signature)
- Feed poll timing, response sizes, and parse results
- Deduplication hash computation and merge decisions
- Correlation engine match attempts and results

**Warning:** debug logging generates high log volume and may include sensitive
data (IOC values, API keys in headers). Do not leave enabled in production.

To enable debug logging temporarily without restarting:
```bash
# If the service supports SIGHUP config reload
kill -SIGHUP $(pidof threatflow)
```

---

## Health Check Reference

| Endpoint | Response | Status | Meaning |
|----------|----------|--------|---------|
| `GET /api/v1/health` | `{"status":"ok","service":"threatflow"}` | 200 | All systems operational |
| `GET /api/v1/health` | `{"status":"degraded","service":"threatflow"}` | 200 | Partial functionality (e.g. CITADEL unreachable, feed errors) |
| `GET /api/v1/health` | Connection refused / timeout | N/A | Service is down |
| `GET /api/v1/health` | `{"status":"unhealthy"}` | 503 | Critical failure (DB down) |

The health endpoint checks:
1. HTTP server is responding
2. Database connection is alive (`SELECT 1`)
3. CITADEL is reachable (if configured)

---

## Log Analysis

### Useful Log Queries

```bash
# All errors in the last hour
journalctl -u threatflow --since "1 hour ago" | grep '"level":"error"'

# Feed poll results
journalctl -u threatflow --since "24 hours ago" | grep '"event":"feed_polled"'

# CITADEL MARSHAL decisions
journalctl -u threatflow --since "24 hours ago" | grep '"marshal"'

# IOC ingestion events
journalctl -u threatflow --since "1 hour ago" | grep '"event":"ioc_ingested"'

# Slow database queries (if logged)
journalctl -u threatflow --since "1 hour ago" | grep '"slow_query"'
```

### Docker / Kubernetes Log Queries

```bash
# Docker: filter by log level
docker logs threatflow 2>&1 | jq 'select(.level == "error")'

# Kubernetes: follow logs with error filter
kubectl -n opensecstack logs -f deployment/threatflow | jq 'select(.level == "error")'

# Kubernetes: logs from all pods
kubectl -n opensecstack logs -l app=threatflow --all-containers
```

---

## Emergency Procedures

### Emergency Feed Shutdown

If a feed is ingesting bad data (false positives, poisoned IOCs):

```bash
# 1. Immediately disable the feed
psql threatflow -c "UPDATE feeds SET enabled = false WHERE name = 'compromised-feed';"

# 2. Identify IOCs from the bad feed
psql threatflow -c "SELECT count(*) FROM iocs WHERE source = 'compromised-feed' AND created_at > now() - interval '24 hours';"

# 3. Revoke the bad IOCs
psql threatflow -c "UPDATE iocs SET revoked = true WHERE source = 'compromised-feed' AND created_at > now() - interval '24 hours';"

# 4. Verify
psql threatflow -c "SELECT count(*) FROM iocs WHERE source = 'compromised-feed' AND NOT revoked;"
```

### Emergency Service Restart

```bash
# Graceful restart (allows in-flight requests to complete)
systemctl restart threatflow

# Docker
docker restart threatflow

# Kubernetes (rolling restart)
kubectl -n opensecstack rollout restart deployment/threatflow
kubectl -n opensecstack rollout status deployment/threatflow
```

---

## Getting Help

- **GitHub Issues:** <https://github.com/opensecstack/opensecstack/issues>
- **Community Discord:** `#threatflow` channel
- **Documentation index:** see the [docs/](.) directory
- **Operator Handbook:** [operator-handbook.md](operator-handbook.md) for daily operations
- **Architecture:** [architecture.md](architecture.md) for system design context
- **CITADEL Integration:** [citadel-integration.md](citadel-integration.md) for governance details

When filing an issue, include:
1. ThreatFlow version (`curl http://localhost:8091/api/v1/version`)
2. Relevant log output (redact secrets)
3. Steps to reproduce
4. Expected vs. actual behaviour

---

## See Also

- [Configuration](configuration.md) — most issues trace back to misconfiguration
- [Deployment](deployment.md) — deployment-specific setup and prerequisites
- [CITADEL Integration](citadel-integration.md) — MARSHAL and WORM connectivity
- [IOC Feeds](ioc-feeds.md) — feed health monitoring and error handling
- [API Reference](api-reference.md) — error response codes and meanings
