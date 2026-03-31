# ThreatFlow Performance Guide

This document covers throughput targets, database optimization, caching strategy, benchmarking, and scaling guidance for ThreatFlow deployments.

---

## Throughput Targets

| Version | IOC Ingestion | Query Latency (p99) | Concurrent Users |
|---------|--------------|---------------------|------------------|
| v0.2 | 100/sec | <500ms | 10 |
| v0.3 | 1K/sec | <200ms | 50 |
| v0.4 | 5K/sec | <100ms | 100 |
| v0.5 | 10K/sec | <50ms | 200 |

Each milestone builds on the previous one. The v0.2 baseline establishes persistence and correctness; subsequent versions add feed polling, correlation, caching, and horizontal scaling to reach the 10K IOCs/sec production target.

---

## Database Optimization

ThreatFlow uses PostgreSQL 16 as its primary data store. Database tuning is the single most impactful lever for ingestion and query performance.

### Connection Pool Tuning

ThreatFlow manages a connection pool via the Go `database/sql` driver backed by `pgx`.

| Setting | Default | High Throughput |
|---------|---------|-----------------|
| `max_open_conns` | 20 | 50 |
| `max_idle_conns` | 2 | 10 |
| `conn_max_lifetime` | 30min | 15min |
| `conn_max_idle_time` | 5min | 5min |

**Rules of thumb:**

- `max_open_conns = 2 x CPU_cores x pod_count` for the ThreatFlow process.
- PostgreSQL `max_connections` must exceed `pool_max x pod_count` plus headroom for admin connections and monitoring.
- If you observe `pq: too many clients already` errors, increase PostgreSQL `max_connections` or reduce the pool size per pod.
- Keep `conn_max_lifetime` shorter than PostgreSQL `idle_in_transaction_session_timeout` to avoid stale connections.

### Indexing Strategy

The indexes below are critical for ingestion deduplication and query performance. They correspond to the schema defined in [data-model.md](data-model.md).

| Index | Type | Columns | Purpose |
|-------|------|---------|---------|
| `UNIQUE (pattern_hash)` | B-tree | `pattern_hash` | SHA-256 deduplication on insert |
| `idx_iocs_type` | B-tree | `type` | Filter IOCs by indicator type |
| `idx_iocs_value` | B-tree | `value` | Exact-match lookups |
| `idx_iocs_feed` | B-tree | `feed_id` | Per-feed queries and dashboard |
| `idx_iocs_confidence` | B-tree | `confidence` | Threshold filtering and sorting |
| `GIN (tags)` | GIN | `tags` | Tag-based filtering (`@>` operator) |
| `GIN (tsvector)` | GIN | `description`, `value` | Full-text search |
| `UNIQUE (stix_id)` on `stix_objects` | B-tree | `stix_id` | STIX ID deduplication |
| `idx_stix_objects_type` | B-tree | `stix_type` | Filter by STIX object type |
| `GIN (content)` on `stix_objects` | GIN | `content` | JSONB property queries |

**Maintenance notes:**

- Run `REINDEX CONCURRENTLY` if index bloat exceeds 30% (check with `pgstattuple`).
- For bulk imports, consider dropping non-unique indexes, importing, then recreating them. The `pattern_hash` unique index must remain to enforce deduplication.

### Table Partitioning (>1M IOCs)

When the `iocs` table exceeds 1 million rows, partition by `created_at` using monthly ranges:

```sql
CREATE TABLE iocs (
    id UUID NOT NULL,
    stix_id VARCHAR(128),
    type VARCHAR(50) NOT NULL,
    value TEXT NOT NULL,
    pattern TEXT,
    pattern_hash CHAR(64),
    feed_id UUID,
    source VARCHAR(255),
    confidence INT,
    description TEXT,
    tags TEXT[],
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN DEFAULT FALSE,
    cve VARCHAR(50),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ
) PARTITION BY RANGE (created_at);

CREATE TABLE iocs_2026_01 PARTITION OF iocs
    FOR VALUES FROM ('2026-01-01') TO ('2026-02-01');

CREATE TABLE iocs_2026_02 PARTITION OF iocs
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');
```

**Partition management:**

- Create partitions at least one month ahead to avoid insert failures.
- Use `pg_partman` or a cron job to automate partition creation.
- Queries that include a `created_at` range predicate will benefit from partition pruning.
- Old partitions can be detached and archived rather than deleted, preserving audit history.

### VACUUM and Maintenance

ThreatFlow's `iocs` table is write-heavy due to continuous feed ingestion. Default PostgreSQL autovacuum settings may fall behind.

**Recommended settings for the `iocs` table:**

```sql
ALTER TABLE iocs SET (
    autovacuum_vacuum_scale_factor = 0.05,
    autovacuum_analyze_scale_factor = 0.02,
    autovacuum_vacuum_cost_delay = 10
);
```

**Monitoring queries:**

```sql
-- Dead tuple count per table
SELECT relname, n_dead_tup, last_autovacuum
FROM pg_stat_user_tables
WHERE schemaname = 'public'
ORDER BY n_dead_tup DESC;

-- Table bloat estimate
SELECT pg_size_pretty(pg_total_relation_size('iocs')) AS total_size,
       pg_size_pretty(pg_relation_size('iocs')) AS table_size;
```

- Run `ANALYZE` weekly (or after large bulk imports) to keep the query planner accurate.
- Monitor `n_dead_tup` in Grafana; alert if it exceeds 100K on any table.

---

## Caching Strategy (v0.5+)

Redis caching is planned for v0.5 to reduce PostgreSQL load and improve p99 latency for hot-path queries.

### Redis Cache Layers

| Cache | Key Pattern | TTL | Purpose |
|-------|-------------|-----|---------|
| Hot IOCs | `tf:ioc:{id}` | 15min | Most recently ingested or queried IOCs |
| Feed status | `tf:feed:{id}:status` | 5min | Poll state, last poll time, error count |
| STIX bundles | `tf:stix:bundle:{id}` | 1h | Pre-computed export bundles |
| Correlation results | `tf:corr:{ioc_id}` | 30min | Recent IOC-to-finding matches |
| Dedup bloom filter | `tf:dedup:bloom` | None | Probabilistic check before DB insert |

### Cache-Aside Pattern

All read endpoints follow the cache-aside (lazy-loading) pattern:

```
GET /api/v1/iocs/{id}
  1. Check Redis for key tf:ioc:{id}
  2. Cache hit  -> return cached JSON, set response header X-Cache: HIT
  3. Cache miss -> query PostgreSQL
                -> serialize to JSON
                -> SET tf:ioc:{id} with 15min TTL
                -> return JSON, set response header X-Cache: MISS
```

### Write-Through on Ingestion

When a new IOC is ingested:

1. Validate and persist to PostgreSQL.
2. Write to Redis (`SET tf:ioc:{id}` with 15min TTL).
3. Invalidate any affected correlation caches (`DEL tf:corr:{id}`).

This ensures that the most recent IOCs are always cache-warm without requiring a read to trigger population.

### Cache Invalidation

- IOC update or revocation: delete `tf:ioc:{id}` and `tf:corr:{id}`.
- Feed re-poll: delete `tf:feed:{id}:status`.
- STIX bundle re-export: delete `tf:stix:bundle:{id}`.
- In case of doubt, flush the entire `tf:*` namespace. TTLs provide a safety net.

---

## Benchmarking

### Running Benchmarks

```bash
# Unit benchmarks (no external dependencies)
go test -bench=. -benchmem -count=5 ./internal/...

# IOC ingestion benchmark (requires running PostgreSQL)
go test -tags integration -bench=BenchmarkIOCIngestion -benchmem -count=5 ./internal/...

# API endpoint benchmark (requires running service + DB)
go test -tags integration -bench=BenchmarkListIOCs -benchmem ./internal/api/...

# Bulk import benchmark via CLI
time threatflow ioc import --file large_feed.csv --source benchmark --batch-size 1000

# Load test with hey (HTTP benchmarking tool)
hey -n 10000 -c 50 -m POST \
    -H "Content-Type: application/json" \
    -d '{"type":"ipv4-addr","value":"198.51.100.1","source":"bench"}' \
    http://localhost:8091/api/v1/iocs
```

### Example Results (v0.2 target -- single pod, 4 CPU, 8GB RAM)

```
BenchmarkIOCIngestion-4       1000       1.2ms/op      4096 B/op    12 allocs/op
BenchmarkListIOCs-4           5000       0.8ms/op      2048 B/op     8 allocs/op
BenchmarkSTIXBundleExport-4    200       5.0ms/op     32768 B/op    64 allocs/op
BenchmarkDeduplication-4      2000       0.5ms/op      1024 B/op     4 allocs/op
BenchmarkBulkImport1K-4         50      20.0ms/op    524288 B/op   256 allocs/op
```

These are target baselines. Actual results will vary with hardware, PostgreSQL configuration, and dataset size. Track results across versions to detect regressions.

---

## Scaling Guide

### Horizontal Scaling

ThreatFlow is stateless -- all state lives in PostgreSQL (and Redis at v0.5). This means you can scale horizontally by adding pod replicas behind a load balancer.

**Considerations:**

- **Database bottleneck**: add PostgreSQL read replicas for query-heavy workloads. Route all `GET` requests to replicas, all `POST`/`PUT`/`DELETE` to the primary.
- **Feed polling**: only one pod should poll a given feed at a time. Use leader election (e.g., PostgreSQL advisory locks or a distributed lock in Redis) to prevent duplicate ingestion.
- **CITADEL integration**: each pod independently authenticates to CITADEL via HMAC. No shared state required.
- **Health checks**: Kubernetes readiness probes should hit `GET /api/v1/health`. Liveness probes can use the same endpoint with a stricter timeout.

### Vertical Scaling Recommendations

| IOC Count | PostgreSQL | ThreatFlow Pod | Redis |
|-----------|-----------|----------------|-------|
| <10K | 2 CPU, 4GB RAM | 1 CPU, 256MB RAM | Not needed |
| 10K--100K | 4 CPU, 8GB RAM | 2 CPU, 512MB RAM | 1 CPU, 1GB RAM |
| 100K--1M | 8 CPU, 32GB RAM | 4 CPU, 1GB RAM | 2 CPU, 4GB RAM |
| >1M | 16 CPU, 64GB RAM | 8 CPU, 2GB RAM | 4 CPU, 8GB RAM |

For the >1M tier, also enable table partitioning and consider a dedicated PostgreSQL cluster (e.g., Patroni or CloudNativePG).

---

## Request Size Limits

| Endpoint | Max Body | Rationale |
|----------|---------|-----------|
| `POST /api/v1/iocs` | 64KB | Single IOC with metadata |
| `POST /api/v1/stix/bundles` | 10MB | Bundle with up to ~10K objects |
| `POST /api/v1/iocs/bulk` | 5MB | Bulk import (up to 1K IOCs per request) |
| `GET` responses | No limit | Pagination enforced (max 100 items/page) |

These limits are enforced by middleware. Requests exceeding the limit receive `413 Payload Too Large`. Adjust via `THREATFLOW_MAX_BODY_SIZE` if needed, but increasing STIX bundle limits beyond 10MB may cause memory pressure under concurrency.

---

## Monitoring Checklist

Before declaring a deployment production-ready, confirm the following metrics are exported and alerted on:

| Metric | Source | Alert Threshold |
|--------|--------|-----------------|
| IOC ingestion rate (IOCs/sec) | Prometheus counter | < target for version |
| API p99 latency | Prometheus histogram | > target for version |
| PostgreSQL active connections | `pg_stat_activity` | > 80% of `max_connections` |
| PostgreSQL dead tuples | `pg_stat_user_tables` | > 100K on any table |
| Redis cache hit ratio | Redis INFO stats | < 70% after warm-up |
| Redis memory usage | Redis INFO memory | > 80% of `maxmemory` |
| ThreatFlow pod memory | Kubernetes metrics | > 80% of limit |
| Feed poll errors (consecutive) | Application log counter | > 3 consecutive failures |

See [deployment.md](deployment.md) for Kubernetes resource configuration and [troubleshooting.md](troubleshooting.md) for common performance issues.
