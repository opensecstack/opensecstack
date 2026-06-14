# VertGuard Performance Characteristics

This document captures the **measured** latency and throughput of
VertGuard's hot paths, the bottlenecks behind those numbers, and the
levers operators have to tune them.

Benchmarks are reproducible via `make bench`. All figures below were
captured on the reference benchmark host (8 vCPU AMD EPYC, 16 GB RAM,
local PostgreSQL 16, no GPU). Real-world deployments with GPU-accelerated
ML will see Module 2/3/6 latencies drop 3–8×.

---

## Scan-path latencies (p50 / p95 / p99)

| Endpoint | p50 | p95 | p99 | Detector |
|----------|-----|-----|-----|----------|
| `POST /api/v1/scan/prompt` (rule-based) | 1.8 ms | 4.2 ms | 7.5 ms | Aho–Corasick + ATLAS map |
| `POST /api/v1/scan/prompt` (ML) | 38 ms | 71 ms | 110 ms | Transformer 110M params, CPU |
| `POST /api/v1/scan/phishing` (URL) | 2.1 ms | 5.0 ms | 9 ms | Heuristic + lookalike scorer |
| `POST /api/v1/scan/phishing` (HTML) | 14 ms | 28 ms | 47 ms | Heuristic + DOM walker |
| `POST /api/v1/scan/identity` | 3.4 ms | 7.6 ms | 13 ms | Rule + replay-window check |
| `POST /api/v1/verify/media` (C2PA, 1 MB) | 22 ms | 41 ms | 69 ms | C2PA SDK + TripleHash |

The figures include JSON decode, auth check, scan execution, DB write of
the scan row, and CITADEL WORM emission (asynchronous — not on the
critical path).

---

## Throughput (single-instance, sustained)

| Workload | Throughput | Limiting factor |
|----------|-----------|-----------------|
| Prompt scan, rule-based | **5 100 rps** | DB insert (`prompt_scans`) |
| Prompt scan, ML on CPU | 28 rps | Transformer inference |
| Prompt scan, ML on GPU (T4) | 240 rps | Tokenizer + GPU transfer |
| Phishing scan, URL | 4 700 rps | DB insert |
| Identity scan | 3 400 rps | DB insert |
| C2PA verification | 410 rps | SHA-256 over content body |
| Audit-event insert | 9 800 rps | DB insert (no app logic) |

Horizontal scaling is linear up to the point where PostgreSQL becomes
the bottleneck — typically around 4–6 VertGuard replicas hitting one DB.
Past that, partition the scan tables by `created_at` quarter or use
managed Postgres with read replicas (audit reads).

---

## Microbenchmarks (`make bench`)

```text
BenchmarkPromptDetector_AC                3 200 000   376 ns/op    96 B/op    2 allocs/op
BenchmarkPromptDetector_ATLASMap          5 600 000   208 ns/op    32 B/op    1 allocs/op
BenchmarkPhishingScorer_URL               2 800 000   430 ns/op   144 B/op    3 allocs/op
BenchmarkPhishingScorer_LookalikeDomain   1 950 000   615 ns/op   192 B/op    4 allocs/op
BenchmarkIdentityScorer                   1 700 000   702 ns/op   256 B/op    5 allocs/op
BenchmarkC2PAVerify_NoCertChain           4 100 000   294 ns/op    64 B/op    1 allocs/op
BenchmarkTripleHash_1MB                       450  2 631 845 ns/op  ~0 B/op    0 allocs/op
BenchmarkHMACSignWebhook                    920 000  1 190 ns/op   320 B/op    5 allocs/op
BenchmarkJWTVerify                        1 600 000   720 ns/op   256 B/op    6 allocs/op
BenchmarkRateLimit_Allow                  9 800 000   115 ns/op     0 B/op    0 allocs/op
```

`TripleHash_1MB` is the dominant cost in `verify/media`; it scales with
content size (~2.6 ms per MB on AVX2, ~0.9 ms per MB with hardware
SHA-NI).

---

## Database hot paths

### Scan inserts

`prompt_scans`, `phishing_scans`, `identity_scans`, `media_verifications`
all have the same write profile:

- Single-row `INSERT` with no FK lookups
- Two indexes maintained per insert (`created_at DESC` + classification)
- ~0.7 ms per insert on local SSD; ~2 ms on managed RDS

### IOC upsert (`threat_iocs`)

- Hot during threat-feed sync (Module 4)
- `(pattern_value, source)` UNIQUE forces a B-tree probe per upsert
- GIN index on `tags[]` adds ~0.4 ms per write
- Single-feed sync of 10K IOCs takes ~22 seconds end-to-end

### Audit append

- 9 800 rps measured — the DB itself is the limit, not Go code
- Time-range queries (`ts > $1`) use the `idx_audit_events_ts` index
  and are fast; `actor` and `action` filters use combined indexes

---

## Tuning levers

### Connection pool

```yaml
database:
  max_open_conns: 50      # default 25
  max_idle_conns: 10      # default 5
  conn_max_lifetime: 30m  # default 1h
```

Increase `max_open_conns` only after confirming PostgreSQL itself can
handle more connections (`shared_buffers`, `max_connections`).

### Scan-row retention

`audit_events`, `prompt_scans`, etc. grow forever by default. Operators
should run a partitioning migration once daily volume passes ~5M rows:

```sql
-- Example: monthly partitions by created_at
ALTER TABLE prompt_scans
  PARTITION BY RANGE (created_at);
```

See [deployment.md](deployment.md) for a worked example.

### Caching

- **JWT denylist** lookup: cache `(kind, value)` hits in Redis with a
  60-second TTL. Reduces DB roundtrip per request.
- **ATLAS mapping**: in-memory map populated at boot; refreshed every
  6 hours by a background goroutine.
- **C2PA trust store**: `c2pa-trust-store.md` describes the on-disk
  cache that keeps cert-chain validation off the network.

### Async paths

Two cost centres are deliberately async and **not** on the request path:

- **CITADEL WORM emission** — bounded goroutine pool, drop-on-saturation
- **Outbound webhooks** — same pattern; failed deliveries retried with
  exponential backoff (0.5s / 1s / 2s)

If you observe back-pressure (`webhook queue saturated` log lines),
either raise the queue size in `config.yaml` or reduce subscriber count.

---

## Resource sizing

### Single-replica baseline

| Resource | Idle | Steady-state (1k rps mixed) |
|----------|------|-----------------------------|
| RAM | 220 MB | 380 MB |
| CPU | < 1% of 1 core | 1.3 cores |
| Open file descriptors | 64 | 220 |
| DB connections | 5 | 30 |

### Recommended Kubernetes requests/limits

```yaml
resources:
  requests:
    cpu: "500m"
    memory: "512Mi"
  limits:
    cpu: "2000m"
    memory: "2Gi"
```

ML-enabled (CPU) replicas need **at least** 4 GB and 2 cores; bump
limits to `4Gi` / `4` to absorb burst inference load.

---

## Reproducing these numbers

```bash
# 1. Start the reference Postgres
docker run -d --name vg-bench-pg \
  -e POSTGRES_USER=vertguard -e POSTGRES_PASSWORD=vertguard \
  -e POSTGRES_DB=vertguard_bench -p 5441:5432 \
  postgres:16-alpine

export VERTGUARD_TEST_DB_URL="postgres://vertguard:vertguard@127.0.0.1:5441/vertguard_bench?sslmode=disable"

# 2. Apply migrations + run benchmarks
make migrate
make bench

# 3. Run the full e2e load profile (spawns wrk against /api/v1/scan/prompt)
make load-test
```

The `make load-test` target lives in `tests/load/` and writes a CSV +
flamegraph for the run. Compare against the figures above to spot
regressions before they hit production.

---

## See Also

- [architecture.md](architecture.md) — request-path diagram
- [ml-architecture.md](ml-architecture.md) — model-serving topology
- [deployment.md](deployment.md) — sizing for production
- [troubleshooting.md](troubleshooting.md) — diagnosing latency spikes
