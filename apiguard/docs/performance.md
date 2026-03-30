# APIGuard Performance Reference

---

## Scan Duration Benchmarks

Benchmarks run against VAmPI (deliberately vulnerable API) on a 4-core VM, all 10 OWASP modules enabled, `scanner.concurrency: 10`.

| API Size | Endpoint Count | Scan Duration | Peak Memory |
|----------|---------------|---------------|-------------|
| Small | 10–20 | 20–60 seconds | 80–120 MB |
| Medium | 20–100 | 1–5 minutes | 120–250 MB |
| Large | 100–300 | 5–15 minutes | 250–500 MB |
| Very large | 300–1000 | 15–60 minutes | 500 MB–1 GB |

Scan duration scales approximately linearly with endpoint count at fixed concurrency. Response time of the target API is the dominant variable — a slow target (>500ms per request) can multiply scan time 5–10×.

---

## Rust Parser Performance

The parser processes schema files into the APIGuard IR before any HTTP traffic begins.

| Spec Format | File Size | Parse Time |
|------------|----------|-----------|
| OpenAPI 3.0 YAML | 50 KB | < 5ms |
| OpenAPI 3.0 YAML | 500 KB | < 30ms |
| OpenAPI 3.0 YAML | 5 MB | < 200ms |
| Swagger 2.0 JSON | 200 KB | < 15ms |

The parser runs in an isolated subprocess. A malformed spec can crash the subprocess — the main Go process catches the exit code and records a scan failure. Parser memory usage is bounded by the spec file size.

---

## Concurrency Tuning

`scanner.concurrency` controls the maximum number of simultaneous HTTP requests sent to the target.

| Target Characteristics | Recommended Concurrency |
|-----------------------|------------------------|
| Internal API, no rate limiting | 20–50 |
| External API with rate limiting | 5–10 |
| Production API (caution) | 2–5 |
| API with 500ms+ response times | 10–15 |

Increasing concurrency reduces scan time but increases load on the target. Watch the target's error rate — a spike in 429 or 503 responses indicates the concurrency is too high.

---

## Rate Limit Interaction

When the target API returns HTTP 429, APIGuard backs off exponentially:

```
First 429:   wait 1s, retry
Second 429:  wait 2s, retry
Third 429:   wait 4s, retry
After 5 retries: mark test as inconclusive, continue with next
```

Set `scanner.rate_limit_rps` to stay below the target's enforced rate limit and avoid hitting 429 at all:

```yaml
scanner:
  rate_limit_rps: 20    # well below most APIs' 60–100 rps limits
  concurrency: 5
```

---

## Response Analyser Throughput

The Rust response analyser processes HTTP responses concurrently. Throughput on a single core:

| Analysis Type | Throughput |
|--------------|-----------|
| Status code + header checks | > 100,000 responses/sec |
| Body regex matching (simple pattern) | > 10,000 responses/sec |
| Body regex matching (complex BOLA pattern) | > 2,000 responses/sec |
| JSON body diff (mass assignment) | > 5,000 responses/sec |

Response analysis is never the bottleneck — network I/O always dominates.

---

## Database Performance

Findings and scan records are written to PostgreSQL at scan completion (not during scanning). The write burst at completion is proportional to the finding count.

| Finding Count | DB Write Time |
|--------------|--------------|
| 10 | < 100ms |
| 100 | < 500ms |
| 1,000 | < 3 seconds |

Indexes on `findings(scan_id)` and `findings(severity)` are required for dashboard query performance. These are created by migration `002_create_findings`.

For very high finding counts (> 1,000), use `database.max_open_conns: 50` and ensure PostgreSQL `work_mem` is at least 64 MB.

---

## Horizontal Scaling

APIGuard is stateless at the application layer. Scale horizontally by adding instances:

```
         ┌─────────────────────┐
         │   Load Balancer     │
         └──────────┬──────────┘
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
  [APIGuard 1]  [APIGuard 2]  [APIGuard 3]
        │           │           │
        └───────────┴───────────┘
                    │
          ┌─────────┴──────────┐
          ▼                    ▼
     [PostgreSQL]           [Redis]
```

All instances share `APIGUARD_JWT_SECRET`, `APIGUARD_DB_URL`, and `APIGUARD_REDIS_URL`. Redis handles distributed rate limiting — no coordination required between instances.

Maximum capacity per instance: ~20 concurrent scans with `concurrency: 10`. Each additional instance adds 20 concurrent scans.

---

## Hardware Recommendations

| Deployment | vCPU | RAM | Storage |
|-----------|------|-----|---------|
| Development | 1 | 1 GB | 10 GB |
| Small team (< 10 scans/day) | 2 | 2 GB | 50 GB |
| Medium (10–100 scans/day) | 4 | 8 GB | 200 GB |
| Large (100+ scans/day) | 8+ | 16 GB+ | 500 GB+ SSD |

Storage is dominated by the evidence JSONB in the findings table. Each finding with full evidence averages 10–50 KB. A scan with 100 findings consumes 1–5 MB of database storage.

---

## Profiling

To profile a scan run:

```bash
# Enable pprof endpoint (development only — never in production)
APIGUARD_PPROF_ENABLED=true apiguard server

# Capture a CPU profile during a scan
go tool pprof http://localhost:6060/debug/pprof/profile?seconds=30

# Capture a memory profile
go tool pprof http://localhost:6060/debug/pprof/heap
```

The Rust components expose timing via structured log output at `RUST_LOG=debug`:

```bash
RUST_LOG=debug apiguard scan --spec ./openapi.yaml --target https://api.example.com
# Logs: parser: 15ms, testgen: 8ms, analyser: 42ms per response
```
