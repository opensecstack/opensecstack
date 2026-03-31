# APIGuard Load Testing

## Benchmark Suite

APIGuard ships with Go benchmarks in `benches/scan_bench_test.go`:

```bash
cd apiguard
go test ./benches/... -bench=. -benchmem -count=3
```

### Current Benchmarks

| Benchmark | Operation | Target |
|-----------|-----------|--------|
| `BenchmarkTargetURLParse` | URL validation + SSRF check | < 1 µs |
| `BenchmarkScanRequestMarshal` | JSON encode scan request | < 5 µs |
| `BenchmarkFindingMarshal` | JSON encode single finding | < 2 µs |
| `BenchmarkUUIDGeneration` | UUID v4 generation | < 500 ns |
| `BenchmarkSHA256Hash` | SHA-256 (WORM chain link) | < 1 µs |

---

## Load Test Scenarios

### Scenario 1: Sustained Scan Load

Simulate a CI/CD pipeline triggering 50 concurrent scans.

```bash
# Using hey (HTTP load generator)
hey -n 200 -c 50 -m POST \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"target":"https://httpbin.org/spec.json"}' \
  http://localhost:8080/api/v1/scans
```

**Pass criteria:**
- P99 latency < 5s for scan creation
- Zero 5xx errors
- All scans complete within 10 min

### Scenario 2: Finding Query Load

Simulate dashboard users querying findings.

```bash
hey -n 10000 -c 100 -m GET \
  -H "Authorization: Bearer $JWT" \
  http://localhost:8080/api/v1/findings?severity=critical
```

**Pass criteria:**
- P99 latency < 200 ms
- Zero 5xx errors
- Rate limiter engages at configured threshold

### Scenario 3: Report Generation Under Load

Stress test PDF/SARIF report generation.

```bash
hey -n 50 -c 10 -m GET \
  -H "Authorization: Bearer $JWT" \
  "http://localhost:8080/api/v1/scans/$SCAN_ID/report?format=pdf"
```

**Pass criteria:**
- P99 latency < 30s (PDF generation is compute-intensive)
- No OOM kills
- Memory usage stays under 2x baseline

### Scenario 4: API Key Auth Brute Force

Verify rate limiting protects auth endpoints.

```bash
hey -n 1000 -c 50 -m POST \
  -H "Content-Type: application/json" \
  -d '{"api_key":"invalid-key"}' \
  http://localhost:8080/api/v1/auth/token
```

**Pass criteria:**
- Rate limiter returns 429 after 20 requests/min per IP
- No auth bypass under load
- Response time remains constant (no timing oracle)

---

## Performance Regression CI

Add this step to CI to catch performance regressions:

```yaml
- name: Run benchmarks
  run: |
    go test ./benches/... -bench=. -benchmem -count=5 \
      | tee bench-results.txt

- name: Compare against baseline
  run: |
    if [ -f bench-baseline.txt ]; then
      go install golang.org/x/perf/cmd/benchstat@latest
      benchstat bench-baseline.txt bench-results.txt
    fi

- name: Upload benchmark results
  uses: actions/upload-artifact@v4
  with:
    name: bench-results
    path: bench-results.txt
```

### Updating Baseline

After a confirmed performance improvement:

```bash
go test ./benches/... -bench=. -benchmem -count=10 > bench-baseline.txt
git add bench-baseline.txt
git commit -m "perf: update benchmark baseline for v1.0.0"
```

---

## Profiling

APIGuard exposes pprof endpoints in development mode:

```bash
# CPU profile (30 seconds)
go tool pprof http://localhost:8080/debug/pprof/profile?seconds=30

# Memory profile
go tool pprof http://localhost:8080/debug/pprof/heap

# Goroutine dump
curl http://localhost:8080/debug/pprof/goroutine?debug=2
```

### Key Metrics to Watch

| Metric | Healthy | Investigate |
|--------|---------|------------|
| Goroutine count | < 500 | > 1000 (possible leak) |
| Heap in use | < 500 MB | > 1 GB |
| GC pause | < 5 ms | > 20 ms |
| DB pool active | < max_open_conns | = max_open_conns (pool exhausted) |

---

## Performance Targets (v1.0.0)

| Operation | P50 | P99 | Notes |
|-----------|-----|-----|-------|
| `POST /scans` (create) | < 100 ms | < 500 ms | Excludes scan execution time |
| `GET /findings` (list) | < 50 ms | < 200 ms | With pagination |
| `GET /scans/{id}/report` (PDF) | < 5 s | < 30 s | Depends on finding count |
| `GET /health` | < 5 ms | < 50 ms | Includes DB ping |
| Scan execution (small spec) | 20 s | 60 s | < 50 endpoints |
| Scan execution (large spec) | 5 min | 15 min | 500+ endpoints |
| Finding write throughput | 100/s | — | Batch insert |
| WORM event emission | < 50 ms | < 200 ms | Async, non-blocking |
