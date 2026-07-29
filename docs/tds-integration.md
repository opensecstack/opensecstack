# TDS Integration Guide

This guide explains how to implement Time Dimension Segmentation (TDS) compliance in new opensecstack platform components and integrations.

For the architectural decision, see [ADR-009](../adrs/ADR-009-time-dimension-segmentation.md).

---

## The Three Tiers

| Tier | Latency bound | Implementation pattern |
|------|--------------|----------------------|
| Second hand | < 300ms | Synchronous HTTP response |
| Minute hand | 300ms – 30s | Short-lived async job with polling, or synchronous |
| Hour hand | > 30s | Background job with webhook callback or polling endpoint |

---

## Classifying a New Operation

When designing a new API endpoint or background job, answer these questions:

1. **What triggers it?** — User request, scheduled job, event?
2. **What does it do?** — Single DB query, subprocess invocation, full scan?
3. **What's the expected latency?** — P50, P95 on target hardware?
4. **What's the consequence of exceeding the bound?** — User-facing timeout, stale data, missed SLA?

Map the answers to a tier:

| If... | Tier |
|-------|------|
| User is waiting synchronously for the response | Second hand |
| Result is needed within a UI interaction but can be async | Minute hand |
| Result feeds a batch report or audit process | Hour hand |
| It involves a full scan, deep audit, or large data processing | Hour hand |

---

## Implementing Each Tier

### Second-hand operation

Synchronous HTTP handler. Must complete within 300ms at P95.

```go
// Good: synchronous, fast
func (h *Handler) GetVIGILStatus(w http.ResponseWriter, r *http.Request) {
    status, err := h.vigil.CurrentStatus(r.Context())
    if err != nil {
        http.Error(w, err.Error(), 500)
        return
    }
    json.NewEncoder(w).Encode(status)
}
```

Avoid within second-hand handlers:
- External HTTP calls (use cached data)
- Full table scans without indexes
- Subprocess invocations longer than ~50ms
- Any loop over an unbounded dataset

### Minute-hand operation

For operations that may take up to 30 seconds. Two patterns:

**Pattern A: Synchronous with generous timeout** (acceptable for < 10s operations)

```go
ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
defer cancel()
result, err := h.scanner.GenerateReport(ctx, scanID)
```

**Pattern B: Async job with polling**

```go
// POST /api/v1/reports — starts job, returns job ID immediately
func (h *Handler) StartReport(w http.ResponseWriter, r *http.Request) {
    jobID := h.jobs.Enqueue(reportJob)
    json.NewEncoder(w).Encode(map[string]string{"job_id": jobID})
    w.WriteHeader(http.StatusAccepted)
}

// GET /api/v1/reports/{job_id} — poll for result
func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
    job, _ := h.jobs.Get(jobID)
    if job.Status == "pending" {
        w.WriteHeader(http.StatusAccepted)
        return
    }
    json.NewEncoder(w).Encode(job.Result)
}
```

### Hour-hand operation

Always async. Must provide a polling endpoint or webhook callback. Never block a synchronous HTTP handler.

```go
// POST /api/v1/vigil/deep-scan — enqueues scan, returns immediately
func (h *Handler) TriggerDeepScan(w http.ResponseWriter, r *http.Request) {
    scanID := h.deepScanner.Enqueue(DeepScanJob{Period: period})
    w.WriteHeader(http.StatusAccepted)
    json.NewEncoder(w).Encode(map[string]string{
        "scan_id":    scanID,
        "poll_url":   fmt.Sprintf("/api/v1/vigil/deep-scan/%s", scanID),
        "webhook_on": "vigil_deep_completed",
    })
}
```

---

## Decomposing Cross-Tier Operations

Some operations have a fast trigger (second-hand) but slow execution (hour-hand). Decompose them:

```
Second-hand:    POST /api/v1/scans          → returns {scan_id, status: "queued"}
Second-hand:    GET  /api/v1/scans/{id}     → returns current status and progress
Hour-hand:      [background] scan execution → updates status as it runs
Second-hand:    GET  /api/v1/scans/{id}/findings → returns findings once complete
```

The caller always gets a fast response. The slow work happens in the background.

---

## TripleHash and TDS

TripleHash (Blake3 + SHA-256 + SHA-512) aligns with TDS tiers:

```go
hash := vantage_hash.TripleHash.Compute(content)

// Use Blake3 for second-hand (real-time) integrity checks
realtimeCheck := hash.Blake3Hex()

// Use SHA-256 for minute-hand (WORM chain) hashing
chainHash := hash.SHA256Hex()

// Use SHA-512 for hour-hand (archival, anchor) operations
archivalHash := hash.SHA512Hex()
```

See [citadel/docs/triple-hash.md](../citadel/docs/triple-hash.md) for the full TripleHash specification.

---

## Adding TDS to a New Platform

1. **Define the TDS tier table** — list every operation in the platform's architecture doc with its tier
2. **Annotate API endpoints** — add a `// TDS: second-hand` comment to each handler
3. **Add Prometheus histograms** — one histogram per operation to measure actual latency
4. **Set alerting rules** — alert at 80% of tier bound (warning) and 100% (critical)
5. **Add tds-scanner support** — add the new platform's operations to `sdk/tools/tds-scanner/`

### Prometheus histogram example

```go
var operationDuration = prometheus.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "opensecstack_operation_duration_seconds",
        Help:    "Duration of operations by TDS tier",
        Buckets: []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 5, 15, 30, 60, 120, 300},
    },
    []string{"platform", "operation", "tds_tier"},
)

// In the handler:
timer := prometheus.NewTimer(operationDuration.With(prometheus.Labels{
    "platform":  "apiguard",
    "operation": "scan_start",
    "tds_tier":  "second-hand",
}))
defer timer.ObserveDuration()
```

### Alerting rule example

```yaml
# Prometheus alerting rule
- alert: TDSSecondHandViolation
  expr: |
    histogram_quantile(0.95,
      rate(opensecstack_operation_duration_seconds_bucket{tds_tier="second-hand"}[5m])
    ) > 0.3
  for: 5m
  labels:
    severity: critical
  annotations:
    summary: "Second-hand operation exceeds 300ms P95"
    description: "{{ $labels.platform }}/{{ $labels.operation }} P95={{ $value }}s"
```

---

## Measuring Compliance

Run the tds-scanner against your deployment:

```bash
tds-scanner scan --target https://your-platform.internal --api-key $KEY --platform apiguard
```

Include tds-scanner in your CI/CD pipeline with `--fail-on-violation` to prevent regressions.

See [sdk/tools/tds-scanner/docs/tds-scanner.md](../sdk/tools/tds-scanner/docs/tds-scanner.md) for full scanner documentation.
