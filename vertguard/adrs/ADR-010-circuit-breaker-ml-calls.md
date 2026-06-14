## ADR-010 — Circuit breaker on all Python ML service calls

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.2
- Owners: VertGuard core, Security ML
- Related: [`docs/ml-architecture.md`](../docs/ml-architecture.md),
  [`internal/ml/`](../internal/ml/),
  [`internal/config/config.go`](../internal/config/config.go)
  (`MLConfig.Timeout`)

## Context

ML inference via the Python gRPC service (ADR-001, ADR-012) can be
slow or fail under load: GPU contention, model loading, OOM kills,
and network hiccups all manifest as high-latency or errored gRPC
calls. Without a circuit breaker, slow ML responses cascade: every
concurrent scan request blocks waiting for the ML call, exhausting
the Go HTTP server's goroutine pool and causing API-wide timeouts
for all callers — including those whose requests would not use ML
at all.

## Decision

A **circuit breaker** wraps every gRPC call to the Python ML service.
When the breaker is open (triggered by consecutive timeouts or errors),
ML calls return immediately with a `CLEAN` classification at low
confidence rather than blocking. The scan result is returned to the
caller with an `ml_unavailable` flag so the caller knows the ML
enrichment was skipped.

This is a **fail-open** policy for ML enrichment: availability is
preferred over completeness when the ML service is degraded. The
Rust pattern-matching and regex prefilter layers remain active; only
the ML enrichment step is skipped.

The breaker is configured via `MLConfig.Timeout` (max per-call
duration) and the consecutive-error threshold is hardcoded to 5
(configurable in a follow-up). Metrics (`vertguard_ml_inference_seconds`,
`vertguard_ml_circuit_open_total`) expose breaker state to Prometheus.

## Reasons

- **Cascade prevention.** Without a breaker, a slow ML service
  causes all scan handlers to block simultaneously. The Go HTTP
  server's default concurrency limit means a 10-second ML timeout
  with 100 concurrent requests exhausts the pool in seconds.
- **ML enrichment is not the primary defence.** The Rust pattern
  library and regex prefilter operate independently of ML. A BLOCKED
  result from patterns is still returned even when the ML service
  is unavailable. ML enrichment improves accuracy on borderline
  inputs; it is not the only detection layer.
- **Fail-open vs fail-closed tradeoff.** Fail-closed (return 503
  when ML is unavailable) would cause all scan endpoints to fail
  during ML service degradation, leaving callers unable to process
  content at all. Fail-open returns a less-enriched result, which
  is correct for a defence-in-depth system — other layers still
  protect.
- **Configurable via `MLConfig`.** Operators can tune `Timeout`
  without a code change. The breaker threshold will be exposed as
  a config field in the follow-up.

## Consequences

- **Reduced detection accuracy during ML outage.** Borderline inputs
  that would have been BLOCKED by ML may be returned as SUSPICIOUS
  or CLEAN when the breaker is open. The pattern layer catches
  unambiguous attacks; paraphrase and indirect injection may slip
  through at reduced confidence.
- **Observability required.** Operators must alert on
  `vertguard_ml_circuit_open_total` > 0 to know when the ML service
  is degraded. The runbook must document recovery steps.
- **AlwaysScore mode.** When `MLConfig.AlwaysScore=true`, the ML
  call is attempted for every request (not just borderline inputs).
  The breaker applies equally; fail-open behaviour is unchanged.

## Alternatives considered + rejected

- **No circuit breaker (timeout only).** `MLConfig.Timeout` caps
  individual call duration but does not prevent pile-up when the
  timeout is longer than the request rate. **Rejected.**
- **Fail-closed circuit breaker.** Return 503 to all callers when
  ML is unavailable. Breaks the primary scan API for all users
  during ML degradation; conflicts with the availability requirement
  for a security-critical path. **Rejected.**
- **Thread pool isolation.** Allocate a fixed goroutine pool for ML
  calls; requests beyond the pool are rejected. Adds complexity;
  circuit breaker achieves the same cascade-prevention goal more
  simply. **Rejected.**

## Validation

- `go test ./internal/ml/...` must cover breaker open/close state
  transitions, fail-open return value, and timeout path.
- Load test: simulate ML service latency of 30 s; verify that
  `/api/v1/prompt/scan` returns results (not timeouts) within
  `MLConfig.Timeout + 50 ms` for all concurrent requests.
- Metric `vertguard_ml_circuit_open_total` must increment when the
  breaker opens.

## Follow-ups

- Expose consecutive-error threshold as `MLConfig.BreakerThreshold`.
- Add half-open probe: attempt one ML call per 30 s when the
  breaker is open to detect recovery without operator intervention.
- Runbook: add section on ML circuit breaker recovery procedure
  to `operator-runbook.md`.
