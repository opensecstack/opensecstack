## ADR-011 — Rate limiting per API key (JWT sub) with per-route overrides

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core
- Related: [`docs/architecture.md`](../docs/architecture.md),
  [`docs/api.md`](../docs/api.md),
  [`internal/ratelimit/`](../internal/ratelimit/),
  [`internal/config/config.go`](../internal/config/config.go)
  (`ServerConfig.RateLimitEnabled`, `RateLimitRPS`, `RateLimitBurst`)

## Context

VertGuard is a B2B API consumed by security teams and automated
pipelines. Rate limiting is required to protect against accidental
storms and deliberate abuse. The keying strategy (what identifies a
"client" for rate-limit purposes) must work correctly in enterprise
network environments.

Options: IP-based rate limiting, API-key-based (JWT sub), combined
IP+key, and no rate limiting.

## Decision

Rate limiting is enforced **per API key**, where the key identity is
the `sub` claim from the JWT bearer token. The token bucket
parameters (`RPS`, `Burst`) are global defaults set in
`ServerConfig`. Per-tenant overrides are stored in the
`ratelimit_overrides` table and loaded into the in-memory
`ratelimit.Limiter` via a background refresh goroutine
(`RunRefresh`, 30-second interval).

The rate limiter is implemented with `golang.org/x/time/rate`
(token bucket). The `ratelimit.Limiter` holds one bucket per
`sub` claim. Buckets for inactive keys are evicted by the GC;
no explicit TTL is needed for the common case.

When the DB is unavailable (dev mode), overrides fall back to an
in-memory `MemoryOverrideStore`. When rate limiting is disabled
(`RateLimitEnabled=false`), the middleware is a no-op.

## Reasons

- **IP-based rate limiting breaks behind NAT and proxies.** Enterprise
  callers frequently share egress IPs (corporate NAT, cloud NAT
  gateways). A single IP limit would throttle all tenants behind
  the same NAT simultaneously. JWT `sub` is the canonical per-tenant
  identifier.
- **Per-tenant overrides required.** Different tenants have different
  scan volumes. A security operations team running continuous
  automated scanning needs a higher limit than a developer testing
  the API interactively. Overrides in `ratelimit_overrides` allow
  account managers to set per-tenant limits without a code change
  or redeploy.
- **Token bucket with burst.** Security scans are bursty by nature
  (batch processing after an incident). Token bucket with a
  configurable burst allows short spikes without rejecting requests,
  while enforcing a sustained-rate ceiling.
- **In-memory with DB persistence.** In-memory buckets have
  sub-microsecond check latency. DB persistence is only for the
  override configuration (not the token bucket state), so DB
  latency is not on the per-request critical path.

## Consequences

- **Token state is per-process.** Bucket state is not shared across
  pods. A request routed to a different pod gets a fresh bucket.
  This means the effective rate limit in a multi-pod deployment
  is `pods × RPS` per API key. For the current single-pod
  deployment model this is correct. Multi-pod operators must set
  `RateLimitRPS` to `intended_limit / pod_count`.
- **Override refresh latency.** Overrides are refreshed every 30
  seconds. A new override takes up to 30 s to take effect across
  all pods.
- **Unauthenticated endpoints not rate-limited.** `/health` and
  `/metrics` are unauthenticated and bypass the rate limiter.
  These endpoints are bounded by their own lightweight handlers.

## Alternatives considered + rejected

- **IP-based rate limiting.** Breaks behind NAT/proxies; throttles
  unrelated tenants sharing an egress IP. **Rejected.**
- **IP + JWT combined.** More complex; still breaks for NAT; adds
  no meaningful security benefit over JWT-only for a B2B API where
  all callers are authenticated. **Rejected.**
- **No rate limiting.** A single misconfigured scanner could
  saturate the ML service and cause cascade failures (see ADR-010).
  Rate limiting is a prerequisite for the circuit breaker to
  function as designed. **Rejected.**
- **External rate limiter (Envoy, nginx).** Adds infrastructure
  dependency; JWT `sub` extraction requires L7 inspection. The
  in-process implementation is simpler and sufficient at current
  scale. **Deferred to v1.x.**

## Validation

- `go test ./internal/ratelimit/...` covers bucket creation, RPS
  enforcement, burst allowance, override application, and refresh.
- Integration test: send `RPS × 2` requests/s under one JWT;
  verify ≥ 50% are rejected with HTTP 429.
- `GET /admin/ratelimit/overrides` must return the configured
  overrides; `PUT /admin/ratelimit/overrides/:sub` must update
  within one refresh interval.

## Follow-ups

- Multi-pod rate limiting: evaluate Redis-backed token bucket
  (e.g. `redis-cell`) when horizontal scaling is required.
- Per-route overrides: extend `ratelimit_overrides` schema to
  include a `route` column for endpoint-specific limits (e.g.
  lower limit on the expensive ML-enriched scan path).
