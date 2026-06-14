## ADR-009 — In-memory nonce cache for replay prevention

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core
- Related: [`docs/architecture.md`](../docs/architecture.md),
  [`internal/identity/`](../internal/identity/),
  [`internal/config/config.go`](../internal/config/config.go)
  (`IdentityConfig.ReplayWindow`, `IdentityConfig.ReplayThreshold`)

## Context

VertGuard webhooks (ThreatFlow inbound, IRFlow callbacks) and the
identity verification module (Module 6) require replay prevention:
a request with a previously-seen nonce must be rejected. This is
standard defence against replay attacks on HMAC-signed webhooks.

Options: in-memory per-process cache, distributed cache (Redis),
or PostgreSQL-backed nonce table.

## Decision

Replay-prevention nonce tracking uses an **in-memory per-process
cache** with a configurable time window. The window is controlled by
`IdentityConfig.ReplayWindow` (env `VERTGUARD_IDENTITY_REPLAY_WINDOW`,
default `5m`). A background janitor goroutine (`StartJanitor()`)
evicts expired entries. The threshold for flagging a replay burst
is `IdentityConfig.ReplayThreshold`.

This is an explicit, documented limitation: **multi-pod deployments
require a Redis-backed implementation** (not yet shipped). The
current implementation is correct for single-pod deployments.

## Reasons

- **Single-pod sufficiency.** Phase 4.1 deployments target a single
  Go pod behind a load balancer with session affinity, or a single
  instance in ASNI's constrained environment. Cross-pod replay
  prevention is not required at this deployment scale.
- **Operational simplicity.** Redis adds a dependency that must be
  operated, monitored, and secured. For a security-critical service,
  every additional component is an additional attack surface. The
  in-memory implementation eliminates this dependency entirely.
- **Five-minute window is sufficient.** ThreatFlow and IRFlow webhook
  nonces are timestamp-bound; a 5-minute window rejects all replays
  within the HMAC signature validity period. The window is
  configurable for tighter policies.
- **PostgreSQL nonce table rejected.** DB round-trips on every
  webhook hit add 1–5 ms latency on the hot path. The janitor
  goroutine runs in-process; no network hop required for the
  common case (nonce not seen before).

## Consequences

- **Multi-pod limitation.** When VertGuard is scaled to more than
  one pod without session affinity, a replay request routed to
  a different pod than the original will not be detected. This
  is documented in `docs/scaling.md` and in operator runbook
  section 2.4 as a known limitation.
- **Memory-bounded.** High-volume webhook traffic with unique nonces
  fills the cache. The janitor eviction keeps the steady-state size
  proportional to `(RPS × ReplayWindow)`. At 1000 req/s with 5 min
  window, this is ≈ 300,000 entries ≈ 30 MB — acceptable.
- **Lost on restart.** An in-memory cache does not survive process
  restarts. A replay request sent immediately after a crash-restart
  would not be detected if its nonce was in the evicted cache.
  The HMAC timestamp validation is the primary defence in this
  window; the nonce cache is defence-in-depth.

## Alternatives considered + rejected

- **Redis-backed cache.** Correct for multi-pod; adds Redis
  dependency, operational complexity, and TLS configuration.
  **Deferred to a follow-up ADR; not rejected permanently.**
- **PostgreSQL nonce table.** Correct but adds DB round-trip on
  every webhook verification; latency unacceptable on hot path.
  **Rejected.**
- **No replay prevention.** HMAC timestamps provide some protection
  but allow replays within the timestamp skew window. Insufficient
  for security-critical webhook receivers. **Rejected.**

## Validation

- `go test ./internal/identity/...` covers nonce insertion, replay
  detection, janitor eviction, and window expiry.
- `POST /api/v1/identity/verify` with a replayed nonce must return
  HTTP 409 (or the configured rejection status) within the window.

## Follow-ups

- Redis-backed nonce cache: implement and document as the required
  configuration for multi-pod deployments. Gate behind
  `identity.redis_url` config key.
- Update `docs/scaling.md` with the multi-pod nonce limitation
  and the Redis migration path.
