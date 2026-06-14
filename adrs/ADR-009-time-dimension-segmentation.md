# ADR-009: Time Dimension Segmentation (TDS)

**Status**: Accepted
**Date**: 2026-03-30
**Deciders**: opensecstack architecture team

---

## Context

opensecstack platforms (APIGuard, NIS2Compass, CITADEL, IRFlow, ThreatFlow) perform operations with widely varying latency requirements. A single request-response model handles operations ranging from sub-millisecond hash computations to multi-minute full-platform audit scans.

Without explicit latency contracts, there is a recurring pattern of:
- Synchronous endpoints blocking on operations that should be async
- Fast operations being delayed by co-located slow operations
- No shared vocabulary for discussing expected response times across teams

We need a shared model for classifying operations by their latency tier and enforcing those tiers at the architectural level.

---

## Decision

We adopt **Time Dimension Segmentation (TDS)** as a cross-cutting architectural principle for all opensecstack platforms.

TDS divides operations into three tiers named after clock hands:

| Tier | Latency bound | Characteristics |
|------|--------------|----------------|
| **Second hand** | < 300ms | Synchronous, per-request, user-facing. Must not block the caller for longer than 300ms. |
| **Minute hand** | 300ms – 30s | Standard async or long-lived sync operations. Acceptable for triggered jobs and report generation. |
| **Hour hand** | > 30s | Batch, analytical, or comprehensive audit operations. Must be async with polling or callback. |

Each platform component is assigned to a TDS tier based on its operational characteristics. Operations that span tiers must be decomposed: the trigger is second-hand, the work is minute-hand or hour-hand.

---

## Rationale

### Named tiers create a shared vocabulary

"This endpoint should be second-hand" is clearer than "this should be fast." The tier names carry implicit latency contracts that everyone understands after one reading.

### Tiers map to technical patterns

| Tier | Implementation pattern |
|------|----------------------|
| Second hand | Synchronous HTTP response |
| Minute hand | Async job with polling endpoint, or synchronous with short timeout |
| Hour hand | Background job with webhook callback or polling; never synchronous |

This makes architectural decisions concrete: any hour-hand operation in a synchronous endpoint is automatically a design violation.

### Prevents performance regression by design

When a new feature is designed, the TDS tier is specified first. This constrains the implementation from the start rather than discovering performance issues after deployment.

### Aligns with TripleHash

The TripleHash scheme (Blake3 + SHA-256 + SHA-512) maps directly to TDS tiers:

| Hash | TDS tier | Use |
|------|---------|-----|
| Blake3 | Second hand | Per-request real-time integrity |
| SHA-256 | Minute hand | WORM chain hashing |
| SHA-512 | Hour hand | Long-term archival and anchor signing |

This alignment makes the connection between cryptographic assurance levels and operational latency tiers explicit.

---

## Platform TDS Assignments

### APIGuard

| Component | TDS tier |
|-----------|---------|
| Spec parse (Rust subprocess) | Second hand |
| Per-endpoint analysis (Go) | Second hand |
| CVSS scoring | Second hand |
| Scan status API | Second hand |
| HTML report generation | Minute hand |
| PDF report generation | Minute hand |
| Full scan — small spec | Minute hand |
| Full scan — large spec | Hour hand |

### NIS2Compass

| Component | TDS tier |
|-----------|---------|
| Control status update | Second hand |
| Organisation CRUD | Second hand |
| Evidence artifact upload | Minute hand |
| Audit log fetch | Minute hand |
| Full compliance export | Hour hand |

### CITADEL

| Component | TDS tier |
|-----------|---------|
| MARSHAL gate evaluation | Second hand |
| AUGUR advisory fetch | Second hand |
| VIGIL_REALTIME status poll | Second hand |
| Chain anchor age check | Minute hand |
| WORM chain verify (7 days) | Hour hand |
| VIGIL_DEEP full audit | Hour hand |

---

## Enforcement

### Design-time

All new API endpoints and background jobs must specify their TDS tier in the design document or ADR. Pull requests that introduce operations without a TDS assignment are rejected in review.

### Runtime measurement

The `tds-scanner` tool (see `sdk/tools/tds-scanner/`) measures actual operation latencies against tier bounds. It is run in CI for all platform deployments.

### Alerting

Prometheus alerting rules notify on-call when a second-hand operation's p95 latency exceeds 250ms (warning) or 300ms (critical).

---

## Alternatives Considered

### No latency classification

Continue without explicit tiers. Rejected: the recurring pattern of undifferentiated latency expectations causes repeated design mistakes.

### SLA-based (specific millisecond targets)

Assign specific millisecond targets per endpoint. Rejected: too brittle — targets vary by hardware. Tier bounds are relative and hardware-agnostic.

### CQRS pattern only

Use Command/Query separation to differentiate fast reads from slow writes. Rejected: insufficient — some queries (VIGIL_DEEP) are hour-hand, some commands (Kerkese submission) are second-hand. The read/write axis does not align with the latency axis.

---

## Consequences

**Positive**:
- Shared vocabulary for latency expectations across all teams
- Implementation patterns are prescribed by tier
- tds-scanner provides automated compliance measurement
- New contributors immediately understand the latency contract for any component

**Negative**:
- Requires upfront tier classification for every new feature
- Some operations legitimately span tiers (e.g. a scan that starts second-hand but runs hour-hand) — decomposition adds API surface area
- The 300ms second-hand bound may be too tight for some network environments; operators in high-latency environments may need to adjust tier thresholds

---

## References

- [docs/tds-integration.md](../docs/tds-integration.md) — integration guide
- [sdk/tools/tds-scanner/](../sdk/tools/tds-scanner/) — compliance measurement tool
- [.citadel/docs/triple-hash.md](../.citadel/docs/triple-hash.md) — TripleHash TDS alignment
- [.citadel/docs/vigil.md](../.citadel/docs/vigil.md) — VIGIL TDS compliance table
