# VIGIL — Ecosystem Health Monitor

> **Status: design-stage.** VIGIL is documented in
> [../../ARCHITECTURE.md:32](../../ARCHITECTURE.md#L32) and
> [marshal-engine.md](./marshal-engine.md) but **not yet implemented
> in v1.0.0**. This document describes the intended behaviour so
> ecosystem callers can plan integration; the code lands in v2.0.

## Purpose

VIGIL answers one question for every platform in the OpenSecStack
ecosystem:

> *"Is now a safe time to perform governance-relevant work?"*

It synthesises telemetry from CITADEL, IRFlow, ThreatFlow, NIS2
Compass, and APIGuard into a single colour-coded health signal:

| Colour | Meaning | Effect on MARSHAL |
|---|---|---|
| **GREEN** | Normal operation — everything within tolerance | Baseline — no modification to decisions |
| **AMBER** | Elevated risk — one or more indicators above threshold | MARSHAL adds a WARN gate-result for all decisions; requires extra context in reasons |
| **RED** | Critical — an unresolved HARD_STOP, severe WORM lag, or chain verification failure | MARSHAL adds an AMBER → RED escalation rule that can refuse non-emergency actions until the red state clears |

## Inputs

VIGIL is a **consumer** of telemetry, not a producer. Planned inputs:

### From IRFlow
- Unresolved P1 incident count (> 0 → AMBER, > 3 → RED)
- HARD_STOP events in the last hour (> 0 → AMBER)
- Average time-since-creation of open P1s (> 24 h → AMBER)

### From CITADEL itself
- WORM chain verification status (`invalid` → RED; always)
- Anchor signature lag (> 10 min since last anchor → AMBER)
- WORM append failure rate (> 1% over 5 min → AMBER)

### From APIGuard
- Critical finding rate (> 3 criticals/hour → AMBER)
- Active scan failure rate (> 10% → AMBER)

### From ThreatFlow
- High-confidence IOC feed gap (no new feed in > 6 h → AMBER)

### From NIS2 Compass
- Article 23 notification success rate (< 90% in last 24 h → AMBER)
- Assessment freshness age (> 90 days → AMBER; > 180 days → RED)

## Aggregation rule

RED dominates AMBER dominates GREEN. Any single RED input forces the
overall status to RED.

The individual input colours are exposed separately on the VIGIL
endpoint; operators can see which dimension triggered the escalation.

## Endpoint (planned)

```
GET /api/v1/vigil/status
```

Response (planned):

```json
{
  "overall":    "AMBER",
  "updated_at": "2026-04-19T10:15:00Z",
  "components": [
    { "name": "worm_chain",   "status": "GREEN", "since": "2026-04-12T00:00:00Z" },
    { "name": "irflow_p1",    "status": "AMBER", "value": 2, "threshold": "> 0",  "since": "2026-04-19T08:22:00Z" },
    { "name": "nis2_success", "status": "GREEN", "value": 99.2 },
    { "name": "apiguard_crit","status": "GREEN", "value": 1 },
    { "name": "threatflow",   "status": "GREEN", "since": "2026-04-12T00:00:00Z" }
  ]
}
```

## Interaction with MARSHAL

In v2.0, VIGIL's output becomes an **explicit input to MARSHAL gate
evaluation**:

- **GREEN**: baseline; MARSHAL evaluates normally.
- **AMBER**: MARSHAL adds VIGIL's colour to `decision.reasons[]` but
  does not change outcomes.
- **RED**: a special rule (`VIGIL_RED_NONEMERGENCY_BLOCK`) will REFUSE
  action types marked non-emergency until VIGIL recovers. Emergency
  types (`CONTAIN`, `ISOLATE`, `CREATE_INCIDENT`) bypass the rule.

This is why VIGIL cannot be a v1.0.0 feature: it requires every
platform to publish clean telemetry *and* a MARSHAL rule that won't
produce surprises when the health state changes mid-operation.

## Why not alerting?

Prometheus / Grafana already alert on these signals individually.
VIGIL is different because:

1. **In-band.** VIGIL's state is available to MARSHAL at decision
   time, not just to a pager.
2. **Recorded in WORM.** Any VIGIL-driven MARSHAL outcome carries the
   colour state, so auditors can replay "what was VIGIL at the moment
   of this decision?".
3. **Cross-platform.** A single pane of ecosystem health — Prometheus
   dashboards show per-service numbers but don't combine them.

## Timeline

- **v1.0.0 (today):** VIGIL is design only. No code exists. Platforms
  publish their individual health via Prometheus metrics as usual.
- **v1.1:** consumer-side scraping infrastructure in CITADEL
  (background worker polls the other platforms' `/health/detail`).
- **v1.2:** VIGIL computes the colour state and exposes `/vigil/status`.
  No MARSHAL integration yet.
- **v2.0:** MARSHAL rule integration. This is the last step because
  it changes decision semantics for every caller and needs a careful
  rollout plan.

## Related

- [Architecture § Time dimensions](../../ARCHITECTURE.md#L115) — time-segment basis for VIGIL latency tiers
- [MARSHAL engine](./marshal-engine.md) — the decision pipeline VIGIL will feed into
- [Known limitations](./known-limitations.md) — honest list of what CITADEL does *not* yet do, including VIGIL
- [ROADMAP.md](../ROADMAP.md#v20--multi-writer-chain-exploratory) — v2.0 plan
