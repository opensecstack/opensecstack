# OpenScrub ↔ IRFlow Integration

> **v1.0.0 scope: webhook contract defined; implementation tracked as
> a v1.1 follow-up.** No `internal/irflow/` package exists in the
> v1.0.0 Go tree — this page documents the contract OpenScrub will
> emit on so the IRFlow side can build the receiver and the operator
> deployment topology can plan for the dependency. The v1.0.0 image
> ships with the integration disabled by default
> (`OPENSCRUB_IRFLOW_API_URL` empty); enabling it before the v1.1
> emitter ships is a no-op.
>
> The HMAC scheme below matches the ecosystem-wide pattern
> documented in [citadel-integration.md](citadel-integration.md) and
> in the canonical [../../irflow/docs/webhook-spec.md](../../irflow/docs/webhook-spec.md):
> `timestamp + "." + raw_body`, HMAC-SHA256, ±5-minute replay window,
> 90-day secret rotation.

## Why this integration

Per [../ECOSYSTEM.md § Data Flow](../../ECOSYSTEM.md), the
ecosystem-level data-flow rule is:

> OpenScrub mitigations → IRFlow incident on sustained mitigation > 5 min

A short DDoS burst that XDP shrugs off in 30 seconds is not an
incident — it is the data plane doing its job. A *sustained*
mitigation, where the same rule has been actively dropping packets
for more than five minutes, is an operationally distinct event:

- Someone is targeting this deployment specifically.
- The mitigation may be blocking legitimate traffic if a rule was
  poisoned (threat-model row #2).
- NIS2 Article 23's 24h-initial / 72h-notification timer may start
  here (depending on operator policy).

IRFlow is the platform that turns that signal into an incident
record, runs the playbook, and feeds NIS2 Compass for notification.
OpenScrub is the source of truth for "this rule has been dropping
packets continuously for the last N minutes."

## Trigger model

The trigger is a SQL condition over the `mitigations` table, not a
push from the data plane. Each `mitigations` row records a
contiguous window in which a given rule was active (`started_at`,
`ended_at`). The control plane scans for:

```sql
SELECT id, rule_id, cidr, packets_dropped, started_at
  FROM mitigations
  JOIN rules ON rules.id = mitigations.rule_id
 WHERE mitigations.started_at < now() - interval '5 minutes'
   AND mitigations.ended_at IS NULL
   AND mitigations.irflow_emitted_at IS NULL;
```

For each matching row the control plane POSTs a single
`incident.create` webhook to IRFlow and records `irflow_emitted_at`
so the same row is not retriggered.

Idempotency: the IRFlow `incident.create` payload carries an
`event_id` derived from the mitigation row id; IRFlow dedupes on
that.

## Outbound contract — OpenScrub → IRFlow

### Request

```
POST {OPENSCRUB_IRFLOW_API_URL}/api/v1/webhooks/openscrub
Content-Type: application/json
X-Openscrub-Signature: sha256=<hex>
X-Openscrub-Timestamp: <unix-seconds>
X-Openscrub-Event-Id: <uuid>
```

### Body

```json
{
  "event_id": "openscrub-evt-2026-05-09-00123",
  "event_type": "openscrub.sustained_mitigation",
  "occurred_at": "2026-05-09T10:31:02Z",
  "source": "openscrub",
  "node": "edge-fra-1",
  "incident": {
    "kind": "sustained_ddos_mitigation",
    "title": "Sustained DDoS mitigation on 198.51.100.0/24 over 5m",
    "severity_hint": "P3"
  },
  "mitigation": {
    "id": "01J5VK…",
    "rule_id": "01J5VK…",
    "cidr": "198.51.100.0/24",
    "rule_type": "block",
    "rule_source": "threatflow",
    "packets_dropped": 184823,
    "bytes_dropped": 110891204,
    "started_at": "2026-05-09T10:25:01Z"
  }
}
```

Notes on fields:

- `mitigation.cidr` is the rule's CIDR, not the source IP that hit
  it. Source-IP fan-out is in CITADEL `openscrub.mitigation` events;
  IRFlow incidents are at the rule level so a single sustained burst
  produces one incident, not thousands.
- `mitigation.rule_source` carries the same enum as
  [citadel-integration.md](citadel-integration.md) (`operator`,
  `threatflow`). An IRFlow incident on a `threatflow`-sourced rule
  may indicate IOC source compromise (threat-model row #3) — IRFlow
  playbook should branch accordingly.
- `severity_hint` is advisory; IRFlow's own classifier sets the
  authoritative severity on the resulting incident.

### Response

IRFlow returns `202 Accepted` with the incident id, or `409` on
duplicate `event_id` (idempotent). OpenScrub treats both as success
and stamps `irflow_emitted_at` on the mitigation row.

| Code | Meaning |
|---|---|
| `202` | Accepted |
| `400` | Malformed body (do not retry; surface in audit) |
| `401` | HMAC mismatch or timestamp outside ±5 min |
| `409` | Duplicate `event_id` — treated as idempotent success |
| `5xx` | Transient — retry per backoff schedule |

## HMAC signing

The signing scheme is identical to the canonical IRFlow webhook
spec. The signed input is:

```
signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(OPENSCRUB_IRFLOW_HMAC_SECRET, signed_payload))
```

`raw_body` is the exact bytes on the wire — no re-serialisation.
The verifier on the IRFlow side rejects on:

- signature mismatch
- timestamp outside ±5 min skew
- replayed `X-Openscrub-Event-Id` (IRFlow persists a dedup table)

Constant-time compare is mandatory. Secret rotation 90 days; both
sides accept old + new during a 24 h overlap window.

## Backoff and retry policy

Mirror of the CITADEL emit pattern in
[citadel-integration.md § Delivery semantics](citadel-integration.md):

- **At-least-once.** Mitigation rows due for emission live in the
  Postgres `mitigations` table itself (not a separate outbox); the
  `irflow_emitted_at` column is the watermark.
- **Exponential backoff** on transient failure: 1s, 2s, 4s, 8s, 16s,
  32s (6 attempts), then dead-letter to a `irflow_dlq` audit row and
  `openscrub_irflow_dlq_total` counter increment.
- **Replay-safe.** The `event_id` is derived from the mitigation row
  UUID, so a retry never produces a fresh id; IRFlow's dedup table
  catches it.
- **Bounded staleness.** If IRFlow is unreachable for a sustained
  period, the loop continues to evaluate the trigger query — the
  data plane is unaffected; mitigations continue to drop packets;
  the audit chain via CITADEL WORM is independent of IRFlow.

## Disabling

Setting `OPENSCRUB_IRFLOW_API_URL=""` (empty) disables emission. No
loop runs; no DLQ accumulates. This is the v1.0.0 default and is
the recommended setting for deployments without IRFlow.

When IRFlow is configured but unreachable, the integration logs a
WARN at startup and continues to evaluate the trigger query; emission
attempts fail and retry per the backoff schedule. This is **fail-open
on the data plane** (mitigations still drop packets) and **fail-loud
on the audit plane** (the WARN + the DLQ counter make the outage
visible).

## Configuration

```bash
# Outbound to IRFlow — empty disables the integration
OPENSCRUB_IRFLOW_API_URL=https://irflow.internal:8085
OPENSCRUB_IRFLOW_HMAC_SECRET=<64-byte random — matches IRFlow side>

# Behavioural toggles
OPENSCRUB_IRFLOW_TRIGGER_AFTER=5m       # default; how long a mitigation must run before emitting
OPENSCRUB_IRFLOW_SCAN_INTERVAL=30s      # how often the trigger query runs
OPENSCRUB_IRFLOW_HTTP_TIMEOUT=10s
```

Empty `OPENSCRUB_IRFLOW_HMAC_SECRET` while `OPENSCRUB_IRFLOW_API_URL`
is set is a startup-blocking misconfiguration — the production gate
refuses to boot, mirroring the [citadel-integration.md](citadel-integration.md)
posture.

## Metrics

| Metric | Purpose |
|---|---|
| `openscrub_irflow_emit_total{result}` | Outbound `incident.create` outcomes (`ok`, `4xx`, `5xx`, `dlq`) |
| `openscrub_irflow_emit_latency_seconds` | Emit-call latency |
| `openscrub_irflow_dlq_depth` | DLQ depth (alert on sustained > 5) |
| `openscrub_irflow_pending_mitigations` | Mitigation rows matching the trigger query but not yet emitted (transient is fine; sustained > 50 means IRFlow is down) |

## Audit

The trigger emission writes a row into the existing `audit_log`
table with `action="irflow.incident_emitted"` and the IRFlow
incident id in the metadata. The CITADEL `openscrub.mitigation`
event for the underlying mitigation is the canonical evidence —
this audit row is the cross-reference, not a duplicate.

## v1.0.0 → v1.1 migration plan

- v1.0.0: this contract document; no Go client.
- v1.1: `internal/irflow/` package implementing the trigger loop,
  outbound HMAC client, and DLQ. Schema migration adds
  `irflow_emitted_at` and `irflow_dlq_*` columns to `mitigations`.
  CI gains a contract test exercising the receiver against an IRFlow
  fixture.
- v1.1+: severity-hint refinement based on field experience; possibly
  a `openscrub.mitigation_resolved` follow-up event when a sustained
  mitigation ends, for IRFlow's incident-closure flow.

## See also

- [citadel-integration.md](citadel-integration.md) — sibling HMAC + outbox pattern, reference implementation in `internal/citadel/`
- [threatflow-integration.md](threatflow-integration.md) — companion inbound integration
- [security/compliance-map.md](security/compliance-map.md) — Article 23 row references this page
- [security/threat-model.md](security/threat-model.md) — STRIDE row #8 (audit-log gaps); IRFlow is a downstream consumer of the same evidence
- [../../irflow/docs/webhook-spec.md](../../irflow/docs/webhook-spec.md) — canonical HMAC pattern this doc inherits
- [../../ECOSYSTEM.md § Data Flow](../../ECOSYSTEM.md) — data-flow line declaring this trigger
