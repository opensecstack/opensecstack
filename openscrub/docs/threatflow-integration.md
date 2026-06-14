# ThreatFlow Integration

> v1.0.0. OpenScrub consumes the ThreatFlow malicious-IP feed and
> reconciles it into the BPF blocklist map. The puller is implemented
> by the Go API process; this page documents the contract.

## Why

ThreatFlow already aggregates and correlates malicious-IP IOCs from
multiple sources. OpenScrub is the natural enforcement point — turn
the feed into kernel-level drops without copy-paste in the middle.

## Pull cadence

- Default: every 15 minutes (`OPENSCRUB_THREATFLOW_INTERVAL`).
- Manual: no manual-trigger endpoint in v1.0.0; restart the API
  container to fire the initial tick immediately.
- A pull cycle is a single transaction: fetch the malicious-IP
  list, diff against `rules WHERE source = 'threatflow'`, apply
  inserts and withdrawals atomically.

## Contract

### Pull request

```
GET {THREATFLOW_API_URL}/api/v1/iocs?type=ip
Authorization: Bearer {THREATFLOW_TOKEN}
Accept: application/json
```

The puller calls the lightweight JSON list endpoint that ThreatFlow
exposes for first-line consumers. (A STIX 2.1 bundle endpoint is on
ThreatFlow's roadmap; OpenScrub will switch when it lands and the
bundle path is gated on a feature flag.)

### Pull response (JSON list)

```json
{
  "items": [
    { "type": "ip", "value": "198.51.100.7" },
    { "type": "ip", "value": "203.0.113.42" }
  ]
}
```

For each item with `type == "ip"`, OpenScrub produces a `/32` (or
`/128`) blocklist rule with `source = "threatflow"` and a TTL of
`OPENSCRUB_THREATFLOW_INTERVAL × 2` so a missed pull cycle does not
leak rules. See [internal/ioc/puller.go](../internal/ioc/puller.go).

## Reconciliation

For each pull cycle:

1. Fetch the JSON list.
2. Build the desired rule set `D` from the `items[]`.
3. Compute `existing_threatflow = SELECT * FROM rules WHERE source = 'threatflow' AND deleted_at IS NULL`.
4. `to_insert = D - existing_threatflow`.
5. `to_withdraw = existing_threatflow - D`.
6. Apply both via the same transactions used for operator-driven
   rules (so audit, BPF map sync, and CITADEL emission all happen).

## Allow-list guard

Before insert, every candidate CIDR is checked against an operator-
owned-CIDR allow-list (`OPENSCRUB_ALLOWLIST`, comma-separated).
A candidate that overlaps the allow-list is rejected with an audit
row of type `ioc_pull_blocked_by_allowlist` — this is the threat-model
mitigation #3 (IOC source compromise → block legitimate traffic).

## Failure handling

- ThreatFlow unreachable: existing rules remain in place until their
  TTL expires. Alert raised on `openscrub_ioc_pull_failures_total > 3`
  over 1 h.
- ThreatFlow returns malformed JSON: cycle aborts, no diff applied.

> **Pending hardening (post-1.0):** the
> [security/threat-model.md](security/threat-model.md) row for
> "IOC source compromise" calls for two additional controls — a
> 50%-delta circuit-breaker that aborts a cycle when the diff exceeds
> half the existing IOC-source rule set, and an operator-owned-CIDR
> allow-list that prevents IOC-driven rules from blocking the
> operator's own ranges. The allow-list is implemented; the
> circuit-breaker is tracked as a v1.0 hardening follow-up.

## Persistence and observability — naming

| Surface | Name | Notes |
|---|---|---|
| Postgres table | `ioc_ingest_log` | One row per pull cycle; created in [migrations/0001_init.up.sql](../migrations/0001_init.up.sql). |
| Prometheus counter | `openscrub_ioc_pulls_total` | Increments per pull cycle. The metric and the table refer to the same lineage; the names diverge for historical reasons — `grep ioc_pulls` will not find the table, and `grep ioc_ingest` will not find the metric. |

## Metrics

| Metric | Type | Description |
|---|---|---|
| `openscrub_ioc_pulls_total` | counter | Total pull attempts. |
| `openscrub_ioc_pull_failures_total` | counter | Failed pulls. |
| `openscrub_ioc_pull_latency_ms` | histogram | End-to-end pull duration. |
| `openscrub_ioc_pull_inserts` | gauge | Rules inserted in last cycle. |
| `openscrub_ioc_pull_withdrawals` | gauge | Rules withdrawn in last cycle. |

## Related

- ThreatFlow API: `../threatflow/docs/api.md` (in the monorepo).
- Allow-list rationale: [security/threat-model.md](security/threat-model.md) #3.
- Rule schema: [api.md](api.md).
