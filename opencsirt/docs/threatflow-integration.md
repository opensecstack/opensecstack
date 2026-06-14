# ThreatFlow Integration

> v1.0.0. OpenCSIRT ↔ ThreatFlow is **bidirectional**: a poller pulls
> IOC bundles from ThreatFlow on a fixed cadence, and the publish
> path pushes the CSAF document of every newly published advisory
> back to ThreatFlow's ingest endpoint. The implementation lives in
> [internal/integrations/threatflow.go](../internal/integrations/threatflow.go).

## Why

ThreatFlow is the ecosystem's IOC aggregator. OpenCSIRT is the
constituency-facing CSIRT operations plane. Without this integration,
a CSIRT analyst would have to copy IOCs out of ThreatFlow into an
advisory and copy advisory IOCs back into ThreatFlow — both flows
are mechanical and error-prone. The two endpoints below close that
loop.

## Inbound — IOC pull

### Cadence

The poller is an exported `*ThreatFlowClient` started by the API
process. Cadence is set by `OPENCSIRT_THREATFLOW_INTERVAL` (default
`60s`). Implementation:

- `NewThreatFlowClient(apiURL, interval, store, logger)` constructs
  the client.
- `Run(ctx)` opens a `time.Ticker(interval)` loop and calls
  `pullOnce(ctx)` on every tick. Returns when `ctx` is cancelled.
- An empty `apiURL` short-circuits — the loop logs `threatflow: API
  URL empty, poller disabled` once and returns. This is the
  zero-config posture; setting `OPENCSIRT_THREATFLOW_API_URL=""`
  reverts to disabled.

### Wire request

```
GET {OPENCSIRT_THREATFLOW_API_URL}/api/v1/iocs?type=all
```

The 30-second `http.Client` timeout in the constructor bounds a
stuck connection. The response body is read through
`io.LimitReader(resp.Body, 16*1024*1024)` — 16 MiB is the hard
ceiling on a single bundle. Beyond that the read truncates and the
JSON decode fails; the cycle is logged as failed and retried on the
next tick.

### Bundle hash dedup

Each pull computes `sha256.Sum256(body)` over the exact bytes on
the wire and consults `IOCIngestStore.LastForSource(ctx,
"threatflow")`. If the hash equals the most recent
`bundle_sha256`, the cycle returns early — no parse, no insert.
This is the v1.0.0 dedup primitive. It catches:

- ThreatFlow holding the same set of IOCs across multiple ticks
  (the common case).
- Idempotent re-delivery after a network blip.

It does **not** detect within-bundle differences when the encoder
re-serialises the same set with a different key order — that's a
known limitation; ThreatFlow's outbound encoder is stable, so in
practice the SHA matches when the set matches.

### Persistence

Every novel pull lands a row in `ioc_ingest_log` (see
[migrations/0001_init.up.sql](../migrations/0001_init.up.sql) §
`ioc_ingest_log`). The persisted shape:

| Column | Source |
|---|---|
| `source` | hard-coded `"threatflow"` |
| `bundle_sha256` | hex of `sha256.Sum256(body)` |
| `count` | length of the parsed `iocs[]` array |
| `ingested_at` | server `now()` default |

The `iocs[]` payload itself is not persisted in v1.0.0 — only the
bundle hash and count. ThreatFlow remains the source of truth for
the indicator set; OpenCSIRT records the lineage.

## Outbound — advisory push

When an advisory transitions to `published`, the API process invokes
`(*ThreatFlowClient).PushAdvisory(ctx, csafDoc)`:

```go
func (c *ThreatFlowClient) PushAdvisory(ctx context.Context, csafDoc map[string]any) error
```

Implementation:

```
POST {OPENCSIRT_THREATFLOW_API_URL}/api/v1/advisories
Content-Type: application/json

<csaf_doc as JSON>
```

The body is the CSAF 2.0 document JSON-encoded by `json.Marshal`.
On 4xx/5xx the call returns `fmt.Errorf("threatflow: push %d", resp.StatusCode)`.
On a configuration miss (`apiURL == ""`) the call returns
`errors.New("threatflow: API URL not configured")`; the publish
path treats this as best-effort failure and does not roll back.

## Failure modes

| Mode | Detection | Behaviour |
|---|---|---|
| `OPENCSIRT_THREATFLOW_API_URL=""` | startup config | poller no-ops; `PushAdvisory` returns immediately with a config error; publish proceeds |
| Network unreachable / DNS / TLS | `c.http.Do` returns error | `pullOnce` returns the error, parent loop logs `threatflow: pull failed` at WARN, next tick retries |
| ThreatFlow returns 5xx | `resp.StatusCode >= 400` | same as transient network — log + retry next tick |
| Body > 16 MiB | `io.LimitReader` truncates → `json.Unmarshal` fails | cycle aborts; no row inserted; next tick retries |
| Identical bundle | SHA matches `LastForSource` | early return, no log noise (intended hot path) |
| `PushAdvisory` rejected (4xx) | non-2xx status | returns error; publish does **not** roll back; CITADEL `opencsirt.advisory_published` event is still emitted |

The poller is intentionally **chatty on failure, silent on success**
beyond the per-cycle `threatflow: ingested count=N` info log when a
new bundle is accepted.

## Auth contract

v1.0.0 sends both inbound and outbound HTTP without an
`Authorization` header. The integration is operated **inside the
ecosystem trust zone** — ThreatFlow and OpenCSIRT share a private
network in the [deployment topology](../../docs/deployment-topology.md).

Two hardening proposals are tracked for v1.1:

1. **Shared bearer token.** Issue an
   `OPENCSIRT_THREATFLOW_TOKEN` minted on the ThreatFlow side, sent
   as `Authorization: Bearer …` on every request, rotated on the
   90-day cadence in [security/security-checklist.md](security/security-checklist.md).
2. **mTLS.** OpenCSIRT and ThreatFlow each present a service
   certificate, validated against a private CA. Stronger than
   bearer (no token to leak) and aligns with the
   [Tier 2 deployment profile](../../docs/deployment-topology.md).

The current code allows either to be added without an API change —
the `*http.Client` is constructed once in
`NewThreatFlowClient` and can be replaced with a TLS-configured
client at startup.

## Related

- [internal/integrations/threatflow.go](../internal/integrations/threatflow.go) — implementation
- [migrations/0001_init.up.sql](../migrations/0001_init.up.sql) — `ioc_ingest_log` schema
- [security/threat-model.md](security/threat-model.md) — STRIDE row "outbound integration credential exposure"
- [advisory-authoring-guide.md](advisory-authoring-guide.md) — what gets in the CSAF body that ThreatFlow ingests
- [../../ECOSYSTEM.md](../../ECOSYSTEM.md) — `OpenCSIRT advisories → ThreatFlow (advisory → IOC pipeline)` data-flow row
- [../../docs/deployment-topology.md](../../docs/deployment-topology.md) — port 8088 + trust zone
