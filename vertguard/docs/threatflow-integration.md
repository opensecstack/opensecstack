# ThreatFlow Integration

VertGuard integrates with ThreatFlow as its primary downstream
consumer of AI-specific threat intelligence. This document describes
the wire contract, authentication, data flow, and operational
concerns.

For VertGuard's Module 4 overview, see [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md).
For ThreatFlow's webhook contract, see [../../threatflow/docs/webhook-spec.md](../../threatflow/docs/webhook-spec.md).

## Integration topology

```
VertGuard Module 4                    ThreatFlow
┌────────────────┐                   ┌─────────────────┐
│ Feed collector │                   │                 │
│     │          │                   │   IOC store     │
│     ▼          │   HMAC-signed     │   (ai_attack_   │
│ Canonicalise   │   POST            │   pattern type) │
│ IOCs to        │ ────────────────► │                 │
│ ThreatFlow     │                   │   Dashboards    │
│ schema         │   HMAC-signed     │   Cross-        │
│                │ ◄──────────────── │   correlation   │
│ Webhook        │   Feed updates    │                 │
│ receiver       │                   │                 │
└────────────────┘                   └─────────────────┘
```

## Authentication — HMAC-SHA256 (reused ecosystem pattern)

Consistent with IRFlow ↔ CITADEL, APIGuard ↔ ThreatFlow, and all
other intra-platform webhooks in the SIN ecosystem:

```
signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(shared_secret, signed_payload))
```

Headers on every request:

| Header | Value |
|---|---|
| `X-Vertguard-Signature` | `sha256=<hex>` |
| `X-Vertguard-Timestamp` | `<unix-seconds>` |
| `X-Vertguard-Event-Id` | `<uuid>` (for replay/dedup) |

Receiver rejects if:
- Signature mismatch
- Timestamp outside ±5 min skew window
- Event ID already seen (replay protection — requires deduplication table)

## Outbound — VertGuard pushes IOCs to ThreatFlow

### IOC submission endpoint

```
POST https://threatflow.internal:8084/api/v1/ioc/bundle
Headers: (per above)
Body (JSON):
{
  "bundle_id": "vg-bundle-2026-04-25-0001",
  "source":    "vertguard",
  "ts_utc":    "...",
  "iocs": [
    {
      "type":        "ai_attack_pattern",
      "value":       "jailbreak.persona_takeover.v3",
      "confidence":  0.91,
      "severity":    "high",
      "mitre_atlas": { "technique_id": "AML.T0051.000", "tactic": "AML.TA0005" },
      "owasp_llm":   "LLM01",
      "first_seen":  "...",
      "last_seen":   "...",
      "references":  [...]
    },
    // ... up to 100 IOCs per bundle
  ]
}
```

### Schedule

- **Real-time:** `severity: critical` IOCs pushed immediately (within
  30 seconds of collection)
- **Batched every 15 minutes:** all other new/updated IOCs
- **Daily at 04:00 UTC:** full reconciliation push

### Batching strategy

Bundles limited to 100 IOCs each. Larger batches split into multiple
bundles with sequential `bundle_id` suffixes (`-0001`, `-0002`, …).

Bundle acknowledgement from ThreatFlow includes per-IOC status:

```json
{
  "bundle_id": "vg-bundle-2026-04-25-0001",
  "received":  100,
  "accepted":  97,
  "rejected":  3,
  "rejections": [
    { "value": "...", "reason": "confidence below minimum threshold" }
  ]
}
```

Rejections logged at WARN level; VertGuard retries the following
cycle unless rejection reason is terminal (e.g. schema violation).

## Inbound — VertGuard receives updates from ThreatFlow

ThreatFlow sends VertGuard updates when:

- Another ThreatFlow consumer reports a match with a VertGuard IOC
  (feedback loop enriches the IOC's `sightings` count)
- A VertGuard IOC becomes deprecated from community consensus
- New AI-attack IOCs enter ThreatFlow from other sources that
  VertGuard should know about

### Webhook receiver endpoint

```
POST /api/v1/webhooks/threatflow
```

Uses the same HMAC-SHA256 pattern. Handler in
`internal/api/handlers/webhooks.go` — pattern identical to IRFlow's
webhook handlers.

## Configuration

```bash
# Outbound to ThreatFlow
VERTGUARD_THREATFLOW_API_URL=http://threatflow.internal:8084
VERTGUARD_THREATFLOW_KEY_ID=vertguard-prod
VERTGUARD_THREATFLOW_KEY_SECRET=<64-byte random>

# Inbound from ThreatFlow
VERTGUARD_WEBHOOK_THREATFLOW_SECRET=<matching secret on ThreatFlow side>

# Cadence (per Module 4 spec)
VERTGUARD_THREATFEED_PUSH_INTERVAL=15m
VERTGUARD_THREATFEED_RECONCILE_CRON="0 4 * * *"
```

Empty `THREATFLOW_KEY_SECRET` → VertGuard starts in **standalone
mode**; IOCs collected locally but not pushed anywhere. Loud WARN at
startup.

## SDK usage

VertGuard uses the Go ThreatFlow client from
[../../sdk/go](../../sdk/go):

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewThreatFlowClient(
    opensecstack.ThreatFlowConfig{
        BaseURL:   cfg.ThreatFlowAPIURL,
        KeyID:     cfg.ThreatFlowKeyID,
        KeySecret: cfg.ThreatFlowKeySecret,
    },
)
err := client.SubmitIOCBundle(ctx, bundle)
```

The SDK handles HMAC signing, retry logic (exponential backoff),
and typed errors.

## Failure modes

| Failure | Impact | Response |
|---|---|---|
| ThreatFlow unreachable | Local IOC queue grows | Queue persisted to DB; retry on connectivity restore |
| HMAC mismatch | 401 from ThreatFlow | Rotate secret; don't retry blindly |
| Timestamp skew | 401 | Sync clocks (NTP) |
| Schema rejection | Partial accept | Fix VertGuard serialiser; keep-unchanged IOCs re-pushed next cycle |
| ThreatFlow DB full | Bundle accepts but drops | ThreatFlow ops concern; VertGuard's own DB retains the IOCs |

## Metrics

| Metric | Purpose |
|---|---|
| `vertguard_threatflow_push_total{result}` | Push outcome counter |
| `vertguard_threatflow_push_latency_seconds` | Push latency histogram |
| `vertguard_threatflow_queue_depth` | Local queue depth (alert if sustained > 1000) |
| `vertguard_threatflow_iocs_sent_total` | Total IOCs submitted |

## Testing

Integration tests live in `tests/integration/threatflow_test.go`.
Run against a live ThreatFlow staging instance:

```bash
export VERTGUARD_THREATFLOW_API_URL=http://localhost:8084
export VERTGUARD_THREATFLOW_KEY_SECRET=test-secret-match-threatflow-side
make test-integration
```

## Related

- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md)
- [mitre-atlas-mapping.md](mitre-atlas-mapping.md)
- [../../threatflow/docs/webhook-spec.md](../../threatflow/docs/webhook-spec.md)
- [../../sdk/go](../../sdk/go) — Go ThreatFlow client
