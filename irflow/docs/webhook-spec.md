# IRFlow Webhook Specification

IRFlow accepts signed, replay-protected webhooks from three ecosystem
platforms: APIGuard, CITADEL, and ThreatFlow. This document is the
canonical wire contract — senders and any custom integrations must
match it exactly.

For the handler code, see [internal/webhook/hmac.go](../internal/webhook/hmac.go)
and [internal/api/webhooks.go](../internal/api/webhooks.go).

## Endpoints

| Endpoint | Source | Typical trigger |
|---|---|---|
| `POST /api/v1/webhooks/apiguard` | APIGuard | A finding crosses a severity threshold, or a scan completes |
| `POST /api/v1/webhooks/citadel` | CITADEL | HARD_STOP decisions, WORM anchor events |
| `POST /api/v1/webhooks/threatflow` | ThreatFlow | IOC bundle published, feed update |

All three endpoints share the same signing scheme, differing only in
the payload shape. None of them require a JWT — authentication is
entirely via HMAC.

## Signing scheme

Every request carries two headers:

| Header | Description |
|---|---|
| `X-Irflow-Timestamp` | Unix seconds at the moment of signing (UTC) |
| `X-Irflow-Signature` | `sha256=<hex>` where `<hex>` is the HMAC-SHA256 output |

The canonical signing input is:

```
signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(per_source_secret, signed_payload))
```

`raw_body` is the exact request body IRFlow will receive — no
re-serialisation, no whitespace normalisation. The signature is over
the bytes on the wire.

An optional `X-Irflow-Event-Id` header is used by senders to deduplicate
retries on their side. IRFlow reads it for logging today; v1.1 will
persist it and reject replays with the same ID.

## Replay protection

IRFlow accepts a timestamp if it falls within ±5 minutes of server
time. The window is controlled by
`IRFLOW_WEBHOOK_CLOCK_SKEW_TOLERANCE` (default `5m`). Requests outside
the window return **401** with `{"error":"webhook: X-Irflow-Timestamp outside allowed clock skew"}`.

The ±5-minute window trades capture-replay risk against real-world
clock drift between peers. A tighter window (30 s) is possible but
requires well-synchronised NTP across APIGuard / CITADEL / ThreatFlow;
most operators keep the default.

## Per-source secrets

Each source has its own shared secret — never reuse a secret across
sources. Configure these on IRFlow's side:

| Variable | Used by |
|---|---|
| `IRFLOW_WEBHOOK_APIGUARD_SECRET` | APIGuard endpoint verifier |
| `IRFLOW_WEBHOOK_CITADEL_SECRET` | CITADEL endpoint verifier |
| `IRFLOW_WEBHOOK_THREATFLOW_SECRET` | ThreatFlow endpoint verifier |

`IRFLOW_WEBHOOK_SECRET` exists as a legacy fallback and will be
removed in v1.1 — do not use it for new deployments. An unconfigured
per-source secret means that endpoint returns **503** until set; this
is fail-closed by design.

## Payload shapes

### APIGuard (`/api/v1/webhooks/apiguard`)

```json
{
  "event_id":    "ag-2026-04-19-00042",
  "event_type":  "apiguard.finding.critical",
  "project_id":  "proj_123",
  "scan_id":     "scan_456",
  "finding": {
    "rule_id":  "OWASP_API_01",
    "severity": "critical",
    "target":   "https://api.example.com/users/{id}",
    "details":  "BOLA on /users/{id} — direct object reference"
  },
  "occurred_at": "2026-04-19T10:12:03Z"
}
```

IRFlow's behaviour: if `severity` is `critical` or `high`, an incident
is auto-created with corresponding severity (`P1` / `P2`). Lower
severities are logged and attached as timeline entries to the nearest
open incident for that project.

### CITADEL (`/api/v1/webhooks/citadel`)

```json
{
  "event_id":      "ct-worm-0000017234",
  "event_type":    "citadel.marshal.hard_stop",
  "project_id":    "proj_123",
  "kerkese_hash":  "sha256:…",
  "worm_entry_id": "worm_7890",
  "decision": {
    "outcome": "HARD_STOP",
    "reason":  "AUGUR_rule_03: DATA_EXPORT attempted without incident_id"
  },
  "occurred_at": "2026-04-19T10:13:11Z"
}
```

HARD_STOP events always produce a **P1** incident and trigger the
project freeze playbook if one is configured. REFUSE events are
logged but do not auto-create incidents — the caller already sees the
refusal at the MARSHAL API layer.

### ThreatFlow (`/api/v1/webhooks/threatflow`)

```json
{
  "event_id":   "tf-bundle-0000042",
  "event_type": "threatflow.bundle.published",
  "bundle_id":  "tf_bundle_789",
  "incident_id": "inc_123",
  "iocs": [
    {"type": "ipv4",    "value": "203.0.113.5",       "confidence": 0.92},
    {"type": "sha256",  "value": "abc123…",           "confidence": 0.81},
    {"type": "domain",  "value": "malicious.example", "confidence": 0.77}
  ],
  "occurred_at": "2026-04-19T10:14:22Z"
}
```

If `incident_id` is present and matches an open incident, the IOCs are
attached to it. If absent, they are staged as unattached enrichments
until a later call correlates them (v1.2 feature).

## Error responses

| Status | Meaning |
|---|---|
| 200 / 202 | Accepted; webhook processed synchronously or queued |
| 400 | Payload failed JSON decode or schema validation |
| 401 | Signature missing, timestamp outside skew, or HMAC mismatch |
| 413 | Body exceeds `IRFLOW_WEBHOOK_MAX_BODY_SIZE` (default 1 MiB) |
| 503 | Per-source secret not configured — endpoint disabled |

IRFlow always returns structured JSON errors: `{"error": "human-readable description"}`.

## Example sender (Go)

```go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "fmt"
    "net/http"
    "strings"
    "time"
)

func postSigned(url, secret string, body []byte) (*http.Response, error) {
    ts := strconv.FormatInt(time.Now().Unix(), 10)
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write([]byte(ts + "." + string(body)))
    sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

    req, _ := http.NewRequest("POST", url, strings.NewReader(string(body)))
    req.Header.Set("Content-Type",        "application/json")
    req.Header.Set("X-Irflow-Timestamp",  ts)
    req.Header.Set("X-Irflow-Signature",  sig)
    return http.DefaultClient.Do(req)
}
```

The [OpenSecStack SDKs](../../sdk/) ship pre-built clients that handle
signing automatically — prefer those over rolling your own.

## Related

- [API reference](./api.md)
- [Architecture](./architecture.md)
- [Governance integration](./governance-integration.md) — outbound side (IRFlow → CITADEL)
