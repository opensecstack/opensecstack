# CITADEL Integration

SecureLab emits `securelab.simulation` events to the CITADEL WORM
ledger at the completion of every live scenario execution. These
events are the audit-grade record that a simulation was run, what
the detection outcome was, and which scenario version was executed.

Dry-run executions do not emit to CITADEL.

## Why CITADEL matters for SecureLab

A detection validation exercise has audit value only if its results
are immutable and independently verifiable. SecureLab stores execution
results in its own Postgres database — but that database is
controlled by the operator and could be modified. The CITADEL WORM
ledger provides an external, append-only record that:

1. A specific scenario version (content-hashed) was executed at a
   specific time by a specific operator.
2. The detection verdict (detected / not detected / inconclusive)
   against each configured platform.
3. The ATT&CK technique(s) covered by the execution.

An auditor querying CITADEL can reconstruct the coverage history for
any ATT&CK technique without trusting SecureLab's own database.

## Event schema — `securelab.simulation`

```json
{
  "event_type": "securelab.simulation",
  "event_id": "01HY...",
  "source": "securelab",
  "source_version": "1.0.0",
  "timestamp": "2027-11-01T14:01:00Z",
  "nonce": "a3f8...",
  "signature": "hmac-sha256:<hex>",

  "payload": {
    "execution_id": "01HY...",
    "scenario_id": "T1059.001-powershell-encoded",
    "scenario_version": "1.0.0",
    "scenario_version_hash": "sha256:abc123...",
    "operator_id": "01HZ...",
    "mode": "live",
    "target_scope": ["192.168.100.0/24"],
    "notes": "Weekly validation run",

    "mitre": {
      "technique": "T1059.001",
      "sub_technique": "PowerShell",
      "tactic": "execution"
    },

    "steps": [
      {
        "index": 1,
        "primitive": "cmd-spawn",
        "status": "completed"
      },
      {
        "index": 2,
        "primitive": "powershell-encoded-command",
        "status": "completed"
      }
    ],

    "detection_results": [
      {
        "step_index": 2,
        "source": "openscrub",
        "verdict": "detected",
        "rule_ref": "DETECT-PS-ENCODED-001",
        "event_id": "openscrub-evt-999",
        "captured_at": "2027-11-01T14:00:35Z",
        "latency_ms": 29500
      },
      {
        "step_index": 2,
        "source": "apiguard",
        "verdict": "not_applicable",
        "rule_ref": null,
        "event_id": null,
        "captured_at": null
      }
    ],

    "overall_verdict": "detected",
    "evidence_hash": "blake3:def456...",

    "started_at": "2027-11-01T14:00:05Z",
    "completed_at": "2027-11-01T14:01:00Z"
  }
}
```

### Field definitions

| Field | Type | Description |
|---|---|---|
| `event_type` | string | Always `securelab.simulation`. |
| `event_id` | ULID | Globally unique event identifier. |
| `source` | string | Always `securelab`. |
| `source_version` | semver | SecureLab version that emitted the event. |
| `timestamp` | ISO 8601 | UTC emission time. |
| `nonce` | hex string | 128-bit random nonce for replay prevention. |
| `signature` | string | HMAC-SHA256 over canonical event body; `hmac-sha256:<hex>`. |
| `payload.execution_id` | ULID | SecureLab execution record ID. |
| `payload.scenario_version_hash` | `sha256:<hex>` | Content hash of the scenario YAML at execution time. Reproducible for audit. |
| `payload.operator_id` | ULID | Operator who triggered the execution. |
| `payload.mode` | string | `live` \| `dry_run`. |
| `payload.detection_results[*].verdict` | string | `detected` \| `not_detected` \| `inconclusive` \| `timeout` \| `not_applicable`. |
| `payload.overall_verdict` | string | `detected` if any step has at least one `detected` verdict; `not_detected` if all asserted steps returned `not_detected`; `partial` if mixed; `inconclusive` if any timeout. |
| `payload.evidence_hash` | `blake3:<hex>` | BLAKE3 hash of the canonical evidence body (the full `payload` object serialised as canonical JSON). Reproducible without CITADEL. |

## Emission flow

```
  SecureLab execution completes (live mode)
         │
         ▼
  Celery worker: compute evidence_hash from canonical payload JSON
         │
         ▼
  Construct securelab.simulation event body
         │
         ▼
  Sign with HMAC-SHA256 (SECURELAB_CITADEL_KEY_SECRET)
         │
         ▼
  Enqueue to bounded async queue (max SECURELAB_CITADEL_QUEUE_SIZE)
         │
         ▼
  Emitter goroutine: POST to CITADEL /api/v1/events
         │         ├─ success → mark execution.citadel_emitted = true
         │         │            record citadel_event_id on execution
         │         └─ failure → retry (exponential backoff, 3 retries)
         │                       circuit breaker after 5 consecutive fails
         │                       mark execution.evidence_status = 'pending'
         ▼
  On shutdown: 10s drain — flush queue before exit
```

An execution is considered fully complete only when `citadel_emitted`
is `true`. Executions with `evidence_status: pending` are surfaced in
the dashboard as needing follow-up.

## Replay prevention

Each event carries a `nonce` (128-bit random) and `timestamp`.
CITADEL enforces a ±5-minute replay window: events with a timestamp
outside this window or a nonce that has been seen before are rejected.

The SecureLab emitter includes the nonce in the HMAC input, so a
replay of an intercepted event is detectable by CITADEL even if the
attacker replays it within the time window with a different nonce
(the signature would not verify).

## Querying CITADEL for SecureLab evidence

CITADEL supports querying events by `event_type` and `source`:

```bash
# All SecureLab simulation events in the last 30 days
GET /api/v1/events?event_type=securelab.simulation&since=2027-10-01

# Events for a specific ATT&CK technique
GET /api/v1/events?event_type=securelab.simulation&filter=payload.mitre.technique:T1059.001

# Events for a specific execution
GET /api/v1/events?event_type=securelab.simulation&filter=payload.execution_id:01HY...
```

## Verifying evidence integrity

The `evidence_hash` field allows offline verification that the event
body has not been tampered with after emission:

```python
import json
import hashlib

# Retrieve the event from CITADEL
event = citadel_client.get_event("01HY...")

# Canonical JSON: sorted keys, no whitespace
canonical = json.dumps(event["payload"], sort_keys=True, separators=(",", ":"))

# Verify
computed = "blake3:" + blake3(canonical.encode()).hexdigest()
assert computed == event["payload"]["evidence_hash"], "Evidence hash mismatch"
```

## Circuit breaker and backpressure

The CITADEL emitter wraps outbound calls in a circuit breaker:

- **Threshold:** 5 consecutive failures → circuit opens
- **Half-open probe:** every 30s after circuit opens
- **Queue backpressure:** if the queue exceeds
  `SECURELAB_CITADEL_QUEUE_SIZE`, new events are rejected (execution
  marked `evidence_pending` immediately)
- **Shutdown drain:** 10s to flush the queue before process exit

Operators should monitor the `securelab_citadel_queue_depth` and
`securelab_citadel_emit_failures_total` Prometheus metrics.

## Go v1.0.0 event name: `securelab.run_completed`

In the Go 1.22 backend (v1.0.0), the CITADEL event type is `securelab.run_completed`. The wire format is HMAC-SHA256 signed JSON. DryRun mode is controlled by `SECURELAB_CITADEL_DRY_RUN`.

### Wire format (v1.0.0)

```json
{
  "event_type": "securelab.run_completed",
  "event_id": "01HY...",
  "source": "securelab",
  "source_version": "1.0.0",
  "timestamp": "2026-05-10T14:01:00Z",
  "nonce": "a3f8...",
  "signature": "hmac-sha256:<hex>",
  "payload": {
    "run_id": "run_abc123",
    "scenario": "api/bola-basic",
    "environment_id": "env_test_01",
    "operator_id": "op_xyz",
    "mitre_technique_ids": ["T1078"],
    "status": "completed",
    "detection_rate": 1.0,
    "gaps": [],
    "started_at": "2026-05-10T14:00:00Z",
    "completed_at": "2026-05-10T14:01:00Z"
  }
}
```

### HMAC signing

The signature covers: `event_id + "." + timestamp + "." + nonce + "." + canonical_payload_json`. Canonical JSON is sorted keys, no whitespace.

Verification:
```go
mac := hmac.New(sha256.New, []byte(hmacSecret))
mac.Write([]byte(eventID + "." + timestamp + "." + nonce + "." + canonicalPayload))
expected := hex.EncodeToString(mac.Sum(nil))
```

### DryRun mode

When `SECURELAB_CITADEL_DRY_RUN=true` (the default), the event is:
- Constructed and signed as normal
- Logged at INFO level with field `dry_run: true`
- NOT sent to the CITADEL API
- Stored in the database with `citadel_status: dry_run`

Set to `false` only when you have a validated CITADEL endpoint and an isolated test environment.

## Related

- [docs/operator-handbook.md](operator-handbook.md) — monitoring
  CITADEL emission health, resolving `evidence_pending` executions
- [docs/architecture.md](architecture.md) — integration arrows
- [SECURITY.md](../SECURITY.md) — result tampering threat model
- CITADEL documentation — `securelab.run_completed` event type
  registration
