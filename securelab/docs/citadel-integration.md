# CITADEL Integration

SecureLab emits a `securelab.run_completed` event to CITADEL's WORM
ledger when a scenario run finishes. This is an **audit-only**
integration: it records that a run happened, on what scenario, with
what outcome, so the fact of the run is part of CITADEL's immutable
history. It is not a governance decision — no MARSHAL gate evaluates
or authorizes anything here, because running a scenario isn't a
privileged action CITADEL needs to approve; it's telemetry submitted
after the fact.

Implementation: [`internal/citadel/connector.go`](../internal/citadel/connector.go).
Call site: [`internal/scenarios/executor.go`](../internal/scenarios/executor.go)
(`Executor.Execute`, after the run's final status is persisted).

## Emission flow

```
  Executor.Execute() persists the run's final status to Postgres
         │
         ▼
  If a Connector is attached (executor.WithCitadel(...)):
         │
         ▼
  Connector.EmitRunCompleted(ctx, runID, scenarioName, status, detectionRate)
         │
         ▼
  Build runCompletedEvent, marshal to JSON, wrap in an emitRequest
  { source, event_type, project_id, payload }
         │
         ▼
  Sign the full emitRequest body: HMAC-SHA256(secret, body) → hex
         │
         ▼
  POST {CITADEL_API_URL}/api/v1/worm/emit
    Content-Type: application/json
    X-CITADEL-Signature: sha256=<hex>
    X-CITADEL-Source: securelab
         │
         ▼
  Non-2xx response or transport error → EmitRunCompleted returns an
  error → executor logs a warning ("citadel emit failed") and moves on
```

The emit call is synchronous, made under a 5-second context timeout
set by the executor, and is **non-fatal**: a failed or slow CITADEL
call never fails the scenario run itself. There is no retry queue,
circuit breaker, or async worker — a single POST is attempted once per
completed run.

## Wiring / when it's active

`cmd/server/main.go` only attaches a `Connector` to the executor when
both are true:

- `SECURELAB_CITADEL_API_URL` is set, **and**
- `SECURELAB_CITADEL_DRY_RUN` is `false`

If either condition fails, `executor.WithCitadel(...)` is never
called and `Executor.citadel` stays `nil` — the executor simply skips
emission for every run (see the `if e.citadel != nil` guard in
`executor.go`). There is no separate "log but don't send" dry-run path
inside the connector itself; dry-run means the connector is never
wired up at all.

Relevant environment variables (`internal/config/config.go`):

| Variable | Purpose | Default |
|---|---|---|
| `SECURELAB_CITADEL_API_URL` | Base URL of the CITADEL API (e.g. `https://citadel.internal`) | unset |
| `SECURELAB_CITADEL_HMAC_SECRETS` | Comma-separated list of HMAC secrets; the first entry is used to sign outbound events | unset |
| `SECURELAB_CITADEL_DRY_RUN` | When `true` (default), CITADEL emission is disabled entirely | `true` |

## Event schema — `securelab.run_completed`

The request body POSTed to `/api/v1/worm/emit` is an `emitRequest`
envelope (matching CITADEL's `citadel/internal/api/handlers/worm.go`
`emitRequest` struct) carrying the run event as its `payload`:

```json
{
  "source": "securelab",
  "event_type": "securelab.run_completed",
  "project_id": "",
  "payload": {
    "event_type": "securelab.run_completed",
    "event_id": "run-abc123-1737904860000000000",
    "source": "securelab",
    "spec_version": "1.0",
    "timestamp": "2026-07-26T14:01:00Z",
    "run_id": "run-abc123",
    "scenario_name": "api/bola-basic",
    "status": "passed",
    "detection_rate": 1.0
  }
}
```

### Field definitions

| Field | Type | Description |
|---|---|---|
| `source` | string | Always `securelab`. |
| `event_type` | string | Always `securelab.run_completed`. |
| `project_id` | string | Not currently populated by the connector (empty string). |
| `payload.event_id` | string | `"<run_id>-<UnixNano timestamp>"`, generated at emit time. |
| `payload.spec_version` | string | Always `"1.0"`. |
| `payload.timestamp` | ISO 8601 (UTC) | Emission time, set when `EmitRunCompleted` is called. |
| `payload.run_id` | string | SecureLab `scenario_runs` row ID. |
| `payload.scenario_name` | string | The scenario's `spec.Name`. |
| `payload.status` | string | Final run status: `passed`, `failed`, or `error`. |
| `payload.detection_rate` | float | `1.0` if a detection was confirmed during the run, `0.0` otherwise (see `Executor.Execute`). |

There is no `nonce`, `evidence_hash`, `mitre` block, per-step
`detection_results` array, or operator identity in the current wire
format — the event is a single flat summary of the run's outcome. If
richer per-technique or per-step evidence is needed later, that's a
schema change to `runCompletedEvent` and `EmitRunCompleted`'s
signature, not something already shipped.

## Signing

The connector signs the **entire marshaled `emitRequest` JSON body**
with HMAC-SHA256 under the configured secret and sends the result,
hex-encoded, as `sha256=<hex>` in the `X-CITADEL-Signature` header:

```go
mac := hmac.New(sha256.New, secret)
mac.Write(body) // the full emitRequest JSON, exactly as sent
sig := hex.EncodeToString(mac.Sum(nil))
// X-CITADEL-Signature: sha256=<sig>
```

This matches the wire format used by the OpenCSIRT CITADEL emitter.
There is no separate nonce or replay-window field added by SecureLab;
any replay protection is enforced on the CITADEL side.

## What this integration is not

- **Not a MARSHAL-governed action.** Emitting a completed-run summary
  is not a privileged action requiring AuthN/AuthZ/NDS/AUGUR
  evaluation — it's after-the-fact audit telemetry about a simulation
  SecureLab already ran under its own authorization. No Kerkese
  contract is needed for this event.
- **Not a queue or async pipeline.** There is no bounded queue,
  circuit breaker, or backoff/retry loop. A failed emit is logged and
  dropped; the next completed run tries again independently.
- **Not evidence-hash verifiable offline.** Unlike some other
  platforms' CITADEL events, there is currently no `evidence_hash`
  field for independent tamper-checking outside of CITADEL's own WORM
  chain integrity (TripleHash).

## Testing

`internal/citadel/connector_test.go` covers the happy path (asserts
method, path, headers, and decoded payload fields) and the non-2xx
error path. Run with:

```bash
go test ./internal/citadel/... ./internal/scenarios/...
```

## Related

- [`internal/citadel/connector.go`](../internal/citadel/connector.go) — implementation
- [`internal/scenarios/executor.go`](../internal/scenarios/executor.go) — call site
- [`internal/config/config.go`](../internal/config/config.go) — `SECURELAB_CITADEL_*` env vars
- [SECURITY.md](../SECURITY.md) — result tampering threat model
