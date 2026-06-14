# Integrating with CITADEL

This document explains how each OpenSecStack platform calls CITADEL,
plus how a third-party application would integrate. For the raw HTTP
wire format see [api.md](./api.md). For what CITADEL protects and
trusts, see [security-model.md](./security-model.md).

## Two integration patterns

| Pattern | Endpoint | When to use |
|---|---|---|
| **MARSHAL evaluation** | `POST /api/v1/marshal/evaluate` | Any privileged action that needs dual-control before it happens (containment, deployment, secret rotation, policy change) |
| **WORM emit** | `POST /api/v1/worm/emit` | Lifecycle events that must be tamper-evident but don't need governance approval (incident created, scan completed, IOC attached) |

Most platforms use both: MARSHAL for the action itself, WORM for the
derived audit events around it.

## Go SDK client

`github.com/opensecstack/sdk/opensecstack.CITADELClient` wraps both
endpoints with:

- HMAC-SHA256 signing of every request body
- Exponential-backoff retry on 5xx (not on 4xx — those are client errors)
- Non-blocking `SendEvent` for WORM emits via a background worker queue
- Client-side `VerifyChain` helper that replays a slice of entries and
  recomputes each `chain_hash`

```go
client := opensecstack.NewCITADELClient(opensecstack.CITADELClientOptions{
    BaseURL:      "https://citadel.internal:8099",
    SharedSecret: os.Getenv("CITADEL_HMAC_SECRET"),
})
defer client.Drain(ctx)

// MARSHAL evaluation
result, err := client.EvaluateKerkese(ctx, opensecstack.Kerkese{...})
if err != nil { return err }
switch result.Outcome {
case "EXECUTE":  // proceed
case "REFUSE":   return fmt.Errorf("refused: %v", result.Reasons)
case "HARD_STOP": return errHardStop
}

// WORM emit (fire-and-forget)
err = client.SendEvent(ctx, opensecstack.SecurityEvent{
    EventType:    "incident.created",
    Source:       "irflow",
    ResourceType: "incident",
    ResourceID:   "inc-42",
    Severity:     "P1",
    Payload:      payload,
})
```

## Platform-by-platform integration

### IRFlow → CITADEL

| Event | Endpoint | Trigger |
|---|---|---|
| `SubmitAction` | `POST /marshal/evaluate` | Before persisting any governed incident action (contain, eradicate, recover, close) |
| `incident.created` | `POST /worm/emit` | Immediately after `store.Create` succeeds in the service layer |
| `incident.closed` | `POST /worm/emit` | On status transition to `closed` |

IRFlow's `internal/governance/citadel.go` is the canonical reference
implementation of both patterns in Go.

A `REFUSE` or `HARD_STOP` outcome short-circuits IRFlow's `SubmitAction`
and returns 403 to the caller; the proposed action is never stored
locally. A `HARD_STOP` additionally triggers IRFlow's CITADEL webhook
handler to auto-create a P1 incident.

### APIGuard → CITADEL

| Event | Endpoint | Trigger |
|---|---|---|
| `scan.started` | `POST /worm/emit` | Scan kick-off (audit trail of who ran what) |
| `scan.completed` | `POST /worm/emit` | Final report available |
| `finding.critical` | `POST /worm/emit` | Each CRITICAL-severity OWASP finding |
| `policy.update` | `POST /marshal/evaluate` | Any change to the custom-rules YAML in production |

APIGuard uses MARSHAL only for policy changes; individual scans are
low-risk and go to WORM directly.

### NIS2 Compass → CITADEL

| Event | Endpoint | Trigger |
|---|---|---|
| `assessment.completed` | `POST /worm/emit` | When a NIS2 assessment is signed off |
| `control.status_changed` | `POST /worm/emit` | Every time a control transitions compliant ↔ non-compliant |
| `approval.granted` | `POST /marshal/evaluate` | Compliance sign-off by a designated approver — requires dual control |

`assessment.completed` carries the `object_fingerprint` and full
approval chain so regulators can reconstruct the timeline from the WORM
log alone.

### ThreatFlow → CITADEL

| Event | Endpoint | Trigger |
|---|---|---|
| `ioc.imported` | `POST /worm/emit` | Per bundle (not per IOC — bundles can hold thousands) |
| `feed.poll_completed` | `POST /worm/emit` | After each scheduled TAXII / CSV / MISP poll |
| `feed.config_changed` | `POST /marshal/evaluate` | Adding, removing, or re-credentialising a feed source |

## Kerkese reference

A Kerkese (Albanian for "request") is the JSON envelope MARSHAL
evaluates. It carries the five inputs the engine needs to make a
decision:

```
{
  "kerkese_version": "v2.0",            // protocol version; must be "v2.0" today
  "ts_utc":          "<RFC3339>",       // when the caller produced the Kerkese
  "project_id":      "<string>",        // scope for policy and rate limiting
  "execution_id":    "<UUIDv4>",        // caller-generated; makes retries idempotent
  "action":          { … },             // what the caller wants to do
  "actor":           { … },             // who proposes the action (operator)
  "verifier":        { … },             // who approves the action (second person)
  "evidence":        { … },             // attached artefacts, references, justifications
  "sod":             { … },             // operator + verifier IDs — redundantly — for Gate 2
  "dry_run":         false,             // true = evaluate without emitting a real WORM entry
  "emergency":       false,             // true = bypass policy-related gates with justification
  "emergency_justification": ""
}
```

Field-by-field:

- **`action`** — `{ type, description?, change_id?, incident_id?, root_cause?, corrective_action? }`. Mandatory: `type`. The caller picks the string; CITADEL's policy matches against it.
- **`actor`** — `{ user_id: int64, role: string, email?: string }`. Operator identity.
- **`verifier`** — same shape. Enforced by Gate 2 to differ from `actor`.
- **`evidence`** — `{ change_id?, artifacts?: [{hash, type, label}], drill_reference?, extra?: object }`. Free-form hook for platform-specific metadata; preserved verbatim in WORM.
- **`sod`** — `{ operator_user_id, verifier_user_id }`. Redundant with `actor`/`verifier`; both are checked to catch payload tampering.

## Error handling

| HTTP | What the caller should do |
|---|---|
| 200 + `EXECUTE` | Proceed with the action; persist `worm_entry_id` on the originating record |
| 200 + `REFUSE` | Do not proceed. Surface `reasons[]` to the user. Log at `info` — this is a governance decision, not an error |
| 403 + `HARD_STOP` | Do not proceed. Trigger a P1 incident via IRFlow. Alert oncall. Log at `warn` |
| 400 | Client bug — malformed Kerkese. Fix the payload. |
| 500 | CITADEL internal error. Retry with exponential backoff (the SDK does this automatically). If retries exhaust, fail loudly — do **not** proceed without MARSHAL |
| 503 | CITADEL is down or degraded. Same as 500 — fail loudly |

Under no circumstances should a platform proceed with a privileged
action when CITADEL is unreachable. The correct behaviour is to surface
the error to the caller and flag the downtime in monitoring.

## Testing against CITADEL

A local CITADEL is the fastest way to exercise integration:

```bash
cd citadel/
make docker-up           # starts Postgres + CITADEL on :8099
curl http://localhost:8099/api/v1/health
# {"status":"ok","version":"1.0.0",...}
```

For CI, consumers typically run a `docker-compose.test.yml` with a
dedicated CITADEL instance and scoped project ID so test data is easy
to wipe.

## Related

- [API reference](./api.md) — wire format for each endpoint
- [Architecture](./architecture.md) — internals of MARSHAL and WORM
- [Security model](./security-model.md) — trust boundaries and known limitations
- [Ecosystem flow map](../../ECOSYSTEM.md) — which platform calls which
