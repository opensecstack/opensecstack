# IRFlow ↔ CITADEL Governance Integration

IRFlow relies on CITADEL for two distinct governance operations on
every incident response action:

1. **MARSHAL evaluation** — dual-control approval of the action before
   it is executed (synchronous, blocking).
2. **WORM emission** — append-only audit log entry recording that the
   action happened (synchronous for incident creation, best-effort for
   other mutations).

Without a reachable CITADEL, IRFlow can run in **local-only** mode
(leave `IRFLOW_CITADEL_API_URL` empty) — actions are persisted without
governance, suitable only for CI and development environments.

For the CITADEL client code, see [internal/governance/citadel.go](../internal/governance/citadel.go).

## Payload: the Kerkese

A Kerkese (Albanian for "request") is the canonical request envelope
CITADEL expects. IRFlow constructs one only on **approval** — the second
step of the two-person-rule action flow (see
[internal/incident/governance.go](../internal/incident/governance.go) and
[internal/governance/citadel.go](../internal/governance/citadel.go)):

```json
{
  "kerkese_version": "1.0",
  "ts_utc":          "2026-04-19T10:12:00Z",
  "project_id":      "prod",
  "execution_id":    "uuid",
  "action":  {
    "type":         "CONTAIN",
    "description":  "block endpoint",
    "incident_id":  "inc_123"
  },
  "actor":    { "user_id": "8f14e...-sinauth-uuid", "role": "operator" },
  "verifier": { "user_id": "3ac09...-sinauth-uuid", "role": "verifier" },
  "sod": {
    "operator_user_id": "8f14e...-sinauth-uuid",
    "verifier_user_id": "3ac09...-sinauth-uuid"
  },
  "evidence":        { "extra": { "any": "json" } },
  "dry_run":         false,
  "actor_token":     "",
  "verifier_token":  "<verifier's raw sinauth bearer token>"
}
```

`actor.user_id` / `verifier.user_id` and `sod.operator_user_id` /
`sod.verifier_user_id` are real [sinauth](../../sinauth/) UUID strings —
each derived from its own separate authenticated HTTP request (the
Operator's `POST .../actions` and the Verifier's
`POST .../actions/{actionID}/approve`), never a client-supplied value. This
replaced an earlier internal representation that folded the user ID through
a lossy `hashUserID()` string→int64 hash; that fold is gone along with the
int64 field it existed to work around.

`actor_token` is intentionally left empty: the Operator's original bearer
token from the propose step is never retained (a bearer token is a
short-lived secret — citadel ADR-005 — and persisting it in
`pending_actions` across an arbitrarily long approval window would
reintroduce risk). `verifier_token` carries the Verifier's real token from
the approve request. CITADEL's Gate 1 treats a missing `actor_token` as a
non-blocking WARN while `citadel.enforce_signatures` stays false (its
documented soft-mode rollout behaviour).

The full schema lives at [../../citadel/docs/kerkese-spec.md](../../citadel/docs/kerkese-spec.md).

## The 5 MARSHAL gates

Every Kerkese runs through:

| Gate | Check | IRFlow-side consequence on fail |
|---|---|---|
| 1. AuthN | Session for `actor.user_id` is valid | Action rejected with 403 + `ErrMarshalRefused` |
| 2. AuthZ | Role is permitted to perform `action.type` | 403 + `ErrMarshalRefused` |
| 3. NDS | `operator_user_id ≠ verifier_user_id` AND different role groups | **HARD_STOP** — 403 + `ErrMarshalHardStop`; incident auto-frozen |
| 4. AUGUR | Off-hours / high-frequency / DATA_EXPORT-without-incident | WARN is logged but does not block; HARD_STOP on DATA_EXPORT |
| 5. WORM | Append outcome to chain | Always runs; a Gate-5 failure logs a warning but does not reverse the decision |

Gate outcomes:

- `EXECUTE` — action proceeds, persisted locally with `marshal_decision=EXECUTE`
- `REFUSE` — action is **not** persisted; caller sees 403
- `HARD_STOP` — action is **not** persisted; IRFlow emits an
  incident-severity upgrade and optionally triggers the freeze playbook

## Two-person-rule call flow

CITADEL is only ever contacted on the **approve** step — proposing an
action never reaches CITADEL.

```
POST /api/v1/incidents/{id}/actions                     (Operator's own session)
    ↓
incident.Service.ProposeAction
    └─► store.CreatePendingAction (status="pending")     — no CITADEL call

POST /api/v1/incidents/{id}/actions/{actionID}/approve   (Verifier's own session)
    ↓
incident.Service.ApproveAction
    ├─► SoD check: verifierUserID == pa.OperatorUserID → ErrSelfApproval (400)
    │      (also enforced at the DB level — see migrations/003_pending_actions.sql)
    ├─► store.Get(incident)     — to read project_id
    ├─► citadel.MarshalEvaluate(kerkese)
    │      ├─► sign Kerkese payload with IRFLOW_CITADEL_KEY_SECRET (HMAC-SHA256)
    │      ├─► POST /api/v1/marshal/evaluate
    │      └─► parse Decision{outcome, gates[], worm_entry_id}
    ├─► on REFUSE / HARD_STOP → return typed error, pa.status updated accordingly
    ├─► store.AddAction(marshal_decision, worm_entry_id)  — real IncidentAction
    └─► store.UpdatePendingAction(status="approved", action_id=...)
```

The IRFlow-side SoD pre-check exists so obvious mistakes (the same
identity trying to approve their own proposal) never leave IRFlow —
saving a network round-trip and avoiding WORM pollution with
predictably-rejected Kerkeses. Unlike the pre-check that used to compare
two client-supplied strings on a single request, this comparison is now
between two independently-authenticated identities across two separate
HTTP requests, so it cannot be defeated by a caller simply supplying two
different-looking strings for the same person.

## WORM emission — the asymmetry

IRFlow emits to WORM from two places:

- **Incident creation** (`incident.Service.Create`) — synchronous. A
  WORM failure fails the request because the audit chain is the
  authoritative record of when an incident came into being.
- **Everything else** (action persist, state transition, IOC
  enrichment) — best-effort. A missing WORM entry surfaces as
  `worm_entry_id = NULL` on the row; the corresponding CITADEL
  decision still contains the proof via its own Gate 5.

The asymmetry is deliberate: incidents *are* the root of truth for an
investigation; derived mutations can be reconstructed from their
MARSHAL decisions even if the IRFlow-side WORM reference is missing.

## Error handling

CITADEL returns typed errors that IRFlow surfaces with their semantic
HTTP codes:

| CITADEL outcome | IRFlow response | Meaning |
|---|---|---|
| 200 EXECUTE | 201 Created | Action stored |
| 200 REFUSE | 403 with `ErrMarshalRefused` | Retryable with corrected Kerkese |
| 200 HARD_STOP | 403 with `ErrMarshalHardStop` | Not retryable — this is a policy break |
| 5xx | 502 Bad Gateway | CITADEL unreachable; caller should retry |
| timeout | 504 Gateway Timeout | Upstream slow; retry after checking CITADEL health |

**Crucially**: a 5xx from CITADEL does **not** degrade to local-only
mode at runtime. An unauthorised action persisted without MARSHAL
approval is never recoverable, so IRFlow prefers an outright 502
— forcing the caller to retry or escalate.

## Observability

Three metric series cover this integration:

| Metric | Labels | Meaning |
|---|---|---|
| `irflow_governance_calls_total` | `target={citadel,nis2}`, `result={success,failure}` | Outbound call outcome |
| `irflow_governance_latency_seconds` | `target` | Latency of the outbound call |
| `irflow_marshal_decisions_total` | `outcome={EXECUTE,REFUSE,HARD_STOP}` | Breakdown of decisions returned |

Alerting rule: `rate(irflow_governance_calls_total{target="citadel",result="failure"}[5m]) > 0`
— any sustained CITADEL failure is incident-worthy on its own.

## Configuration

Minimum production settings:

```bash
IRFLOW_CITADEL_API_URL=https://citadel.internal
IRFLOW_CITADEL_KEY_ID=irflow-prod
IRFLOW_CITADEL_KEY_SECRET=<from secret manager>
IRFLOW_CITADEL_PROJECT_ID=prod
IRFLOW_CITADEL_DRY_RUN=false
```

`DRY_RUN=true` flips every MARSHAL call to "short-circuit EXECUTE"
without touching CITADEL — intended for staging environments where
the audit chain is not provisioned. Never true in production.

## Related

- [Webhook spec](./webhook-spec.md) — inbound side (CITADEL → IRFlow)
- [RBAC guide](./rbac-guide.md) — IRFlow-side SoD enforcement
- [../../citadel/docs/marshal-engine.md](../../citadel/docs/marshal-engine.md) — server-side gate semantics
- [../../citadel/docs/kerkese-spec.md](../../citadel/docs/kerkese-spec.md) — full Kerkese schema
