# Kerkese — CITADEL Request Schema

A **Kerkese** (Albanian: *request*) is the canonical envelope every
caller sends to `POST /api/v1/marshal/evaluate`. It names the actor,
the action they intend to perform, the dual-control counterparty
(when applicable), and enough context for AUGUR to reason about
behavioural heuristics. MARSHAL runs five gates over the Kerkese and
returns a `Decision`.

For the Go struct, see [internal/marshal/types.go](../internal/marshal/types.go).
For the evaluation logic, see [marshal-engine.md](./marshal-engine.md).

## Full JSON shape

```json
{
  "execution_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98",
  "project_id":   "prod",

  "actor": {
    "user_id": 42,
    "role":    "operator"
  },

  "sod": {
    "operator_user_id": 42,
    "verifier_user_id": 77
  },

  "action": {
    "type":         "CONTAIN",
    "incident_id":  "inc_2026_0123",
    "payload_hash": "sha256:abcd1234..."
  },

  "dry_run": false,
  "ts_utc":  "2026-04-19T10:12:03Z"
}
```

## Field reference

### `execution_id` — UUID

Caller-supplied idempotency key. MARSHAL uses it to de-duplicate
retries and to correlate the decision with the caller's own execution
log. When absent, CITADEL generates one server-side and returns it in
the Decision — but callers should always supply their own so retries
across CITADEL restarts remain coherent.

### `project_id` — string

Logical partition for the WORM chain. The chain remains a single
linear log; `project_id` lets auditors filter decisions to one
tenant / service / regulator jurisdiction without scanning unrelated
entries. Defaults to `"citadel"` when empty.

### `actor` — object (required)

The identity performing the action.

| Field | Type | Notes |
|---|---|---|
| `user_id` | int64 | Primary key into CITADEL's session store. Gate 1 uses this to look up the session. |
| `role` | string | Claimed role. Gate 1 rejects if it doesn't match the session's recorded role; Gate 2 uses it for RBAC. |

### `sod` — object (conditional)

Separation of Duties counterparty. Required for every action that
Gate 2 classifies as SoD-sensitive (most containment / data-handling
actions). For read-only or self-service actions it may be omitted —
the gate short-circuits PASS when both user IDs are zero.

| Field | Type | Notes |
|---|---|---|
| `operator_user_id` | int64 | The initiating user. Must equal `actor.user_id` in normal flows; dual-identity proxies are forbidden. |
| `verifier_user_id` | int64 | The approving counterparty. Must differ from `operator_user_id` AND belong to a different role group (enforced by Gate 3). |

### `action` — object (required)

The act being authorised.

| Field | Type | Notes |
|---|---|---|
| `type` | string | Canonical verb: `CREATE_INCIDENT`, `CONTAIN`, `RESTORE`, `DATA_EXPORT`, `VERIFY`, etc. Gate 2 maps role → allowed types. |
| `incident_id` | string | Scope binding. Required for `DATA_EXPORT` (rule_03 HARD_STOP) and recommended for every mutation. Empty for pre-incident actions. |
| `payload_hash` | string | Digest of the caller's action payload (e.g. `sha256:...`). Not used for evaluation; anchored to WORM for forensics. |

### `dry_run` — boolean

When `true`, MARSHAL returns a full Decision but **skips** the Gate 5
WORM append. Use for:

- Client-side tests.
- "What would happen if…?" policy simulations.
- Debugging REFUSE patterns without polluting the chain.

Never `true` on a production path.

### `ts_utc` — RFC3339 timestamp

Time the caller built the Kerkese. AUGUR rule_01 uses the hour
portion. Clock skew tolerance is not enforced at the Kerkese layer —
callers are expected to send `time.Now().UTC()`. The WORM entry
records the *server* timestamp separately.

## Validation

At ingress, CITADEL validates:

| Check | Failure |
|---|---|
| JSON parses | `400 Bad Request: invalid JSON` |
| `actor.user_id > 0` | `400: actor.user_id is required` |
| `actor.role != ""` | `400: actor.role is required` |
| `action.type != ""` | `400: action.type is required` |
| `ts_utc` is valid RFC3339 | `400: ts_utc parse error: ...` |

All other validation is gate-level — `execution_id` can be zero
(server mints one), `sod.*` can be zero when not applicable,
`project_id` defaults.

## Decision response

```json
{
  "execution_id": "7e9a9a7e-2a1f-4c13-9f60-5a1f2e0d1a98",
  "outcome":      "EXECUTE",
  "dry_run":      false,
  "ts_utc":       "2026-04-19T10:12:03.412Z",
  "gates": [
    { "gate": 1, "name": "AuthN", "status": "PASS", "latency_ms": 0.84 },
    { "gate": 2, "name": "AuthZ", "status": "PASS", "latency_ms": 0.21 },
    { "gate": 3, "name": "NDS",   "status": "PASS", "latency_ms": 1.12 },
    { "gate": 4, "name": "AUGUR", "status": "PASS", "latency_ms": 1.43 },
    { "gate": 5, "name": "WORM",  "status": "PASS", "latency_ms": 4.22 }
  ],
  "reasons":        [],
  "worm_entry_id":  "wo_0000017234"
}
```

`outcome` ∈ `{EXECUTE, REFUSE, HARD_STOP}`. `reasons` is empty when
`outcome == EXECUTE` and otherwise contains the concatenated reasons
from failing gates in gate order.

`worm_entry_id` is present whenever Gate 5 succeeded — i.e. even
when gates 1-4 rejected the call. Callers can quote this ID when
later retrieving the WORM entry for forensics.

## Canonical signing

IRFlow and other signed callers HMAC-SHA256 the raw JSON body with
their shared `KEY_SECRET`. CITADEL returns 401 on signature mismatch
— reject, don't MARSHAL. See [integration.md](./integration.md) for
the HMAC scheme in full.

## Related

- [MARSHAL engine](./marshal-engine.md) — gate-by-gate evaluation
- [API reference](./api.md#post-apiv1marshalevaluate) — HTTP-level details
- [Integration patterns](./integration.md) — how downstream platforms build Kerkeses
- [WORM log](./worm-log.md) — what `worm_entry_id` points at
