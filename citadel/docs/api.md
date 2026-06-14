# CITADEL API Reference

CITADEL exposes a minimal REST API. Every endpoint returns JSON with
`Content-Type: application/json`. Default listen address: `:8099`.

- **Transport**: HTTPS is terminated upstream (ingress / load balancer);
  CITADEL itself speaks plain HTTP on its bind port.
- **Authentication**: mutating endpoints (`POST /marshal/evaluate`,
  `POST /worm/emit`) expect an HMAC-SHA256 signature in
  `X-Citadel-Signature`. CITADEL verifies the signature in Phase-4+
  builds; v1.0.0 accepts signatures but does not yet enforce them
  server-side — see [security-model.md](./security-model.md#authentication).
- **Idempotency**: WORM emits use a client-side `event_id` to deduplicate
  retried submissions.

## Endpoints

### `GET /api/v1/health`

Liveness + build metadata. Used by load balancers.

```json
{
  "status":  "ok",
  "version": "1.0.0",
  "commit":  "abc1234",
  "built":   "2026-04-08T10:30:00Z",
  "db":      "ok"
}
```

Returns 200 when ready, 503 when the database ping fails.

### `POST /api/v1/marshal/evaluate`

Submit a Kerkese (governance evaluation request) to the MARSHAL engine.
See [integration.md](./integration.md) for the full Kerkese schema.

Request:

```json
{
  "kerkese_version": "v2.0",
  "ts_utc":          "2026-04-19T10:00:00Z",
  "project_id":      "proj-a",
  "execution_id":    "550e8400-e29b-41d4-a716-446655440000",
  "action":          { "type": "contain", "incident_id": "inc-42" },
  "actor":           { "user_id": 1001, "role": "operator" },
  "verifier":        { "user_id": 1002, "role": "verifier" },
  "evidence":        { "extra": { "note": "blocking endpoint" } },
  "sod":             { "operator_user_id": 1001, "verifier_user_id": 1002 },
  "dry_run":         false
}
```

Response:

```json
{
  "outcome":       "EXECUTE",
  "execution_id":  "550e8400-e29b-41d4-a716-446655440000",
  "worm_entry_id": "a1b2c3d4-...",
  "gates": [
    { "gate": 1, "name": "schema",    "status": "pass", "latency_ms": 0.12 },
    { "gate": 2, "name": "sod",       "status": "pass", "latency_ms": 0.05 },
    { "gate": 3, "name": "policy",    "status": "pass", "latency_ms": 1.20 },
    { "gate": 4, "name": "rate",      "status": "pass", "latency_ms": 0.08 },
    { "gate": 5, "name": "emergency", "status": "skip", "latency_ms": 0.01 }
  ],
  "reasons": [],
  "ts_utc":  "2026-04-19T10:00:00.123Z"
}
```

HTTP status mapping:

| Outcome     | HTTP |
|---|---|
| `EXECUTE` | 200 |
| `REFUSE`  | 200 (decision is a valid response, not an error) |
| `HARD_STOP` | 403 |

### `POST /api/v1/worm/emit`

Append an event to the immutable audit chain. Called by every platform
for lifecycle events that must survive tampering.

Request:

```json
{
  "source":     "irflow",
  "event_type": "incident.created",
  "project_id": "proj-a",
  "payload":    { "incident_id": "inc-42", "severity": "P1" }
}
```

Response:

```json
{
  "worm_entry_id": "a1b2c3d4-...",
  "chain_hash":    "<hex-sha256>",
  "prev_hash":     "<hex-sha256>",
  "sequence_num":  1042
}
```

The `chain_hash` is computed as `SHA-256(prev_hash ‖ TripleHash(event))` —
see [architecture.md](./architecture.md#worm-chain). Clients should persist
the returned `worm_entry_id` on the originating record so the audit trail
can be reconstructed later.

### `GET /api/v1/worm/verify`

Walk the chain between two timestamps and verify hash continuity.

Query parameters:

| Param | Format | Default |
|---|---|---|
| `from` | RFC3339 | now − 24 h |
| `to`   | RFC3339 | now |

Response:

```json
{
  "valid":            true,
  "entries_verified": 8342,
  "break_at":         "",
  "anchor_verified":  true
}
```

When `valid` is false, `break_at` contains the ID of the first entry
whose `chain_hash` does not match `SHA-256(prev_hash ‖ TripleHash)` —
forensic investigation should focus there.

## Error format

Every failure response uses:

```json
{ "error": "human-readable message" }
```

| HTTP | When |
|---|---|
| 400 | Malformed Kerkese, malformed WORM payload, invalid RFC3339 timestamp |
| 403 | MARSHAL `HARD_STOP` outcome |
| 500 | Internal failure — logged with CITADEL's request ID |
| 503 | Database unreachable on `/health` |

## Performance envelope

On an Intel Core i7-7600U (2.80 GHz, Go 1.24):

| Operation | Mean latency | Allocs |
|---|---|---|
| MARSHAL evaluate (`EXECUTE`) | 8.2 µs | 31 |
| MARSHAL evaluate (`HARD_STOP`) | 10.9 µs | 32 |
| TripleHash (100 B payload) | 2.0 µs | 2 |
| WORM chain step | 533 ns | 0 |
| Full WORM emit (in-memory) | 3.7 µs | 6 |

A production PostgreSQL-backed emit adds ≈ 4 ms for the synchronous
INSERT on the WORM table — disk is the limit, not the chain algebra.

## Related

- [Architecture](./architecture.md) — MARSHAL internals, TripleHash rationale
- [Security model](./security-model.md) — what CITADEL trusts and enforces
- [Integration](./integration.md) — how each platform talks to CITADEL
