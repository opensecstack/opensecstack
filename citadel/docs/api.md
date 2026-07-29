# CITADEL API Reference

CITADEL exposes a minimal REST API. Every endpoint returns JSON with
`Content-Type: application/json`. Default listen address: `:8099`.

- **Transport**: HTTPS is terminated upstream (ingress / load balancer);
  CITADEL itself speaks plain HTTP on its bind port.
- **Webhook/event transport authentication**: `POST /worm/emit` expects an
  HMAC-SHA256 signature in `X-Citadel-Signature` per
  [ADR-002](../adrs/002-hmac-sha256-event-signing.md). CITADEL still
  accepts this header but does not yet enforce it server-side — see
  [security-model.md](./security-model.md#what-citadel-trusts).
- **Kerkese identity/signature authentication** (`POST /marshal/evaluate`):
  the Kerkese body itself carries the Actor's and Verifier's identity —
  `actor_token`/`verifier_token` (sinauth-issued bearer JWTs) and
  `sig_operator`/`sig_verifier` (hex Ed25519 signatures over
  `CanonicalPayload(k)`, produced by `citadel keygen` + your own signing
  code — see `sdk/go/citadel.Sign`). Gate 1 (AuthN) and Gate 3 (NDS)
  verify both, but only *block* the decision if the corresponding
  `citadel.enforce_identity` / `citadel.enforce_signatures` config flag is
  on — **both default to `false`** today, so a Kerkese with a missing or
  invalid token/signature currently produces a `WARN` gate, not a
  `REFUSE`. See [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md),
  [ADR-005](../adrs/005-sinauth-identity-bridge.md), and
  [ADR-006](../adrs/006-split-enforce-identity-and-signatures.md).
- **Idempotency**: not yet implemented. `POST /worm/emit` has no
  `event_id` deduplication today — a replayed request produces a new WORM
  entry. Tracked in [known-limitations.md](./known-limitations.md).

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

`actor.user_id`, `verifier.user_id`, and `sod.*_user_id` are **sinauth
UUID strings**, not integers — see
[ADR-005](../adrs/005-sinauth-identity-bridge.md). `actor_token`/
`verifier_token` and `sig_operator`/`sig_verifier` are optional today
(soft-gated — see [Authentication](#authentication) above), but Gate 1/
Gate 3 verify and record them whenever present.

Request:

```json
{
  "kerkese_version": "v2.0",
  "ts_utc":          "2026-04-19T10:00:00Z",
  "project_id":      "proj-a",
  "execution_id":    "550e8400-e29b-41d4-a716-446655440000",
  "action":          { "type": "contain", "incident_id": "inc-42" },
  "actor":           { "user_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "role": "operator" },
  "verifier":        { "user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7", "role": "verifier" },
  "evidence":        { "extra": { "note": "blocking endpoint" } },
  "sod":             { "operator_user_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6", "verifier_user_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7" },
  "actor_token":     "<sinauth-issued bearer JWT for the Actor>",
  "verifier_token":  "<sinauth-issued bearer JWT for the Verifier>",
  "sig_operator":    "<hex Ed25519 signature over CanonicalPayload(k), by the Actor>",
  "sig_verifier":    "<hex Ed25519 signature over CanonicalPayload(k), by the Verifier>",
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
    { "gate": 1, "name": "AuthN",   "status": "PASS", "latency_ms": 0.12 },
    { "gate": 2, "name": "AuthZ",   "status": "PASS", "latency_ms": 0.05 },
    { "gate": 3, "name": "NDS",     "status": "PASS", "latency_ms": 1.20 },
    { "gate": 4, "name": "AUGUR",   "status": "PASS", "latency_ms": 0.08 },
    { "gate": 5, "name": "WORM",    "status": "PASS", "latency_ms": 0.01 }
  ],
  "reasons": [],
  "ts_utc":  "2026-04-19T10:00:00.123Z"
}
```

Gate `status` is one of `PASS`, `WARN`, `FAIL`, or `HARD_STOP` (see
`internal/marshal/types.go`). A `WARN` status means the check failed but
its enforce flag is off, so it did not change the outcome — check
`reason` for what would fail once the flag is turned on.

HTTP status mapping:

| Outcome     | HTTP |
|---|---|
| `EXECUTE` | 200 |
| `REFUSE`  | 403 |
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

### `POST /api/v1/keys/register`

Registers an Ed25519 public signing key for a sinauth `user_id`, used by
MARSHAL Gate 1/Gate 3 to verify `sig_operator`/`sig_verifier`. See
[ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md). Generate a
keypair locally with `citadel keygen` — the private key never leaves your
machine or reaches CITADEL.

Request:

```json
{
  "user_id":    "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "token":      "<live sinauth bearer token whose subject matches user_id>",
  "key_id":     "myname",
  "public_key": "<64 hex chars — 32-byte Ed25519 public key>"
}
```

`token` must be a currently-valid sinauth bearer token whose verified
subject equals `user_id` — this is the only check standing between "this
key belongs to `user_id`" and "anyone can register a key for anyone",
since CITADEL has no other HTTP-level auth middleware in front of this
endpoint. Re-registering the same `key_id` for a `user_id` overwrites the
stored public key and clears any prior revocation.

Response (`201 Created`):

```json
{
  "key_id":        "myname",
  "registered_at": "2026-07-26T10:00:00Z"
}
```

Errors: `400` for a malformed body, a `public_key` that isn't 64 hex
characters, or missing fields; `403` if `token` doesn't verify or its
subject doesn't match `user_id`.

### `GET /api/v1/keys/{user_id}`

Looks up the active (non-revoked) signing key registered for `user_id`.
Public keys are not secret — this endpoint requires no authentication.

Response (`200 OK`):

```json
{
  "key_id":        "myname",
  "registered_at": "2026-07-26T10:00:00Z"
}
```

`404` if `user_id` has no active signing key.

## Error format

Every failure response uses:

```json
{ "error": "human-readable message" }
```

| HTTP | When |
|---|---|
| 400 | Malformed Kerkese, malformed WORM payload, invalid RFC3339 timestamp, malformed `/keys/register` body |
| 403 | MARSHAL `REFUSE` or `HARD_STOP` outcome; `/keys/register` token doesn't match `user_id` |
| 404 | `/keys/{user_id}` — no active signing key for that user |
| 500 | Internal failure — logged with CITADEL's request ID |
| 503 | Database unreachable on `/health` |

## Performance envelope

These figures predate the sinauth-token and Ed25519-signature checks added
to Gate 1/Gate 3 (ADR-004/005) and have not yet been re-measured with them
live — expect Gate 1/Gate 3 latency to grow, dominated by the (network-bound)
sinauth token verification call when `actor_token`/`verifier_token` are
present.

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
