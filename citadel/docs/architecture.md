# CITADEL Architecture

CITADEL is the governance engine for the OpenSecStack ecosystem. It
enforces dual-control authorisation on every privileged action and
anchors the resulting decisions in an append-only, hash-chained audit
log.

This document covers the internals. For the public API, see
[api.md](./api.md). For the security posture, see
[security-model.md](./security-model.md).

## High-level layout

```
                     +-------------------+
    caller plat.     |    HTTP server    |
     (IRFlow,        |   chi router      |
      APIGuard,      |   middleware      |
      NIS2Compass)   +---------+---------+
                               |
              +----------------+----------------+
              |                                 |
     +--------v--------+              +---------v--------+
     |    MARSHAL      |              |      WORM        |
     |  5-gate engine  |              |   Append-only    |
     |                 |              |   chain          |
     +--------+--------+              +---------+--------+
              |                                 |
              |     decisions anchored          |
              +---------------+-----------------+
                              |
                    +---------v---------+
                    |   PostgreSQL 16   |
                    |  + pgcrypto       |
                    +-------------------+
```

Every request flows through chi middleware (request-id, recovery,
security headers), the relevant handler, and — if the handler produces a
durable effect — a WORM emit that anchors the decision.

## MARSHAL — five-gate engine

Every Kerkese passes through five gates, in order. A failure at any gate
produces a `REFUSE` or `HARD_STOP`; only a full pass produces `EXECUTE`.

| # | Gate | Checks |
|---|---|---|
| 1 | **Schema** | Kerkese structure, required fields, enumerations, timestamp sanity |
| 2 | **SoD** (Separation of Duties) | Operator ID ≠ verifier ID; roles are mutually compatible |
| 3 | **Policy** | Project-scoped allow-list for action types; role-to-action matrix |
| 4 | **Rate** | Per-actor + per-project token bucket; prevents runaway automation |
| 5 | **Emergency** | Optional override — requires `emergency=true` + `emergency_justification` that is itself auditable |

Each gate records its outcome + latency, so `gates[]` in the response
doubles as a compliance artefact ("why did this decision take 8 ms?").

Gate evaluation is fully in-memory after the initial Kerkese parse —
the 8 µs mean latency quoted in [api.md](./api.md#performance-envelope)
is dominated by JSON decoding, not policy lookup.

### Outcomes

| Outcome | Meaning |
|---|---|
| `EXECUTE` | All five gates passed. The caller may proceed with the action. |
| `REFUSE`  | At least one policy or SoD check failed. The caller must not proceed. |
| `HARD_STOP` | Emergency freeze, rate-limit breach, or signed policy revocation. Overrides any dual-control grant. Triggers a P1 incident upstream (IRFlow's CITADEL webhook handler). |

## WORM chain

Every write to the WORM table is an event record containing:

- A generated `id` (UUID v4)
- `source` (platform emitting the event)
- `event_type` (e.g. `incident.created`, `marshal.execute`, `worm.anchor`)
- `project_id`
- `payload` (raw JSON, application-defined)
- `timestamp` (UTC)
- `prev_hash` — hex(SHA-256) of the previous entry's `chain_hash`
- `chain_hash` — hex(SHA-256(prev_hash ‖ TripleHash(entry))) — see below
- `sequence_num` — strictly monotonic per-CITADEL-instance

The `sequence_num` is the reason CITADEL is currently **single-writer**:
two active instances would each allocate `sequence_num = N+1` and produce
divergent chains. Sharded multi-writer is tracked for v2.0.

### TripleHash

The `TripleHash(entry)` inputs a concatenation of:

```
SHA-256(canonical_json(entry)) ‖ SHA-512(canonical_json(entry)) ‖ BLAKE3(canonical_json(entry))
```

The rationale for three hash functions of different families:

- **SHA-256** — ubiquitous, hardware-accelerated on every modern CPU.
- **SHA-512** — same Merkle-Damgård construction as SHA-256 but with
  double the output size; resistant to a SHA-256-specific preimage or
  collision attack.
- **BLAKE3** — a completely different construction (Merkle tree, not
  Merkle-Damgård). If a flaw is discovered in either SHA variant, BLAKE3
  still binds the entry.

An attacker who wants to silently mutate an old entry would need to
forge a collision in all three hash families simultaneously — currently
believed to be computationally infeasible. TripleHash doubles the
audit-integrity budget at roughly 3× the hashing cost (still only ~2 µs
for a 100-byte payload).

### Anchoring

Every N entries (configurable, default: hourly batch), CITADEL signs
the latest `chain_hash` with an **Ed25519 anchor key** and emits an
`anchor` event. A verifier replaying the chain compares its recomputed
`chain_hash` at each anchor against the signed value — any divergence
proves tampering and pinpoints the sequence range.

Anchor keys are stored in CITADEL's config secrets today; HSM-backed
anchoring is tracked for v1.1 (see [security-model.md](./security-model.md#keys)).

## Request lifecycle

For `POST /api/v1/marshal/evaluate`:

```
HTTP request  →  chi middleware (request-id, recovery)
              →  JSON parse + Kerkese validation
              →  Gate 1 (schema)
              →  Gate 2 (SoD)
              →  Gate 3 (policy)
              →  Gate 4 (rate)
              →  Gate 5 (emergency)
              →  Outcome assembled
              →  WORM emit (the decision itself is an event)
              →  JSON response + `worm_entry_id`
```

If any gate rejects, WORM still records the denied decision — refusals
are just as important in a compliance context.

## Component boundaries

| Package | Responsibility |
|---|---|
| `cmd/citadel` | CLI entrypoint, config loading, graceful shutdown |
| `internal/api` | chi router, middleware stack, handler wiring |
| `internal/api/handlers` | `Health`, `Marshal`, `WORM` HTTP types |
| `internal/marshal` | Engine, gate implementations, Kerkese types |
| `internal/db` | pgxpool, WORM table operations, MarshalStore adapter |
| `internal/config` | env + YAML configuration |
| `internal/version` | build-time version stamps |
| `benches/` | Benchmark suite under `-tags bench` |

The dependency graph is strictly one-way: `api → marshal`, `api → db`,
`marshal → db` (via `MarshalStore`), never the other direction. This is
what allows MARSHAL to be benchmarked in isolation without a database
by swapping in an in-memory store.

## Scaling characteristics

| Dimension | Property |
|---|---|
| Vertical (single instance) | ≥ 100k evaluations/sec on modern server CPU (MARSHAL is CPU-bound, not I/O-bound) |
| WORM write throughput | Disk-bound — sync commit on Postgres 16 caps at ~5 ms per entry; 200 emits/sec per CITADEL instance is a realistic production ceiling |
| Horizontal | **Single-writer today.** Active/passive failover supported via leader-lock (Consul, K8s Lease); multi-writer sharded-chain design planned for v2.0 |

## Related

- [API reference](./api.md) — wire format for each endpoint
- [Security model](./security-model.md) — threat model, key handling
- [Integration guide](./integration.md) — how each platform calls CITADEL
- [`../ARCHITECTURE.md`](../../ARCHITECTURE.md) — ecosystem-level architecture (all platforms)
