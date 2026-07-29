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

Not pictured above: CITADEL also depends on **sinauth** (the ecosystem's
OIDC identity provider) at runtime. Gate 1/Gate 3 call out to sinauth's
JWKS endpoint (via `internal/auth.SinauthVerifier`) to verify
`actor_token`/`verifier_token`, and the server refuses to start if
`CITADEL_CITADEL_SINAUTH_ISSUER_URL` is unreachable — see
[ADR-005](../adrs/005-sinauth-identity-bridge.md).

## MARSHAL — five-gate engine

Every Kerkese passes through five gates, in order (`internal/marshal/marshal.go`,
`Engine.Evaluate`). A failure at any gate produces `REFUSE` or `HARD_STOP`;
only a full pass produces `EXECUTE`. Gate 5 (WORM) always runs, regardless
of the outcome of gates 1–4 — refusals are logged too.

| # | Gate | Checks |
|---|---|---|
| 1 | **AuthN** | Actor's sinauth bearer token (`actor_token`) authenticates `actor.user_id`; Actor's Ed25519 signature (`sig_operator`) verifies against a registered key. See [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md) / [ADR-005](../adrs/005-sinauth-identity-bridge.md) |
| 2 | **AuthZ** | RBAC: `actor.role` must be permitted to perform `action.type`, per the fixed `rbacMap` in `internal/marshal/types.go` (always enforced), composed with an optional soft-launch Permify-snapshot check ([ADR-007](../adrs/007-permify-gate2-snapshot.md)) |
| 3 | **NDS** (Separation of Duties) | Operator ID ≠ Verifier ID and different role groups (unconditional `HARD_STOP` if violated); Operator and Verifier sinauth tokens authenticate; Verifier's Ed25519 signature (`sig_verifier`) verifies |
| 4 | **AUGUR** | 3 behavioral heuristic rules: off-hours action (outside 07:00–19:00 UTC) → `WARN`; >10 actions by the same actor in 5 minutes → `WARN`; `DATA_EXPORT` without `incident_id` → unconditional `HARD_STOP` |
| 5 | **WORM** | Unconditional append-only log of the decision, with TripleHash. Bearer tokens are redacted before archiving; Ed25519 signatures are persisted as non-repudiation evidence |

Each gate records its outcome + latency, so `gates[]` in the response
doubles as a compliance artefact ("why did this decision take 8 ms?").

Gate evaluation is fully in-memory after the initial Kerkese parse and the
(network-bound) sinauth token verification calls in Gates 1/3 — the 8 µs
mean latency quoted in [api.md](./api.md#performance-envelope) predates
those calls and has not yet been re-measured with them live.

### Identity and signature checks are soft-gated, independently

Gate 1 and Gate 3's token and signature checks always run and are always
recorded in `gates[]`, but whether a failure actually blocks the decision
is controlled by two independent `Engine` flags — `EnforceIdentity` and
`EnforceSignatures` (config: `citadel.enforce_identity`,
`citadel.enforce_signatures`; both **default `false`**). `combineChecks()`
(`internal/marshal/marshal.go`) merges the sub-checks: `REFUSE` if any
failed check is enforced, `WARN` if a failed check is only soft-gated,
`PASS` otherwise. See [ADR-006](../adrs/006-split-enforce-identity-and-signatures.md)
for why the two flags are split and why both still default off — briefly,
apiguard's and threatflow's default configurations submit a placeholder
Verifier with no `verifier_token`, and no producer platform has per-user
Ed25519 signing UX yet.

The structural SoD invariants in Gate 3 — same identity, same role group —
are **not** behind either flag; they are unconditional `HARD_STOP`s.

### Gate 2 is now a two-check composition

`gate2AuthZ` (`internal/marshal/marshal.go`) builds two `enforcedCheck`s
folded via the same `combineChecks` helper ADR-006 introduced for
Gate 1/Gate 3:

- **Check A — `rbacMap`** (`roleAllowed`): the permanent safety net,
  `enforce: true` always, unconditionally. This is never weakened by
  the Permify work below or any future change.
- **Check B — Permify snapshot** (`permifyCheck`, backed by a
  `PermifySnapshot` interface implemented by
  `internal/permifysync.Snapshot`, a periodically-refreshed local
  table — never a live per-request call to Permify): `enforce:
  cfg.EnforcePermifyAuthz` (config `citadel.enforce_permify_authz`,
  default `false`). An unknown/unsynced role-action pair is always
  PASS; only an explicit known-deny is a fail candidate, and even then
  it only `REFUSE`s once the flag is on — until then it only `WARN`s.
  A `nil` snapshot (unwired, or `PermifyURL` unset) makes this
  sub-check a no-op PASS, identical to today's rbacMap-only behavior.

See [ADR-007](../adrs/007-permify-gate2-snapshot.md) for the full design.

### Known limitation: `rbacMap` does not cover most real producers

Gate 2 (AuthZ)'s `rbacMap` check is a hard, unconditional check — there
is no soft mode for it. `rbacMap`/`roleGroupMap` in
`internal/marshal/types.go` list a handful of legacy action types
(`API_SCAN_INITIATE`, `INCIDENT_CREATE`, `DATA_EXPORT`, `CONFIG_CHANGE`,
`USER_CREATE`/`DELETE`, `PLAYBOOK_EXECUTE`, `IOC_INGEST`) across 5 roles
(`admin`, `operator`, `analyst`, `viewer`, `auditor`). Nine producer
platforms (apiguard, irflow, threatflow, opencsirt, openscrub,
securelab, community, cyberpath, nis2compass) were wired this session to
submit real governance requests to CITADEL, but their actual `action.type`
values and role names were not added to these maps. In practice, this
means most real `evaluate()` calls from those platforms will `REFUSE` at
Gate 2 today, even with `enforce_identity`/`enforce_signatures` both off.
This is a real, open gap — not a hidden one. The Permify-snapshot check
above (ADR-007) does not close this gap yet either: the synced snapshot
is currently expected to be empty/near-empty, since sinauth's Permify
schema doesn't yet model CITADEL's action-type vocabulary — tracked for
a follow-up change to `rbacMap`/`roleGroupMap` and/or the Permify schema.

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
              →  JSON parse + Kerkese defaulting (ts_utc, execution_id)
              →  Gate 1 (AuthN — sinauth token + Ed25519 signature)
              →  Gate 2 (AuthZ — RBAC)
              →  Gate 3 (NDS — Separation of Duties + identity/signature)
              →  Gate 4 (AUGUR — behavioral heuristics)
              →  Gate 5 (WORM — unconditional append)
              →  Outcome assembled
              →  WORM emit (the decision itself is an event)
              →  JSON response + `worm_entry_id`
```

If any gate rejects, WORM still records the denied decision — refusals
are just as important in a compliance context.

## Component boundaries

| Package | Responsibility |
|---|---|
| `cmd/citadel` | CLI entrypoint (incl. `citadel keygen`), config loading, graceful shutdown |
| `internal/api` | chi router, middleware stack, handler wiring |
| `internal/api/handlers` | `Health`, `Marshal`, `WORM`, `Keys` HTTP types |
| `internal/marshal` | Engine, gate implementations, Kerkese types, Ed25519 canonical-payload signing (`sig.go`) |
| `internal/auth` | `SinauthVerifier` — bridges Gate 1/Gate 3 token checks to sinauth's JWKS via `sdk/go/sinauth` |
| `internal/keygen` | `citadel keygen` CLI — generates an Operator/Verifier Ed25519 keypair locally; CITADEL never sees the private key |
| `internal/db` | pgxpool, WORM table operations, `MarshalStore` adapter, `signing_keys` registry |
| `internal/config` | env configuration (Viper) |
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
