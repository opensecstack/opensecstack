---
status: Accepted
date: 2026-07-26
---
# ADR-004: Operator/Verifier Ed25519 signatures on every Kerkese

## Context

The IEEE paper describing CITADEL (Definition 2 "Non-Repudiation", Algorithm 1)
specifies that every governed action carries an Ed25519 signature from the
Operator and a distinct signature from the Verifier, both verified during
Gate 1 (AuthN) and Gate 3 (NDS), and both persisted in the WORM entry. Prior
to this ADR, no such mechanism existed anywhere in CITADEL: Gate 1 checked
only session existence, Gate 3 checked only that Operator and Verifier were
different user IDs in different role groups. No per-user key registry
existed, and none of the three producer platforms that submit governance
requests (apiguard, irflow, threatflow) derived Actor/Verifier identity from
an authenticated session — apiguard hardcoded `UserID: 0`; irflow trusted
client-supplied string IDs from the HTTP request body. A signature checked
against no real key, from an unauthenticated identity, proves nothing — so
this ADR also had to close those gaps, not just add signature verification
in isolation.

## Decision

### Canonical signing payload

Both the Operator and the Verifier sign the same deterministic, pipe-joined
string (never full-JSON canonicalization, which is a recurring source of
cross-implementation signature bugs):

```
v1|{execution_id}|{action.type}|{action.change_id}|{actor.user_id}|{actor.role}|{verifier.user_id}|{verifier.role}|{sod.operator_user_id}|{sod.verifier_user_id}|{ts_utc RFC3339}
```

Implemented identically in `citadel/internal/marshal/sig.go` (`CanonicalPayload`)
and `sdk/go/citadel/sign.go` (`CanonicalPayload`) — both are covered by tests
asserting the same fixture produces the same string
(`internal/marshal/sig_test.go`, `sdk/go/citadel/sign_test.go`).
`KerkeseEvidence` (free-form JSON) is deliberately excluded from the signed
surface: WORM's existing TripleHash/chain_hash already covers full-payload
integrity; the signature's job is proving who authorized what, not
re-proving payload integrity a second time.

### Key custody: self-custody CLI, CITADEL never sees a private key

`citadel keygen` (`internal/keygen`) generates an Ed25519 keypair locally,
writes the private key to a `0600` file, and prints the public key plus a
ready-to-run registration command. `POST /api/v1/keys/register`
(`internal/api/handlers/keys.go`) binds a public key to a `user_id`,
persisted in the new `signing_keys` table (`migrations/002_signing_keys.sql`).
Registration requires a live, non-revoked `session_id` that belongs to the
`user_id` being registered — CITADEL's HTTP layer has no other auth
middleware today, so this is the only thing preventing one user from
registering a key under someone else's identity.

### Gate wiring

Gate 1 (`gate1AuthN`) additionally verifies `SigOperator` against the
Operator's registered key; Gate 3 (`gate3NDS`) additionally verifies
`SigVerifier` against the Verifier's registered key. Both signatures are
persisted on the WORM entry itself (`migrations/003_worm_signatures.sql`),
so the immutable audit chain carries the non-repudiation evidence, not just
MARSHAL's in-memory decision.

### Rollout: temporary `enforce_signatures` flag

`Engine.EnforceSignatures(bool)` (default `false`, `CitadelConfig.EnforceSignatures`,
env `CITADEL_ENFORCE_SIGNATURES`) controls whether a missing/invalid
signature REFUSEs the gate (enforced) or only produces a `GateWarn` that does
not block (soft mode). This is temporary scaffolding for the multi-producer
rollout: apiguard, irflow, and threatflow cannot all migrate atomically, so
signature verification ships checked-and-tested but non-blocking until every
producer signs, then the flag is flipped to `true` and eventually deleted.
This is the one deliberate deviation from "enforce unconditionally" in this
ADR, and it is intentionally temporary, not a permanent configuration knob.

### Producer identity fixes (prerequisite, not optional)

apiguard's hardcoded `Actor.UserID: 0` / irflow's client-supplied
`OperatorID`/`VerifierID` strings are fixed as part of the same rollout —
see `sdk/go/citadel` migration work in apiguard/irflow/threatflow. A
signature from "user 0" or from a string ID nobody authenticated is not
non-repudiation; closing this gap was a precondition for the ADR's decision
to be meaningful, not a separate concern.

## Consequences

- New tables: `signing_keys` (per-user Ed25519 public key registry, separate
  from `anchors`, which is the unrelated periodic chain-anchor feature).
  `worm_entries` gains `sig_operator`/`sig_verifier` columns.
- New shared package `sdk/go/citadel` replaces three independently
  hand-duplicated, structurally-drifted `Kerkese` copies (apiguard,
  irflow, threatflow) — see `sdk/go/citadel/types.go`.
- `marshal.Store` interface grows `GetSigningKey`; `AppendWORM` grows two
  parameters. Both mock (`marshal_test.go`) and benchmark
  (`benches/marshal_bench_test.go`) stores were updated to match — the
  latter now benchmarks the Ed25519-inclusive latency, which is the number
  that should replace the pre-signature figure in the IEEE paper's
  benchmark table.
- CITADEL still has no HTTP-level auth middleware in front of
  `/marshal/evaluate` — Gate 1's session check plays that role today, and
  `/keys/register`'s session-ownership check is scoped narrowly to avoid
  assuming a general auth layer that does not exist. A real auth middleware
  layer remains future work, out of scope for this ADR.
- `enforce_signatures` is temporary: once apiguard, irflow, and threatflow
  all sign every Kerkese in the target environment, flip the flag to `true`
  and delete the flag and its soft-mode branches in a follow-up cleanup —
  tracked, not left open-ended.
