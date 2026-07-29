---
status: Accepted
date: 2026-07-26
---
# ADR-006: split `enforce_identity` from `enforce_signatures`

## Context

ADR-004/005 introduced a single `citadel.enforce_signatures` flag gating
BOTH the sinauth-token identity check (ActorToken/VerifierToken) and the
Ed25519 signature check (SigOperator/SigVerifier) together in Gate 1/Gate 3.
apiguard, irflow, and threatflow were then migrated in parallel to forward
real sinauth-authenticated identity — but none of them implemented per-user
Ed25519 key custody / signing (that remains future work, no producer has a
private-key UX yet). Under the combined flag, enabling identity enforcement
would have been impossible without also enabling signature enforcement,
which every producer would immediately fail (nobody signs).

## Decision

Split the single flag into two independent ones on `Engine`:
`EnforceIdentity(bool)` and `EnforceSignatures(bool)` (config:
`citadel.enforce_identity`, `citadel.enforce_signatures`). A new
`combineChecks` helper (`internal/marshal/marshal.go`) merges any number of
`(status, reason, enforce)` triples: REFUSE if any failed check is
enforced, WARN if any failed check is only soft-gated, PASS otherwise. Gate
1 combines the operator token check (`EnforceIdentity`) and operator
signature check (`EnforceSignatures`); Gate 3 combines both the operator
and verifier token checks (`EnforceIdentity`) and the verifier signature
check (`EnforceSignatures`).

### Both flags default to `false` — not just signatures

The original intent was to default `EnforceIdentity` to `true` now that all
three producers forward real tokens. That turned out to be wrong for the
*default* configuration of two of them, discovered before shipping:

- **apiguard**: `citadel.require_approval` (apiguard's own config, added
  alongside its new two-person approval flow) defaults to `false`. In that
  default state, apiguard submits a placeholder Verifier
  (`"apiguard-system-verifier"`) with an **empty** `VerifierToken` — by
  design, since there's no real second approver unless
  `require_approval=true`. `EnforceIdentity=true` would REFUSE every scan
  apiguard submits by default.
- **threatflow**: has no second-approver concept at all for any of its
  governed actions (`IOC_INGEST`, `IOC_REVOKE`, `STIX_BUNDLE_IMPORT`,
  `FEED_*`) — always submits the placeholder Verifier
  `"threatflow-system-verifier"` with an empty `VerifierToken`.
  `EnforceIdentity=true` would REFUSE every threatflow governed action,
  unconditionally, forever (there's no flag on threatflow's side to turn
  this off the way apiguard has `require_approval`).
- **irflow** is the only one actually ready: its new propose/approve flow
  only submits a Kerkese to CITADEL at approval time, and only with two
  real, distinct, authenticated tokens.

Turning `EnforceIdentity` on globally today would silently break apiguard's
and threatflow's default behavior. It stays `false` until: apiguard runs
with `require_approval=true` (or an equivalent), and threatflow gets its
own real second-approver flow (tracked, not built here) — or until
`EnforceIdentity` is scoped more finely than "all Kerkese, globally" (e.g.
enforced per-project-id, so irflow's real flow can be enforced independently
of apiguard/threatflow's placeholder flows — a follow-up worth considering,
not decided here).

## Consequences

- `Engine.New(store, verifier)` still starts in full soft mode; call
  `.EnforceIdentity(true)` and/or `.EnforceSignatures(true)` independently.
- New tests (`internal/marshal/marshal_test.go`) prove the two flags are
  genuinely independent: `TestGate1_EnforceIdentityAlone_DoesNotBlockOnMissingSignature`
  and `TestGate1_EnforceSignaturesAlone_DoesNotBlockOnMissingToken`.
- Neither flag is enabled in this change. Enabling `EnforceIdentity`
  globally requires a product decision on apiguard's `require_approval`
  default and a real second-approver flow for threatflow — both out of
  scope here, tracked as follow-ups. Enabling `EnforceSignatures` requires
  per-user Ed25519 key custody / signing UX on at least one producer,
  unchanged from ADR-004.
