---
status: Accepted
date: 2026-07-28
---
# ADR-007: Permify-derived Gate 2 snapshot check

## Context

CITADEL's MARSHAL Gate 2 (AuthZ) checks a hardcoded `rbacMap` covering only
5 roles / 10 action types drawn from apiguard/irflow/threatflow's
vocabulary — a real scope gap now disclosed in the IEEE paper's
limitations section, since the ecosystem has grown to 11 platforms with far
more action types than the map covers.

Separately, sinauth adopted Permify (open-source Zanzibar-style ReBAC/RBAC
engine) as the authorization engine behind its previously-dead
`rbac.Evaluate` path (see `sinauth/adrs/`). This ADR covers the second,
later half of that decision: deriving CITADEL's Gate 2 policy from the same
Permify instance/schema over time, closing the role/action coverage gap
without ever weakening what Gate 2 already guarantees today.

Two hard constraints, carried over from the plan this work was scoped
under:

1. Gate 2 must NOT make a live synchronous call to Permify per-request —
   it is currently an in-process map lookup at ~microsecond latency, in the
   hot path of every governed action across 11 platforms. It reads a
   periodically-refreshed local snapshot instead
   (`internal/permifysync`, a `time.Ticker`-driven goroutine that upserts
   into a local `permify_role_action_snapshot` table and exposes a fast
   in-memory `Snapshot.Allowed(role, actionType) (allowed, known bool)`
   read method).
2. Any new CITADEL enforcement behavior rolls out behind a new flag
   defaulting `false`, exactly mirroring `EnforceIdentity`/
   `EnforceSignatures` (ADR-006) — no platform's current default behavior
   changes when this ships. This is the same rollout shape as ADR-006: new
   flag, defaults false, existing behavior unchanged until a deployment
   opts in.

## Decision

Rewrite `gate2AuthZ` (`internal/marshal/marshal.go`) to build two
`enforcedCheck`s folded via the existing `combineChecks` helper (the same
mechanism ADR-006 introduced for Gate 1/Gate 3):

- **Check A — rbacMap** (`roleAllowed`): the permanent safety net,
  `enforce: true` **always**, unconditionally, regardless of any flag. This
  is never weakened by this change or any future one — it is the one
  guarantee Gate 2 has always made and continues to make.
- **Check B — Permify snapshot** (`permifyCheck`, backed by a new
  `PermifySnapshot` interface with a single `Allowed(role, actionType)
  (allowed, known bool)` method, implemented by
  `internal/permifysync.Snapshot`): `enforce: cfg.EnforcePermifyAuthz`
  (new flag, `citadel.enforce_permify_authz`, default `false`). Critically,
  `known == false` (Permify has not synced an opinion for this role/action
  yet) is treated as a **PASS** for this check — absence of Permify data
  must never itself cause a REFUSE. Only an explicit `known=true,
  allowed=false` is a fail candidate, and even then it only REFUSEs once
  the flag is on; until then it only WARNs.

New config (`CitadelConfig`): `PermifyURL` (`mapstructure:"permify_url"`,
default `""` — the same Permify instance/schema sinauth's `internal/authz`
writes to, not a separate one), `EnforcePermifyAuthz`
(`mapstructure:"enforce_permify_authz"`, default `false`),
`PermifySyncInterval` (`mapstructure:"permify_sync_interval"`, default
`5m`). `Engine` gains `EnforcePermifyAuthz(enforce bool) *Engine` and
`PermifySnapshot(snapshot PermifySnapshot) *Engine`, both the same
immutable-copy-builder shape as `EnforceIdentity`/`EnforceSignatures`. A
`nil` snapshot (unwired, or `PermifyURL` unset) makes the Permify sub-check
a no-op PASS for every role/action, identical to today's rbacMap-only
behavior.

## Consequences

- With `EnforcePermifyAuthz=false` (the default, and the state of every
  existing deployment until it explicitly opts in): Gate 2's outcome is
  bit-for-bit identical to before this change whenever rbacMap passes — a
  Permify-known deny can only produce a `WARN`, which does not change
  `Decision.Outcome`. A role/action combination absent from `rbacMap`
  still fails closed exactly as before, Permify or no Permify.
- With `EnforcePermifyAuthz=true`: a role/action explicitly denied by the
  synced Permify policy (`known=true, allowed=false`) now REFUSEs, even if
  it happens to be absent from `rbacMap` (rbacMap already failed it) or
  present there. rbacMap continues to gate REFUSE on its own regardless —
  this flag only ever adds REFUSE-capability, never removes it.
- `internal/permifysync` (migration `005_permify_policy_snapshot.sql`, the
  ticker goroutine, and the `Snapshot` type) is a separate package landed
  independently of this ADR's `gate2AuthZ`/config/ADR changes; `marshal.go`
  depends only on the local `PermifySnapshot` interface, not on that
  package, so the two land independently without a build-order dependency.
- New tests (`internal/marshal/gate2_test.go`) cover: rbacMap pass +
  Permify unknown → PASS (today's exact behavior, unaffected); rbacMap
  pass + Permify known-deny + flag off → WARN only (still EXECUTE);
  rbacMap pass + Permify known-deny + flag on → FAIL/REFUSE; rbacMap fail
  (regardless of Permify or the flag) → FAIL/REFUSE always; a role/action
  absent from `rbacMap` with no Permify opinion either still fails closed.
- Extending Permify's schema to cover all 11 platforms' full action
  vocabularies and flipping `enforce_permify_authz` to `true` after
  burn-in are explicitly deferred, not built speculatively — tracked as
  Phase 3 follow-up.
