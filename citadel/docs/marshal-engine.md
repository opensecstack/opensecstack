# MARSHAL Decision Engine

> **Legacy name:** MARSHAL was called **ARBITER** in early CITADEL
> designs. The renaming happened before v1.0.0; code, logs, and
> metrics use `MARSHAL` exclusively. If you find "ARBITER" in an old
> ADR, conference deck, or external reference, it means this engine.

MARSHAL is CITADEL's 5-gate cryptographic authorisation engine. Every
privileged action from every platform in the ecosystem passes through
it before execution. The outcome — `EXECUTE`, `REFUSE`, or `HARD_STOP`
— plus the gate-by-gate reasoning is unconditionally appended to the
WORM chain at Gate 5, regardless of whether prior gates passed.

For the payload shape, see [kerkese-spec.md](./kerkese-spec.md). For
the AUGUR heuristics in detail, see [augur.md](./augur.md). For the
WORM append semantics, see [worm-log.md](./worm-log.md).

## The five gates in order

```
Kerkese → Gate 1 AuthN → Gate 2 AuthZ → Gate 3 NDS → Gate 4 AUGUR → Gate 5 WORM
           (sinauth JWT)  (RBAC)         (SoD)        (heuristics)   (audit)
                                                                        ↓
                                                                   Always runs
```

Gates 1-4 can short-circuit the outcome but the execution continues
through to Gate 5. Gate 5 **always runs** — even on a REFUSE or
HARD_STOP — because the audit chain must record that the rejection
happened. An unrecorded rejection is worse than an unrecorded
execution: it leaves no trace of attempted abuse.

The engine code is in [internal/marshal/marshal.go](../internal/marshal/marshal.go#L43).

## Gate 1 — AuthN (Authentication)

**Question:** does `ActorToken` verify as a live sinauth bearer JWT
whose `sub` matches `actor.user_id`? Also verifies `SigOperator`
against the operator's registered Ed25519 key — see
[ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md).

**Implementation:** the token check is `TokenVerifier.Verify(ctx, token) → (userID, role, err)`,
implemented by `internal/auth.SinauthVerifier`, which wraps
`sdk/go/sinauth.Client.VerifyToken` — a real cryptographic check
against sinauth's JWKS, not a local session lookup. See
[ADR-005](../adrs/005-sinauth-identity-bridge.md); CITADEL has no local
sessions table. The two checks are gated independently
(`EnforceIdentity` for the token, `EnforceSignatures` for the
signature) — see
[ADR-006](../adrs/006-split-enforce-identity-and-signatures.md).

**Fail cases:**

| Condition | Reason string |
|---|---|
| Token verification errors | `AUTH_FAIL: actor_token invalid or expired: ...` |
| Missing token | `AUTH_FAIL: no actor_token provided for user_id=N` |
| Token subject ≠ claimed `actor.user_id` | `AUTH_FAIL: actor_token subject "X" does not match actor.user_id "Y"` |

**Outcome on fail:** `WARN` when the corresponding flag
(`EnforceIdentity` for the token check, `EnforceSignatures` for the
signature check) is at its default `false`; `REFUSE` once the flag is
enabled. Both default to `false` in v1.0.0 — see
[ADR-006](../adrs/006-split-enforce-identity-and-signatures.md) for why
neither is on by default yet.

## Gate 2 — AuthZ (Authorisation)

**Question:** is `actor.role` permitted to perform `action.type`?

**Implementation:** two checks composed via `combineChecks` (the same
helper Gate 1/Gate 3 use for their soft-gated sub-checks):

1. **`rbacMap` check** (`roleAllowed(role, actionType)`) — in-code RBAC
   map. Typical mapping: `admin` can do anything; `operator` can
   `CONTAIN`, `PATCH`, `CREATE_INCIDENT`; `verifier` can `VERIFY`; etc.
   `enforce: true` always, unconditionally — this is the permanent
   safety net Gate 2 has always provided and it is never weakened by
   check 2 below.
2. **Permify-snapshot check** (`permifyCheck`) — a new, optional
   soft-launch check against a periodically-refreshed local snapshot of
   Permify-derived role→action policy (`internal/permifysync.Snapshot`,
   read via a `PermifySnapshot.Allowed(role, actionType) (allowed,
   known bool)` interface method). No live per-request call to
   Permify — Gate 2 is in the hot path of every governed action.
   `enforce: cfg.EnforcePermifyAuthz` (config
   `citadel.enforce_permify_authz`, default `false`). `known == false`
   (Permify has synced no opinion for this role/action yet) is always
   treated as a **PASS**; only `known=true, allowed=false` is a fail
   candidate, and it only `REFUSE`s once the flag is on — until then it
   only `WARN`s. A `nil` snapshot (unwired, or `PermifyURL` unset)
   makes this check a no-op PASS for every role/action, identical to
   pre-ADR-007 behavior. See
   [ADR-007](../adrs/007-permify-gate2-snapshot.md).

**Fail cases:**

| Condition | Status | Reason |
|---|---|---|
| Role/action pair absent from `rbacMap` | `REFUSE` (always) | `AUTHZ_FAIL: role "X" is not permitted to perform "Y"` |
| Permify snapshot has `known=true, allowed=false` for this role/action | `WARN` (soft, default) / `REFUSE` (once `EnforcePermifyAuthz` is enabled) | combined per-check reason from `combineChecks` |

**Outcome on fail:** `rbacMap` failing always produces `REFUSE`,
regardless of the Permify flag. A Permify-known deny can only add a
`WARN` while `EnforcePermifyAuthz` is off; once the flag is on, it can
independently produce `REFUSE` even for a role/action pair `rbacMap`
would otherwise have passed.

## Gate 3 — NDS (Separation of Duties)

**Question:** is the action backed by two distinct identities, and are
they from different role groups?

**Implementation:**

1. `sod.operator_user_id ≠ sod.verifier_user_id` — same identity is
   `HARD_STOP`, not merely `REFUSE`.
2. Their role groups differ. Role groups are derived from the
   producer-asserted `Actor.Role`/`Verifier.Role` (unchanged from
   before ADR-005) — sinauth's role claim is scoped per sinauth
   client, not to CITADEL's 5-role taxonomy, so it cannot substitute
   here.
3. Both `ActorToken` and `VerifierToken` verify as live sinauth
   tokens whose subjects match `sod.operator_user_id`/`verifier_user_id`
   (`TokenVerifier.Verify`, same mechanism as Gate 1 — no local
   session table involved), and `SigVerifier` verifies against the
   Verifier's registered Ed25519 key.

Checks 1 and 2 are unconditional structural invariants (logic bugs if
violated, not a rollout concern) and run before check 3, which is
soft-gated the same way as Gate 1: token checks by `EnforceIdentity`,
the signature check by `EnforceSignatures` — see
[ADR-006](../adrs/006-split-enforce-identity-and-signatures.md).

**Fail cases:**

| Condition | Status | Reason |
|---|---|---|
| Operator ID == verifier ID | `HARD_STOP` | `NDS_SAME_IDENTITY: operator and verifier are the same user` |
| Same role group (not "unknown") | `HARD_STOP` | `NDS_SAME_GROUP: operator and verifier are both in role group "X"` |
| Either token/signature missing/invalid | `WARN` (soft, default) / `REFUSE` (once `EnforceIdentity`/`EnforceSignatures` is enabled) | combined per-check reason from `combineChecks` |

**Why HARD_STOP on SoD violation:** same-identity dual control is a
deliberate attempt to defeat the separation control. Downgrading it to
REFUSE allows a brute-force retry loop. HARD_STOP escalates to
IRFlow's P1 incident auto-creation and a project freeze.

## Gate 4 — AUGUR (Behavioural heuristics)

Three rules evaluated in sequence; rule_03 can override the others.

| Rule | Trigger | Status |
|---|---|---|
| rule_01 | Action initiated outside 07:00–19:00 UTC | `WARN` |
| rule_02 | Same actor performed > 10 actions in 5 min | `WARN` (added to existing reason) |
| rule_03 | `action.type == "DATA_EXPORT"` AND `action.incident_id` empty | `HARD_STOP` |

rule_03 overrides anything set by rules 01/02 because data exfiltration
without an incident context is the highest-risk pattern MARSHAL tracks.

A `WARN` status does not block execution — Gate 4's contribution to
the decision is additive. The outcome becomes REFUSE only if an
earlier gate said so; HARD_STOP on rule_03 takes precedence.

Full rule discussion in [augur.md](./augur.md).

## Gate 5 — WORM (Audit)

**Question:** can we commit this decision to the append-only chain?

**Implementation:** `Store.AppendWORM(ctx, source, eventType, projectID, payload)`
where `payload` is the full JSON of the decision — including the
Kerkese, the outcome, all five gate results, and reason strings.

A Gate 5 failure is logged as a `WARN` result on the gate itself but
does **not** reverse the outcome of gates 1-4. The rationale: if the
chain is unwritable, the decision still stands — we just lost the
audit trail for this specific one, which Ops must fix urgently
(alerts fire, metric `citadel_worm_append_failures_total` increments).

`project_id` defaults to `"citadel"` when the Kerkese doesn't carry
one — the chain can then be partitioned per project for auditor queries.

## Outcome resolution

Final outcome is the **maximum severity** observed across gates 1-4:

```
EXECUTE    < REFUSE    < HARD_STOP
```

If any gate escalated to HARD_STOP, the outcome is HARD_STOP — even if
a later gate would have returned REFUSE or EXECUTE. Reasons from every
failing gate are concatenated into `decision.reasons[]` for debugging.

## Performance

v1.0.0 baseline on Intel Core i7-7600U, Go 1.24.4:

| Step | Latency |
|---|---|
| Gate 1 AuthN (in-memory mock) | ~0.8 µs |
| Gate 2 AuthZ | ~0.3 µs |
| Gate 3 NDS | ~1.2 µs |
| Gate 4 AUGUR | ~1.5 µs |
| Gate 5 WORM (synchronous PostgreSQL 16) | 4.22 ms |
| **Total evaluate** (mocked store) | **7.55 µs** |
| **Total evaluate** (real DB) | **~5 ms — dominated by Gate 5** |

The WORM append dominates every real-world call. If higher throughput
is needed, Gate 5 becomes the obvious place to optimise — candidates:
batched appends (v1.1), sharded chains per `project_id` (v2.0).

## Dry-run mode

Setting `decision.dry_run = true` on the inbound Kerkese instructs
MARSHAL to produce a full decision **without** calling `AppendWORM`.
Useful for:

- Caller-side integration tests.
- Policy validation before rollout.
- Reproducing an audit finding locally.

Dry-run decisions are **not** WORM-logged, so they leave no trace.
Callers must not use dry-run mode in production paths.

## Related

- [Kerkese schema](./kerkese-spec.md)
- [AUGUR heuristics](./augur.md)
- [SoD (NDS) protocol](./sod.md)
- [WORM chain](./worm-log.md)
- [Architecture](./architecture.md) — MARSHAL in the context of the full engine
