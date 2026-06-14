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
           (session)      (RBAC)         (SoD)        (heuristics)   (audit)
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

**Question:** does `actor.user_id` have a valid session, and does the
claimed `role` match what the session recorded?

**Implementation:** `Store.SessionExists(ctx, userID) → (role, roleGroup, exists, err)`.

**Fail cases:**

| Condition | Reason string |
|---|---|
| Session lookup errors | `AUTH_ERROR: session lookup failed for user_id=N` |
| No session exists | `AUTH_FAIL: no valid session for user_id=N` |
| Claimed role ≠ session role | `AUTH_FAIL: claimed role "X" does not match session role "Y"` |

**Outcome on fail:** `REFUSE`.

## Gate 2 — AuthZ (Authorisation)

**Question:** is `actor.role` permitted to perform `action.type`?

**Implementation:** in-code RBAC map in `roleAllowed(role, actionType)`.
Typical mapping: `admin` can do anything; `operator` can `CONTAIN`,
`PATCH`, `CREATE_INCIDENT`; `verifier` can `VERIFY`; etc.

**Fail case:** the role/action pair is absent from the map.

**Outcome on fail:** `REFUSE` with
`AUTHZ_FAIL: role "X" is not permitted to perform "Y"`.

## Gate 3 — NDS (Separation of Duties)

**Question:** is the action backed by two distinct identities, and are
they from different role groups?

**Implementation:**

1. `sod.operator_user_id ≠ sod.verifier_user_id` — same identity is
   `HARD_STOP`, not merely `REFUSE`.
2. Both user IDs resolve to valid sessions.
3. Their role groups differ.

**Fail cases:**

| Condition | Status | Reason |
|---|---|---|
| Operator ID == verifier ID | `HARD_STOP` | `NDS_SAME_IDENTITY: operator and verifier are the same user` |
| Either user lacks a session | `FAIL` | `NDS_FAIL: operator/verifier has no valid session` |
| Same role group (not "unknown") | `HARD_STOP` | `NDS_SAME_GROUP: operator and verifier are both in role group "X"` |

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
