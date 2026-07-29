# SoD — Separation of Duties (NDS Protocol)

**NDS** ("Ndarja e Detyrimeve të Sigurisë" — Albanian for Separation
of Security Duties) is MARSHAL's Gate 3. It ensures that no single
operator can unilaterally authorise a governance-relevant action:
every such action requires an **initiating** identity (the operator)
and a **verifying** identity (the verifier) that are cryptographically
distinct at both the user and role-group levels.

For Gate 3 in the wider MARSHAL flow, see [marshal-engine.md § Gate 3](./marshal-engine.md#gate-3--nds-separation-of-duties).
For the Go implementation, see [internal/marshal/marshal.go:166](../internal/marshal/marshal.go#L166).

## The two-key principle

Classic security control, military provenance: "no single person can
launch the missile." Translated to software governance:

1. An **operator** proposes an action (fills out a Kerkese).
2. A **verifier** approves it.
3. MARSHAL evaluates — the verifier is not a rubber-stamp; they
   authenticate with their own sinauth bearer token and carry their
   own role, and MARSHAL checks both against independent criteria.

If the operator and verifier are the **same person** — either
literally (same `user_id`) or effectively (same role group, so they
could trivially co-operate in bad faith) — MARSHAL HARD_STOPs the
action.

## Gate 3 checks in order

```go
// 1. Same-identity check — HARD_STOP
if sod.OperatorUserID == sod.VerifierUserID {
    return HARD_STOP("NDS_SAME_IDENTITY")
}

// 2. Role-group check — HARD_STOP. Role groups are derived from the
// producer-asserted Actor.Role/Verifier.Role, not looked up from any
// local table.
opGroup := roleGroup(actorRole)
vfGroup := roleGroup(verifierRole)
if opGroup == vfGroup && opGroup != "unknown" {
    return HARD_STOP("NDS_SAME_GROUP")
}

// 3. Both parties authenticate with a live sinauth token, and the
// verifier's Ed25519 signature is checked — soft-gated independently
// by EnforceIdentity / EnforceSignatures (see ADR-006), not a session
// lookup.
opTokenStatus, _ := verifyToken(ctx, actorToken, operatorUserID)
vfTokenStatus, _ := verifyToken(ctx, verifierToken, verifierUserID)
sigStatus, _ := verifyVerifierSignature(ctx, kerkese)
```

### Same-identity → HARD_STOP (not REFUSE)

Rationale: passing the operator's user_id as both operator and
verifier is a deliberate attempt to defeat SoD. Downgrading it to
REFUSE invites a retry loop where the caller keeps submitting variations
until one slips through. HARD_STOP escalates immediately and creates
an incident record in IRFlow.

### Role groups

A **role group** is a coarser classification than a role. CITADEL
maintains the grouping out of band — example layout for a typical
deployment:

| Role group | Roles it contains |
|---|---|
| `operations` | `ops-oncall`, `ops-shift-lead`, `ops-junior` |
| `security` | `security-engineer`, `soc-analyst`, `sec-lead` |
| `audit` | `auditor`, `compliance-reviewer` |
| `admin` | `admin`, `superadmin` |

Two operators both in `operations` cannot form a valid pair — the
assumption is that they would collude. A pair must span two groups:
`operations` ↔ `security`, or `admin` ↔ any.

The `"unknown"` group is a sentinel for a role that doesn't map to any
configured group; Gate 3 deliberately does not force a failure on
unknown groups because that would break during a migration. Set role
groups explicitly in production.

## What the caller sends

```json
"sod": {
  "operator_user_id": 42,
  "verifier_user_id": 77
}
```

Both IDs are required for SoD-sensitive action types. For read-only
or single-principal actions, Gate 3 short-circuits PASS when both
IDs are zero — but the caller should be explicit about which action
types do and don't require SoD. The role → action RBAC matrix (Gate 2)
is where this intent is encoded.

## Scope — which actions are SoD-gated?

By convention, these action types always require SoD:

| Action type | Why |
|---|---|
| `CONTAIN` | Disruptive to production; mistakes cost availability |
| `DELETE_RESOURCE` | Destructive; cannot be undone |
| `DATA_EXPORT` | Exfiltration risk — also hit by AUGUR rule_03 |
| `CREDENTIAL_ROTATE` | Breaks sessions; should be peer-reviewed |
| `POLICY_OVERRIDE` | Affects the rule that just rejected something |

Read-only actions (`GET_INCIDENT`, `LIST_IOCS`) should not carry SoD.
The Gate 2 RBAC matrix is where the caller expresses "this action
needs SoD"; Gate 3 then enforces it.

## The caller's responsibility

SoD only works if the **initiating identity and the verifying identity
are cryptographically distinct**. IRFlow is where this is operationally
enforced:

1. Operator logs in, gets JWT with `sub=alice`.
2. Operator drafts an action, POSTs it.
3. IRFlow checks `actor_id (from JWT) ≠ verifier_id (from request)` at
   the service layer — before even calling CITADEL.
4. Verifier must have *separately* authenticated and provided their
   ID; a genuinely distinct identity check is impossible to spoof from
   within a single session.

CITADEL's Gate 3 is the second line of defence: even if IRFlow were
bypassed, MARSHAL still checks the identities.

## Attack surface

### Collusion between role groups

Gate 3 can't detect two distinct users in different role groups
deliberately cooperating in bad faith. Example: a security engineer
and an operations lead both want to exfiltrate data and agree to
cover for each other.

Mitigation: **AUGUR rule_03** — `DATA_EXPORT` without an incident_id
is `HARD_STOP` regardless of SoD. So the attack has to also fabricate
an incident. This raises the visibility of the act — a made-up
incident sits in the incident list, queryable by anyone.

Future work (v1.2+): third-party approval for extremely sensitive
actions. E.g. `POLICY_OVERRIDE` might require three distinct
signatures, not two.

### Session hijack

An attacker with a valid JWT for both operator and verifier passes
SoD trivially. Defence: short token TTL (8 h default), MFA on token
issuance, audit log review.

### Role-group misconfiguration

If role groups are not configured, Gate 3 falls back to the
same-identity check only — collusion between two users with the same
role but different IDs becomes possible. This is why empty role
groups log a WARN on CITADEL startup.

## Auditing SoD decisions

Every Gate 3 decision is in the WORM chain. Query:

```sql
SELECT ts_utc, payload
FROM worm_entries
WHERE event_type = 'marshal.decision'
  AND payload::jsonb -> 'gates' @> '[{"gate":3,"status":"HARD_STOP"}]';
```

Any result is a potential insider threat event. Investigate every
one — the false-positive rate is approximately zero.

## Related

- [MARSHAL engine](./marshal-engine.md) — full Gate 3 in context
- [Kerkese schema](./kerkese-spec.md) — the `sod` field layout
- [../../irflow/docs/rbac-guide.md](../../irflow/docs/rbac-guide.md) — how IRFlow pre-enforces SoD
- [Known limitations](./known-limitations.md) — what SoD deliberately does *not* catch
