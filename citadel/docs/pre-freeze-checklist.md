# Pre-Freeze Checklist

A **project freeze** is CITADEL's most disruptive operational
intervention: it tells MARSHAL to refuse every non-emergency action
for a given `project_id` until explicitly unfrozen. Freezing production
stops business — callers receive HARD_STOP on every mutating Kerkese.

Do not freeze without walking through this checklist. An impulsive
freeze causes collateral damage that later has to be explained to
the board.

For the HARD_STOP handling that might tempt you to freeze, see
[hard-stop-playbook.md](./hard-stop-playbook.md). For the incident
SOP, see [sop-012-incident.md](./sop-012-incident.md).

## When to freeze

Freeze is justified when **all three** are true:

1. **Active threat** — confirmed malicious activity, not just a
   suspicious log line. Minimum: one HARD_STOP with corroborating
   session anomalies, IOC hits, or an insider-tip escalation.
2. **Blast radius scoped to a project** — the threat is localised to
   a specific `project_id`; freezing that project contains damage
   without disrupting others.
3. **Accepting the disruption is cheaper than the alternative** —
   typically means: the threat is currently exfiltrating, modifying,
   or disrupting, and waiting for clean remediation costs more than
   the business cost of frozen operations.

If any of these is false, prefer narrower interventions first:

- **Revoke the specific user session** — stops one actor.
- **Rotate a specific credential** — stops one credential.
- **Increase alerting sensitivity on the project** — catches next
  move without disrupting.
- **Route calls through manual verification** (v1.2 feature) — slows
  the attacker without halting.

## The checklist

Walk it **in order**. Do not skip steps, even if you're in a hurry
— the whole point of the checklist is to prevent panic-driven damage.

### 1. Confirm the trigger

- [ ] What is the specific event that triggered the consideration of
      freeze? Cite the WORM entry IDs.
- [ ] Has the event been **corroborated** by a second signal (IOC
      match, user report, metric anomaly)?
- [ ] Has at least one other responder reviewed the evidence?

Single-signal HARD_STOPs are rarely freeze-worthy. Collusive attacks
are the exception — flag these, but still corroborate.

### 2. Identify the scope

- [ ] What is the affected `project_id`?
- [ ] Are there other active projects on the same CITADEL — how many
      users, how much business flow? (Query: `SELECT project_id, count(*) FROM worm_entries WHERE ts_utc > now() - interval '1 day' GROUP BY 1`.)
- [ ] Is the attack confined to the named project_id, or is there
      evidence of lateral movement? If the latter, a project-scoped
      freeze isn't enough and you need broader isolation.

### 3. Assess what the freeze actually blocks

Freeze blocks Kerkeses with `project_id == <frozen>` and
`action.type != <emergency list>`. Emergency list (default):

- `CREATE_INCIDENT`
- `CONTAIN`
- `ISOLATE`
- `REVOKE_SESSION`
- `ROTATE_CREDENTIAL`

Everything else — including `GET_*`, `LIST_*`, etc. — is MARSHAL-gated
so also refused. The freeze is deliberately broad because an attacker
who has compromised the gate-3 counterparty can bypass narrower
controls.

- [ ] Confirm the responders who need to act *during* the freeze have
      roles that permit the emergency action list.
- [ ] Confirm the freeze does not block your own incident-response
      tooling. If IRFlow itself uses non-emergency actions to drive
      its response workflow, you may need to temporarily grant its
      service token an emergency-tier role.

### 4. Authorisation

Freeze is itself a governance-sensitive operation. It requires:

- [ ] Approval from a second distinct identity (SoD on the freeze
      itself).
- [ ] Both identities in the incident response role group.
- [ ] WORM entry recording the freeze: who, why, project_id, expected
      duration.

v1.0.0 implementation: the freeze flag is set via a signed admin API
call; a future v1.2 feature routes it through IRFlow's project-freeze
playbook with formal SoD.

### 5. Communication

Before flipping the switch:

- [ ] Post on the status page / customer comms channel — "Project X
      operations are temporarily halted as part of a security
      investigation. ETA: unknown."
- [ ] Notify the project owner directly if they aren't already on the
      incident.
- [ ] Update the incident record in IRFlow with the expected freeze
      window.

Silence during a freeze is what turns an incident into a crisis.

### 6. Set a deadline

- [ ] Declare the freeze duration up-front. 4 hours is the default
      initial window.
- [ ] Schedule a status review at the halfway point — 2 hours in — to
      decide extend or release.
- [ ] If extending, run this checklist again (steps 1-5 at least).

Indefinite freezes become wallpaper and stop serving their purpose.

### 7. Validate post-freeze intent

Before the flip, ask: **what do we do during these 4 hours?**

- [ ] Named investigators?
- [ ] Planned remediation steps?
- [ ] Measurable criterion for unfreezing?

"We'll figure it out" is not an answer. If you can't state the
post-freeze plan, the freeze isn't ready.

## Executing the freeze

Once the checklist is complete:

```bash
# Authorised SoD-signed admin call (shape is illustrative for v1.0.0):
curl -X POST https://citadel.internal/api/v1/admin/freeze \
  -H "X-Operator-Id: 42" \
  -H "X-Verifier-Id: 77" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
        "project_id":       "prod",
        "reason":           "Insider-threat investigation INC-2026-0045",
        "expires_at":       "2026-04-19T18:00:00Z",
        "emergency_actions": ["CREATE_INCIDENT","CONTAIN","ISOLATE","REVOKE_SESSION","ROTATE_CREDENTIAL"]
      }'
```

Verify the freeze is active:

```bash
curl -sf https://citadel.internal/api/v1/admin/freeze | jq .
# Should show the frozen project_id and its expiry
```

## Unfreeze

Unfreezing requires the same SoD approval as freezing:

```bash
curl -X DELETE https://citadel.internal/api/v1/admin/freeze/prod \
  -H "X-Operator-Id: 42" \
  -H "X-Verifier-Id: 77" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "reason": "Remediation complete — session revoked, credentials rotated, monitoring in place" }'
```

The unfreeze is also WORM-logged. A subsequent audit can then trace:
freeze → investigation → remediation → unfreeze, all in a single chain.

## Post-freeze

Within 5 business days:

- [ ] Post-mortem document (freeze scope, timeline, root cause,
      remediation, lessons).
- [ ] Update this checklist if any step turned out wrong or missing.
- [ ] Review the checklist with the wider team — rehearsed familiarity
      is the whole point.

## Anti-patterns

- **Don't freeze without running the checklist.** Even if the trigger
  is crystal clear. The checklist's value is as much in the social
  handshake (getting a second pair of eyes, communicating the
  decision) as in the technical steps.
- **Don't freeze without a deadline.** "We'll unfreeze when we're
  done" is how multi-day freezes happen.
- **Don't use freeze as policy.** If a class of operations keeps
  triggering freezes, the underlying policy is wrong. Fix the
  policy, don't normalise the freeze.

## Related

- [HARD_STOP playbook](./hard-stop-playbook.md) — what usually triggers freeze consideration
- [SOP-012 CITADEL incident runbook](./sop-012-incident.md)
- [Operator runbook](./operator-runbook.md) — day-to-day operations (that freeze disrupts)
