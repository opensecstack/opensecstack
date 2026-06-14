# HARD_STOP Playbook

A `HARD_STOP` is MARSHAL's most severe outcome: the proposed action is
refused **and** the system flags it as an active policy violation, not
a recoverable denial. Unlike REFUSE (which can be resubmitted with a
corrected Kerkese), HARD_STOP means the request itself is evidence
of either misconfiguration or malicious intent.

This playbook is for **receivers** of a HARD_STOP — IRFlow, on-call
operators, the security team. For the CITADEL side's response to a
HARD_STOP emitted from within CITADEL itself (e.g. SoD violation),
see [sop-012-incident.md](./sop-012-incident.md).

For the gate logic that produces HARD_STOPs, see
[marshal-engine.md](./marshal-engine.md), [sod.md](./sod.md), and
[augur.md](./augur.md).

## Sources of HARD_STOP

| Gate | Rule | Likely cause |
|---|---|---|
| 3 (NDS) | `NDS_SAME_IDENTITY` | Operator and verifier user_ids are identical — likely spoofing attempt |
| 3 (NDS) | `NDS_SAME_GROUP` | Operator and verifier are in the same role group — policy circumvention |
| 4 (AUGUR) | `rule_03: DATA_EXPORT without incident_id` | Exfiltration pattern — highest-priority trigger |

Every HARD_STOP is recorded in the WORM chain with the full Kerkese,
gate reasoning, and the operator's identity. An auditor can trace
the sequence trivially.

## Downstream effects

When MARSHAL returns HARD_STOP, the calling platform's expected
behaviour:

### IRFlow

```
action submission → MARSHAL Evaluate → HARD_STOP
                                          ↓
IRFlow receives:   ErrMarshalHardStop (typed error)
                                          ↓
IRFlow emits to caller:  403 { "error": "action hard-stopped", "reasons": [...] }
                                          ↓
IRFlow's CITADEL webhook handler (if configured):
                   POST /webhooks/citadel with event_type=citadel.marshal.hard_stop
                                          ↓
                   Auto-creates a P1 incident with HARD_STOP context
                                          ↓
                   Triggers the "project freeze" playbook if configured
                                          ↓
                   On-call paged
```

### Other callers (APIGuard, ThreatFlow, custom)

Platforms that submit Kerkeses to CITADEL without IRFlow integration
must implement their own HARD_STOP handling:

- **Surface the denial** to the end user with the gate reasons.
- **Do not retry** — unlike REFUSE, retry is never the correct
  response to HARD_STOP.
- **Log to Prometheus** — the platform's own `marshal_hard_stops_total`
  metric should exist so alert rules fire independently of CITADEL.
- **Notify security.** At minimum, alert via the same channel as P1
  incidents.

## Responder runbook

### Step 1 — Acknowledge

When the pager fires, ack within 5 minutes. The P1 incident in IRFlow
has:

- The Kerkese payload (who, what, when).
- The gate that tripped.
- The reason string.
- Links to the WORM entry.

### Step 2 — Classify

From the reason string, classify the event:

| Pattern | Likely nature |
|---|---|
| `NDS_SAME_IDENTITY` | Misconfigured client auto-filling both IDs, OR spoofing. Check the client's auth context. |
| `NDS_SAME_GROUP` | Role-group configuration error, OR colluding operators. Check `sessions.role_group` for both user_ids — if wrong, policy was mis-deployed; if right, it's a real SoD breach. |
| `AUGUR_rule_03` | `DATA_EXPORT` without incident_id. Almost always exfiltration attempt. |

### Step 3 — Contain

Depending on the classification:

- **Misconfiguration**: no containment needed, but policy must be
  fixed. Update the client's SoD wiring or the role groups and
  deploy.
- **Real SoD breach / exfiltration attempt**: revoke the operator's
  session immediately (`DELETE FROM sessions WHERE user_id = ?`);
  rotate their credentials; start an investigation incident.

### Step 4 — Preserve evidence

The WORM entry is already preserved. For the investigation:

```sql
-- The HARD_STOP entry
SELECT * FROM worm_entries
 WHERE event_type = 'marshal.decision'
   AND payload::jsonb -> 'outcome' = '"HARD_STOP"'
 ORDER BY sequence_num DESC LIMIT 20;

-- The operator's recent action history
SELECT ts_utc, source, event_type, payload::jsonb -> 'kerkese' -> 'action' ->> 'type' AS action_type
 FROM worm_entries
 WHERE payload::jsonb -> 'kerkese' -> 'actor' ->> 'user_id' = ?
   AND ts_utc > now() - interval '7 days'
 ORDER BY ts_utc DESC;
```

Export the above to the investigation workspace; keep the original
WORM entries untouched.

### Step 5 — Decide: freeze or not?

**Project freeze** is a drastic measure — it tells MARSHAL to refuse
*every* non-emergency action for a given `project_id` until explicitly
unfrozen. Use when:

- Multiple HARD_STOPs in a short window.
- Confirmed insider threat.
- Evidence of credential compromise that may not be localised to one
  user.

Freeze is implemented via a flag in CITADEL's config (or, in v1.2, via
IRFlow's project-freeze playbook). The pre-freeze checklist in
[pre-freeze-checklist.md](./pre-freeze-checklist.md) is a hard
requirement — never freeze without running it.

### Step 6 — Post-mortem

Every HARD_STOP merits a post-mortem, even when the root cause is
misconfiguration. The document should answer:

- Why did MARSHAL refuse this action?
- Was the refusal correct given the policy?
- If correct: what did the attacker try to do?
- If incorrect: what was wrong with the policy or the client wiring?
- What changes close the gap?

Post-mortems for HARD_STOPs go into the `HARD_STOP` label in GitHub
(or your equivalent tracker). Read the last quarter's worth when
onboarding a new CITADEL operator.

## Anti-patterns

- **Do not auto-retry a HARD_STOP.** This sometimes looks tempting
  — "maybe it was a blip". It's not. HARD_STOP is by design
  non-transient; retrying just produces more WORM entries that each
  say "this call was policy-violating".
- **Do not bypass via admin.** Admin roles *can* submit Kerkeses
  that technically pass Gate 2, but HARD_STOPs from Gate 3 or Gate 4
  still HARD_STOP. If you think "an admin should be able to fix
  this", you probably want **policy amendment**, not a bypass.
- **Do not silence the alert.** HARD_STOP alerts must fire every
  time. Repeated legitimate false positives should prompt a policy
  fix, not an alert-rule change.

## Tuning — when HARD_STOPs are too noisy

If a specific rule is producing a steady stream of HARD_STOPs and
the ops team is confident they are false positives:

- Propose a policy change with a corresponding ADR in [../adrs/](../adrs/).
- Rule changes land in CITADEL via a new migration + a new version;
  they are never silent config toggles.

The alternative — suppressing HARD_STOPs in the alerting layer — is
what auditors will flag first, because it undermines the entire
point of HARD_STOP.

## Related

- [MARSHAL engine](./marshal-engine.md)
- [SoD (NDS) protocol](./sod.md)
- [AUGUR heuristics](./augur.md)
- [SOP-012 CITADEL incident runbook](./sop-012-incident.md)
- [Pre-freeze checklist](./pre-freeze-checklist.md)
