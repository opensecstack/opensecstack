# Appeal Flow

Every MARSHAL decision is final at the moment it is made. There is
**no "undo"** on the WORM chain — a REFUSE or HARD_STOP entry stays
in place forever, as does an EXECUTE. But the *effect* of a decision
can be contested, and if the contest succeeds, CITADEL supports a
**compensating entry**: a new WORM entry that references the disputed
one and records the corrected understanding.

This is the audit-safe way to fix mistakes. It preserves the original
evidence (an attacker cannot use "appeal" to erase a successful
detection) while allowing the ecosystem to reflect a decision that
was later re-evaluated.

For the WORM's append-only semantics, see [worm-log.md § What WORM does not do](./worm-log.md#what-worm-does-not-do).
For the HARD_STOP handling that often triggers appeals, see
[hard-stop-playbook.md](./hard-stop-playbook.md).

## Who can appeal

| Role | Can appeal what |
|---|---|
| Operator (subject of the decision) | Their own REFUSE or HARD_STOP decisions |
| Verifier | Decisions they were a counterparty to |
| Admin | Any decision |
| External auditor | Any decision, via the deployer as proxy |

Appeals are themselves governance-sensitive: they require MARSHAL
evaluation, SoD, and produce their own WORM entry. An appeal cannot
be silent.

## The shape of a compensating entry

```json
{
  "event_type": "marshal.compensation",
  "project_id": "prod",

  "compensates_worm_entry_id": "wo_00001234",
  "compensation_type":         "UPHOLD | OVERTURN | MITIGATE",
  "reason":                    "Human-readable justification",
  "authorised_by": {
    "operator_user_id": 42,
    "verifier_user_id": 77
  },
  "ts_utc": "2026-04-19T10:15:00Z"
}
```

| `compensation_type` | Semantic meaning |
|---|---|
| `UPHOLD` | Appeal reviewed; the original decision stands. Chain-of-custody value: records that an independent review occurred. |
| `OVERTURN` | Appeal accepted; the original decision is treated as incorrect by downstream consumers. The original entry is not altered. |
| `MITIGATE` | Appeal partially accepted; downstream should treat the decision with an asterisk. Typical use: "the hard-stop was correct but the project-freeze was excessive". |

## Filing an appeal

```
POST /api/v1/appeals
Content-Type: application/json
Authorization: Bearer <operator or verifier JWT>

{
  "compensates_worm_entry_id": "wo_00001234",
  "compensation_type":         "OVERTURN",
  "reason":                    "Operator was a legitimate admin performing emergency incident response; the NDS_SAME_GROUP trigger reflected a policy gap we have now closed.",
  "verifier_user_id":          77
}
```

The handler:

1. Looks up the target entry — must exist, must be an
   `event_type = marshal.decision` with `outcome != EXECUTE`.
2. Constructs a compensation Kerkese and submits it to MARSHAL
   itself. SoD applies — operator ≠ verifier on the appeal.
3. On EXECUTE, appends the compensation entry to WORM and returns the
   new entry ID.

## Downstream consumer behaviour

When a consumer (IRFlow, APIGuard, etc.) queries a WORM entry that
has a compensation pointing at it:

- **UPHOLD**: no change in consumer behaviour; the appeal is audit
  metadata.
- **OVERTURN**: consumers should treat the original as void. For
  example, if IRFlow auto-created a P1 incident from the original
  HARD_STOP and the HARD_STOP is later overturned, IRFlow can mark
  the incident as `false_positive` without losing the incident record.
- **MITIGATE**: consumers apply the specific mitigation named in
  `reason` — this is operator-readable text, not machine-parseable.

Consumers locate compensations by querying:

```sql
SELECT * FROM worm_entries
 WHERE event_type = 'marshal.compensation'
   AND payload::jsonb ->> 'compensates_worm_entry_id' = 'wo_00001234';
```

A single decision can have multiple compensations (appeals can
themselves be appealed). The most recent compensation's
`compensation_type` is the current state.

## Appeals that target appeals

An UPHOLD of an UPHOLD is redundant but not invalid. An OVERTURN of
an OVERTURN effectively restores the original decision's standing.

Each compensation is its own WORM entry with its own operator +
verifier + reason. There's no limit to the depth, but practical
deployments rarely go past two levels.

## Evidence-side effect

For auditors, the important thing is that **the original entry is
never altered**. A chain verification over the original entry's range
continues to pass. The compensation lives in a later range with its
own chain_hash and (eventually) its own anchor signature.

This matters because:

1. An auditor examining the original decision sees exactly what was
   recorded at the time, not what was later decided.
2. A forensic reconstruction can separate "what the system thought
   then" from "what the humans corrected later".
3. Even if all appeals are overturned, the history of refusals is
   preserved — useful for insider-threat analysis.

## When NOT to appeal

- **Do not appeal a REFUSE that was correct.** File a policy ADR if
  the policy was wrong; don't compensate an individual entry.
- **Do not appeal to cover up an incident.** OVERTURNs are
  WORM-logged with operator identity. Auditors looking for insider
  activity find suspicious OVERTURN patterns quickly.
- **Do not appeal routine denials.** Appeals are for genuinely
  disputed decisions, not every REFUSE. A 100:1 ratio of appeals to
  REFUSEs means the appeal mechanism is being used as a retry.

## Rate limits

In v1.0.0, appeals are not rate-limited at the API layer. In v1.1
the following rule lands:

- No more than **3 appeals per actor per hour** — sustained appeal
  spam means something is wrong.
- Any actor with > 10 appeals pending resolution has their `operator`
  privilege temporarily paused until resolved.

Expected normal rate: < 1 appeal per week across a typical SOC.

## Related

- [HARD_STOP playbook](./hard-stop-playbook.md) — when appeals happen
- [WORM log](./worm-log.md) — why compensations exist instead of deletion
- [MARSHAL engine](./marshal-engine.md) — the gates the appeal itself passes through
- [Evidence custody](./evidence-custody.md) — how compensations appear in export bundles
