# Separation of Duties (SoD) Enforcement

CITADEL enforces separation of duties as an absolute rule. SoD violations trigger an immediate HARD STOP — no exceptions, no overrides.

## Core Rule

> The person who performs an action cannot be the same person who verifies it.

| Principle | Enforcement |
|-----------|-------------|
| OWNER ≠ VERIFIER for same object | MARSHAL Gate 1 checks this. HARD STOP on violation. |
| Operator ≠ Auditor for same transaction | Role separation enforced at Odoo group level. |
| Custody owner ≠ Data steward for same evidence | citadel.evidence model enforces different user IDs. |

## Roles

| Role | Odoo Group | Can Do | Cannot Do |
|------|-----------|--------|-----------|
| **Operator** | `group_sig_operator` | Submit action requests, create records, upload evidence | Execute MARSHAL, verify own actions, access audit views |
| **Verifier** | `group_sig_verifier` | Execute MARSHAL evaluation, approve/refuse actions | Submit action requests for objects they own |
| **Auditor** | `group_sig_auditor` | View WORM log, verify chain anchors, run PATROL audits | Modify any operational data, execute MARSHAL |

## SoD in MARSHAL Output

Every MARSHAL decision includes SoD status:

```json
{
  "sod": {
    "required": true,
    "operator_user_id": 42,
    "verifier_user_id": 87,
    "status": "VALID"
  }
}
```

| Status | Meaning |
|--------|---------|
| `VALID` | operator_user_id ≠ verifier_user_id, both have correct roles |
| `VIOLATION` | Same person attempted both roles → HARD STOP |
| `NOT_REQUIRED` | Action does not require SoD (INFO-level read-only operations) |

## Evidence Custody SoD

The `citadel.evidence` model enforces:

- `custody_owner_id` — person responsible for the evidence
- `data_steward_id` — person responsible for data integrity

**Rule:** `custody_owner_id ≠ data_steward_id` — enforced at model level. Any attempt to set them equal is blocked.

## HARD STOP on SoD Violation

When SoD is violated:

1. MARSHAL returns `HARD_STOP` immediately
2. `citadel.incident` auto-created with classification `custody_breach`
3. All sensitive actions frozen for the affected scope
4. Notification cascade:
   - T+0: Primary authority notified
   - T+15m: Secondary authority notified
   - T+30m: CEO-level notification
   - T+1h: System enters DEGRADED MODE if unacknowledged

## No Exceptions

There is no override mechanism for SoD violations. The only resolution path is:

1. Acknowledge the incident
2. Assign a different verifier
3. Re-submit the action request
4. MARSHAL evaluates the new request normally
