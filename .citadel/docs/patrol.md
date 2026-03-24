# PATROL Audit Intelligence Reference

PATROL (formerly VIGIL / ARGIUS) is the audit verification intelligence within CITADEL. It performs continuous and deep audit of governance records, returning verdicts on compliance and integrity. PATROL has **no execution authority** — but `INVALID` verdicts trigger mandatory escalation.

## Role in CITADEL

| Property | Value |
|----------|-------|
| **Authority** | No direct execution authority. INVALID verdicts trigger escalation. |
| **Data access** | Mirror databases only (read-only). Never operative databases. |
| **Outputs** | Audit verdicts: VALID, VALID_WITH_WARNINGS, INVALID, INCONCLUSIVE |
| **Consumers** | Auditors (`group_sig_auditor`), incident workflow, compliance reports |

## The 4 Verdicts

| Verdict | Meaning | Consequence |
|---------|---------|-------------|
| **VALID** | All audited records are consistent, complete, and compliant. | No action. Logged. |
| **VALID_WITH_WARNINGS** | Records are compliant but anomalies detected that warrant attention. | Warnings logged. Auditor should review at next scheduled audit. |
| **INVALID** | Non-compliance, inconsistency, or integrity violation detected. | **Mandatory escalation.** `citadel.incident` auto-created. Notification cascade triggered. |
| **INCONCLUSIVE** | Audit cannot be completed — insufficient data, mirror stale, or scope too broad. | Re-scope or wait for fresh mirror data. Do not treat as VALID. |

## Audit Types

### Continuous Audit

Runs automatically on a schedule. Checks ongoing compliance:

| Check | Frequency | Description |
|-------|-----------|-------------|
| Chain integrity | Every 1 hour | Verify chain anchors are unbroken from genesis to HEAD |
| WORM log consistency | Every 1 hour | Verify no gaps in log sequence, all fingerprints valid |
| SoD compliance | Every 4 hours | Verify no SoD violations exist in recent transactions |
| Mirror freshness | Every 15 minutes | Verify mirrors are within SLA |
| Evidence custody | Every 4 hours | Verify `custody_owner_id ≠ data_steward_id` for all evidence |

### Deep Audit

Triggered manually by an auditor or automatically after an incident:

| Check | Description |
|-------|-------------|
| Full chain recomputation | Recompute every anchor hash from genesis. Compare with stored hashes. |
| Cross-ERP reconciliation | Compare mirror data against operative source for discrepancies |
| Transaction completeness | Verify every MARSHAL decision has a corresponding WORM log entry |
| Evidence integrity | Recompute SHA-256 fingerprints for all evidence records |
| Out-of-band anchor verification | Verify anchor deposits match independent storage |
| Temporal consistency | Verify timestamps are monotonically increasing, no backdated entries |

## Mirror-Only Access

Like BEACON, PATROL reads exclusively from mirror databases:

| Mirror | Source | Data |
|--------|--------|------|
| Mirror_Odoo18_TCL_001 | Odoo 18 Abissnet | HR, contracts, invoicing |
| Mirror_Odoo19_CRV_001 | Odoo 19 TRIA | Financial portfolio |

**Rule:** If mirror freshness exceeds the SLA, PATROL must return `INCONCLUSIVE` rather than audit stale data.

## PATROL Output Schema (v1.0)

```json
{
  "meta": {
    "schema_version": "1.0",
    "project_id": "ABISSNET_TCL_001",
    "audit_id": "uuid",
    "audit_type": "CONTINUOUS | DEEP",
    "ts_utc": "2026-03-24T12:00:00Z",
    "mirror_source": "Mirror_Odoo18_TCL_001",
    "mirror_freshness_utc": "2026-03-24T11:48:00Z"
  },
  "verdict": {
    "outcome": "VALID | VALID_WITH_WARNINGS | INVALID | INCONCLUSIVE",
    "scope": {
      "audit_target": "chain_integrity | worm_consistency | sod_compliance | evidence_custody | full_deep",
      "date_range": { "from": "date", "to": "date" },
      "record_count": 0
    },
    "findings": [
      {
        "finding_id": "uuid",
        "check": "string (which audit check produced this finding)",
        "severity": "INFO | WARNING | CRITICAL",
        "description": "string",
        "affected_records": [
          { "model": "string", "record_id": 0, "fingerprint": "sha256 hex" }
        ],
        "remediation": "string (suggested corrective action)"
      }
    ]
  },
  "integrity": {
    "audit_hash_sha256": "hex string — SHA-256 of canonical audit JSON",
    "chain_anchor_id": 0
  }
}
```

See [patrol_audit_output_v1.0.json](../schemas/patrol_audit_output_v1.0.json) for the full JSON Schema.

## Escalation on INVALID

When PATROL returns `INVALID`:

1. `citadel.incident` auto-created with classification based on finding type
2. All affected scope frozen (no new MARSHAL evaluations for affected records)
3. Notification cascade:
   - T+0: Primary authority and assigned auditor notified
   - T+15m: Secondary authority notified
   - T+30m: CEO-level notification if unacknowledged
   - T+1h: System enters DEGRADED MODE if unresolved
4. Deep audit automatically triggered for the affected scope

## Logging

All PATROL audits are logged to `citadel.log` with:

- `system_module`: `citadel.patrol`
- `action`: `audit_continuous` or `audit_deep`
- `result_status`: Maps to verdict (VALID → `EXECUTED`, INVALID → `HARD_STOP`, others → `REFUSED`)
- `risk_class`: Derived from highest finding severity

## Access Control

Only users in `group_sig_auditor` can:

- View PATROL audit results
- Trigger deep audits
- Verify chain anchors
- Access the WORM log viewer

Auditors **cannot** modify operational data or execute MARSHAL evaluations (SoD enforcement).
