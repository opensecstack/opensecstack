# WORM Log Specification

The CITADEL WORM Log (`citadel.log`) is the append-only immutable evidence ledger. Every governance action is recorded permanently. No UPDATE. No DELETE.

## Model Definition

**Table:** `citadel.log`
**Enforcement:** INSERT-only via PostgreSQL database trigger

| Field | Type | Description |
|-------|------|-------------|
| `log_id` | UUID | Primary key, auto-generated |
| `ts_utc` | timestamp | Authoritative timestamp (NTP-synced) |
| `actor_user_id` | integer | User who performed the action |
| `actor_role` | string | Role at time of action |
| `system_module` | string | Odoo module that triggered the log entry |
| `action` | string | What was done (create, write, unlink, execute, etc.) |
| `result_status` | enum | `EXECUTED` \| `REFUSED` \| `HARD_STOP` |
| `risk_class` | enum | `INFO` \| `WARNING` \| `CRITICAL` |
| `object_fingerprint` | string (SHA-256) | SHA-256 hash of the object state at time of action |
| `chain_anchor_id` | integer (FK) | Link to current chain anchor |
| `odoo_model` | string | Odoo model name (e.g. `hr.contract`) |
| `record_id` | integer | Odoo record ID |
| `transaction_id` | string | Unique transaction identifier |
| `evidence_ids` | array | Links to citadel.evidence records |

## INSERT-Only Enforcement

```sql
-- PostgreSQL trigger: block UPDATE and DELETE on citadel.log
CREATE OR REPLACE FUNCTION citadel_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'citadel.log is immutable: % operations are not permitted', TG_OP;
  RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_citadel_log_immutability
  BEFORE UPDATE OR DELETE ON citadel_log
  FOR EACH ROW
  EXECUTE FUNCTION citadel_log_immutable();
```

## Object Fingerprint Algorithm

Every logged object gets a SHA-256 fingerprint:

1. Serialise the object to canonical JSON (sorted keys, no whitespace)
2. Compute `SHA-256(canonical_json_bytes)`
3. Store as hex string in `object_fingerprint`

This allows any future auditor to verify that the object has not been modified since it was logged.

## Risk Classification

| Risk Class | When Applied | Example |
|-----------|-------------|---------|
| `INFO` | Normal successful operation | Scan completed, report generated |
| `WARNING` | Action succeeded but with concerns | BEACON flagged NEEDS_REVIEW, risk accepted |
| `CRITICAL` | Hard stop, SoD violation, scope breach | MARSHAL returned HARD_STOP, incident created |

## Retention

WORM log entries are never deleted. They are the permanent audit trail. Archival to cold storage is permitted after the retention period (configurable, minimum 7 years for compliance).
