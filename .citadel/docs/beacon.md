# BEACON Advisory Intelligence Reference

BEACON (formerly AUGUR / NORA) is the analytical advisory intelligence within CITADEL. It returns normative advisory signals — never binding decisions. BEACON has **no execution authority**. Its signals must be cited in governance records but cannot authorise or block actions.

## Role in CITADEL

| Property | Value |
|----------|-------|
| **Authority** | None. Advisory only. |
| **Data access** | Mirror databases only (read-only). Never operative databases. |
| **Outputs** | Normative signals: COMPLIANT, NEEDS_REVIEW, NON_COMPLIANT, INSUFFICIENT_DATA |
| **Consumers** | Human decision-makers, WORM log (cited), MARSHAL (informational only — MARSHAL does not depend on BEACON) |

## The 4 Signals

| Signal | Meaning | Action Required |
|--------|---------|-----------------|
| **COMPLIANT** | Evidence reviewed. No issues found. Meets all applicable requirements. | None. Cite in record. |
| **NEEDS_REVIEW** | Evidence is present but raises questions. Human judgement required. | Human must review and document decision. Cite in WORM log. |
| **NON_COMPLIANT** | Evidence contradicts one or more requirements. | Human must address before proceeding. Cite reason in WORM log. |
| **INSUFFICIENT_DATA** | Not enough evidence to form an advisory opinion. | Gather additional evidence. Do not proceed without resolution. |

## What BEACON Is NOT

- BEACON does **not** make binding decisions — only MARSHAL does
- BEACON does **not** block actions — it only advises
- BEACON does **not** read operative databases — only mirrors
- BEACON does **not** replace human judgement — it informs it
- BEACON signals are **not** optional — they must be cited in governance records even if the human disagrees

## Mirror-Only Access

BEACON reads exclusively from mirror databases, never from operative instances:

| Mirror | Source | Data |
|--------|--------|------|
| Mirror_Odoo18_TCL_001 | Odoo 18 Abissnet | HR, contracts, invoicing |
| Mirror_Odoo19_CRV_001 | Odoo 19 TRIA | Financial portfolio |

**Rule:** If mirror freshness exceeds the SLA (< 15 min for CRITICAL), BEACON must return `INSUFFICIENT_DATA` rather than advise on stale data.

## BEACON Output Schema (v1.0)

```json
{
  "meta": {
    "schema_version": "1.0",
    "project_id": "ABISSNET_TCL_001",
    "advisory_id": "uuid",
    "ts_utc": "2026-03-24T12:00:00Z",
    "mirror_source": "Mirror_Odoo18_TCL_001",
    "mirror_freshness_utc": "2026-03-24T11:48:00Z"
  },
  "signal": {
    "outcome": "COMPLIANT | NEEDS_REVIEW | NON_COMPLIANT | INSUFFICIENT_DATA",
    "confidence": "HIGH | MEDIUM | LOW",
    "domain": "compliance | financial | operational | hr",
    "findings": [
      {
        "finding_id": "uuid",
        "rule_ref": "string (SOP or policy reference)",
        "description": "string",
        "severity": "INFO | WARNING | CRITICAL",
        "evidence_refs": ["citadel.evidence record IDs"]
      }
    ]
  },
  "context": {
    "applicable_sops": ["SOP identifiers evaluated"],
    "data_scope": {
      "odoo_model": "string",
      "record_ids": [0],
      "date_range": { "from": "date", "to": "date" }
    }
  },
  "integrity": {
    "advisory_hash_sha256": "hex string — SHA-256 of canonical advisory JSON",
    "chain_anchor_id": 0
  }
}
```

See [beacon_advisory_output_v1.0.json](../schemas/beacon_advisory_output_v1.0.json) for the full JSON Schema.

## Usage in Governance Flow

```
Operator submits action request
    │
    ▼
BEACON analyses mirror data
    │
    ├── COMPLIANT ──────────► Cited in MARSHAL input. Proceed to MARSHAL.
    ├── NEEDS_REVIEW ───────► Human reviews. Documents decision. Proceeds or halts.
    ├── NON_COMPLIANT ──────► Human addresses issue. Re-submits or escalates.
    └── INSUFFICIENT_DATA ──► Gather evidence. Do not proceed without resolution.
    │
    ▼
MARSHAL evaluates (independent of BEACON — MARSHAL uses its own evidence)
```

**Rule:** BEACON signals are informational input. MARSHAL makes the binding decision independently through its 5-gate evaluation. A BEACON `COMPLIANT` signal does not guarantee MARSHAL `EXECUTE`.

## Logging

All BEACON advisories are logged to `citadel.log` with:

- `system_module`: `citadel.beacon`
- `action`: `advisory`
- `result_status`: Maps to signal (COMPLIANT → `EXECUTED`, others → `REFUSED`)
- `risk_class`: Derived from highest finding severity
