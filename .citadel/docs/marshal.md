# MARSHAL Engine Reference

MARSHAL (formerly ARBITER / DEA_GATE) is the deterministic 5-gate decision engine at the core of CITADEL. It produces exactly one of three outcomes: **EXECUTE**, **REFUSE**, or **HARD STOP**. No interpretation. No heuristics. Only deterministic verification.

## The 5 Gates

Every action request passes through all 5 gates in sequence. If any gate fails, the process stops.

| Gate | Name | Question | Failure Mode |
|------|------|----------|--------------|
| **Gate 1** | Authority | Does the actor have an explicit mandate? Is the scope clear? Is the actor authorised? Is SoD respected? | REFUSE if no mandate. HARD STOP if SoD violation. |
| **Gate 2** | Scope | Does `project_id` string-exact match a whitelisted project? Is this within the authorised scope? | REFUSE if out of scope. HARD STOP if spoofing detected. |
| **Gate 3** | Determinism | Is the output fully derived from evidence? No assumptions? No heuristics? | REFUSE if any assumption or heuristic detected. |
| **Gate 4** | Evidence | Is evidence complete, traceable, non-contradictory, and temporally valid? | REFUSE if incomplete. HARD STOP if contradictory. |
| **Gate 5** | Schema | Is the output schema complete? Loggable? ORM-mappable? | REFUSE if schema validation fails. |

## Decision Tree

```
Request arrives
    │
    ▼
┌─ Gate 1: Authority ─┐
│  Mandate? Scope?     │──── SoD violation ──────► HARD STOP
│  Actor? SoD?         │──── No mandate ──────────► REFUSE
└──────┬───────────────┘
       │ PASS
       ▼
┌─ Gate 2: Scope ─────┐
│  project_id match?   │──── Spoofing detected ──► HARD STOP
│  Whitelist check?    │──── Out of scope ────────► REFUSE
└──────┬───────────────┘
       │ PASS
       ▼
┌─ Gate 3: Determinism ┐
│  Evidence-derived?    │──── Heuristic found ────► REFUSE
│  No assumptions?      │
└──────┬───────────────┘
       │ PASS
       ▼
┌─ Gate 4: Evidence ───┐
│  Complete? Traceable? │──── Contradictory ──────► HARD STOP
│  Non-contradictory?   │──── Incomplete ─────────► REFUSE
│  Temporally valid?    │
└──────┬───────────────┘
       │ PASS
       ▼
┌─ Gate 5: Schema ─────┐
│  Schema complete?     │──── Validation fail ────► REFUSE
│  Loggable? Mappable?  │
└──────┬───────────────┘
       │ PASS
       ▼
    EXECUTE
```

## Project Scope Whitelist

MARSHAL only processes requests for whitelisted projects:

| Project ID | Description |
|------------|-------------|
| `ABISSNET_TCL_001` | Abissnet operative (Odoo 18) |
| `TRIA` | TRIA financial portfolio (Odoo 19) |
| `Portfolio_CRV_001_P01` | CRV portfolio subset |

## MARSHAL Output Schema (v2.0)

The output contains 5 mandatory objects:

```json
{
  "meta": {
    "schema_version": "2.0",
    "runtime_context": "production",
    "project_id": "ABISSNET_TCL_001",
    "execution_id": "uuid",
    "ts_utc": "2026-03-24T12:00:00Z"
  },
  "decision": {
    "outcome": "EXECUTE | REFUSE | HARD_STOP",
    "severity": "INFO | WARNING | CRITICAL",
    "gates": [
      { "gate": 1, "name": "authority", "status": "PASS | FAIL", "reason": "" }
    ],
    "reasons": []
  },
  "bindings": {
    "odoo": { "model": "", "record_id": 0, "transaction_id": "" },
    "actor": { "user_id": 0, "role": "", "groups": [] },
    "sod": {
      "required": true,
      "operator_user_id": 0,
      "verifier_user_id": 0,
      "status": "VALID | VIOLATION"
    }
  },
  "integrity": {
    "pack_hash_sha256": "",
    "canonical_fingerprint_sha256": "",
    "chain_anchor": {
      "anchor_id": 0,
      "anchor_hash": "",
      "rotation_seq": 0
    }
  },
  "actions": {
    "proposed": [],
    "executed": [],
    "required_evidence": [],
    "incidents": []
  }
}
```

**Rule:** When `outcome=EXECUTE`, `required_evidence[]` must be empty (maxItems: 0).

## SoD Enforcement

MARSHAL enforces separation of duties at Gate 1:

- `group_sig_operator` may request execution
- `group_sig_verifier` executes MARSHAL
- OWNER = VERIFIER for same object → **IMMEDIATE HARD STOP**
- No exceptions. No overrides.
