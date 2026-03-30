# CITADEL Architecture

## Four-Layer System

| Layer | Name | Contents | Mutability |
|-------|------|----------|------------|
| P0_CORE | The Law | Immutable principles — identity, authority, source of truth, logging, freeze, crisis | Immutable after FREEZE |
| P1_OPERATIONAL | Enforcement | Runtime governance, change intake, sandbox, post-production audit | Operational — logged |
| P1.5_INSTITUTIONAL | Closure | Incidents, exceptions, personal accountability, sanctions | Institutional — logged |
| DATA | Operational Data | Odoo models, HR, contracts, invoicing, portfolio | Governed by MARSHAL |

## Component Diagram

```
                    ┌──────────────────────────────────┐
                    │          SIG Hub (Odoo 19)        │
                    │                                    │
                    │  ┌────────────┐  ┌─────────────┐  │
                    │  │  MARSHAL   │  │  WORM Log   │  │
                    │  │  (5 gates) │  │  (citadel.  │  │
                    │  │            │  │   log)      │  │
                    │  └─────┬──────┘  └─────────────┘  │
                    │        │                           │
                    │  ┌─────┴──────┐  ┌─────────────┐  │
                    │  │  Evidence  │  │   Chain     │  │
                    │  │  Vault     │  │   Anchors   │  │
                    │  └────────────┘  └─────────────┘  │
                    │                                    │
                    │  ┌────────────┐  ┌─────────────┐  │
                    │  │  Incident  │  │  SoD Engine │  │
                    │  │  Workflow  │  │             │  │
                    │  └────────────┘  └─────────────┘  │
                    └──────────┬───────────────────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
    ┌─────────────┐  ┌─────────────┐  ┌─────────────┐
    │   Mirror    │  │   Mirror    │  │   Mirror    │
    │  Odoo 18    │  │   TRIA      │  │  (future)   │
    │  TCL_001    │  │  CRV_001    │  │             │
    └──────┬──────┘  └──────┬──────┘  └─────────────┘
           │                │
           ▼                ▼
    ┌──────────────────────────────┐
    │  BEACON       │    PATROL    │
    │  (advisory)   │    (audit)   │
    │  reads mirror │ reads mirror │
    │  only         │ only         │
    └──────────────────────────────┘
```

## The CONTROL ≠ DATA Principle

Absolute separation between governance rules and operational data:

- **CONTROL** = SOPs, policies, MARSHAL rules, freeze state
- **DATA** = Odoo records (HR, contracts, invoices, portfolio)
- MARSHAL verifies only DATA, not CONTROL documents
- CONTROL changes require their own separate governance process

## Mirror Topology

BEACON and PATROL **never** access operative databases directly. They read from mirrors:

| Mirror | Source | Freshness | Purpose |
|--------|--------|-----------|---------|
| Mirror_Odoo18_TCL_001 | Odoo 18 Abissnet | < 15 min for CRITICAL | HR, contracts, invoicing data for advisory/audit |
| Mirror_Odoo19_CRV_001 | Odoo 19 TRIA | < 15 min for CRITICAL | Financial portfolio data for advisory/audit |

## Integration with opensecstack Platforms

When CITADEL governance is enabled for an opensecstack platform:

1. Platform submits action request → MARSHAL evaluates 5 gates
2. MARSHAL returns EXECUTE / REFUSE / HARD STOP
3. All outcomes logged to citadel.log (WORM, append-only)
4. Findings/evidence linked to citadel.evidence with SHA-256 fingerprint
5. Chain anchor updated with new log entries

| Platform Event | CITADEL Action | Severity |
|---------------|----------------|----------|
| APIGuard scan requested | MARSHAL Gate 1 (authority) + Gate 2 (scope) | INFO |
| APIGuard scan completed | citadel.log + findings → citadel.evidence | INFO/WARNING/CRITICAL |
| IRFlow incident created | citadel.log + citadel.incident | WARNING/CRITICAL |
| NIS2 Compass assessment | citadel.evidence (compliance evidence) | INFO |
| Any HARD STOP | citadel.incident auto-created, notification cascade | CRITICAL |
