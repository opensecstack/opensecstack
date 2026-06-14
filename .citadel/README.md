# CITADEL Governance Engine

> The innermost fortress — last and most protected layer inside a defensive system.

Built by **Security Intelligence Group (SIG)**. CITADEL is the governance layer for the opensecstack ecosystem. It guarantees every action happens according to the rules, creating an audit-proof, long-term governance system with cryptographic proofs.

## What CITADEL Is

CITADEL is an institutional governance engine that runs inside Odoo 18/19. It provides:

- **MARSHAL** — Deterministic 5-gate decision engine (EXECUTE / REFUSE / HARD STOP)
- **BEACON** — Analytical advisory intelligence (reads data, returns normative signals)
- **PATROL** — Audit verification intelligence (continuous + deep audit)
- **WORM Log** — Append-only immutable evidence ledger (INSERT-only, no UPDATE, no DELETE)
- **Chain Anchors** — SHA-256 cryptographic chain proving log integrity
- **Evidence Vault** — Forensic evidence store with chain of custody
- **SoD Engine** — Separation of duties enforcement

## What CITADEL Is NOT

- Not a chatbot or AI assistant
- Not an autonomous system that makes decisions on its own
- Not a development tool — it is an institutional framework
- Not optional when governance is enabled — all actions go through MARSHAL

## The Three Intelligences

| Intelligence | Purpose | Authority | Reads From |
|-------------|---------|-----------|------------|
| **BEACON** | Advisory signals: COMPLIANT, NEEDS_REVIEW, NON_COMPLIANT, INSUFFICIENT_DATA | No execution authority. Signals must be cited in records. | Mirror only (read-only) |
| **MARSHAL** | Deterministic verification: EXECUTE, REFUSE, HARD STOP | Binding. No interpretation. 5-gate evaluation. | Direct operational data |
| **PATROL** | Audit verdicts: VALID, VALID_WITH_WARNINGS, INVALID, INCONCLUSIVE | Non-compliance reports trigger escalation on INVALID. | Mirror only (read-only) |

## The 3-Outcome Principle

Every MARSHAL evaluation produces exactly one of three outcomes:

| Outcome | Meaning | What Happens |
|---------|---------|--------------|
| **EXECUTE** | All 5 gates passed. Action is authorised. | Action proceeds. Logged to WORM. |
| **REFUSE** | One or more gates failed. Action is not authorised. | Action blocked. Logged. Can be appealed. |
| **HARD STOP** | Critical violation detected (SoD breach, scope violation, tamper). | All sensitive actions frozen. Incident auto-created. Notification cascade. |

## Multi-ERP Topology

| Instance | Purpose | Data |
|----------|---------|------|
| Odoo 18 — Abissnet (TCL_001) | Operative legal facts | HR, contracts, invoicing, CRM |
| Odoo 19 — SIG Hub | Institutional architecture | SOPs, BEACON, MARSHAL, PATROL |
| Odoo 19 — TRIA (CRV_001) | Financial portfolio | Crypto assets, indices, metals |

**Rule:** Authorisations do not transfer between ERPs.

## Documentation

### Getting Started / Overview

- [Architecture](docs/architecture.md) — Four-layer system design (P0_CORE, P1_OPERATIONAL, P1.5_INSTITUTIONAL, DATA)
- [Data Model](docs/data-model.md) — PostgreSQL schema for the CITADEL governance engine
- [Kerkese Specification](docs/kerkese-spec.md) — Structured action request format submitted to MARSHAL for governance review
- [Known Limitations](docs/known-limitations.md) — Current limitations of CITADEL v0.1.x and planned improvements
- [Auditor Walkthrough](docs/auditor-walkthrough.md) — Guide for auditors conducting governance reviews of CITADEL-governed systems

### MARSHAL (Governance Engine)

- [MARSHAL Engine](docs/marshal.md) — Deterministic 5-gate decision engine (EXECUTE / REFUSE / HARD STOP)
- [ARBITER Overview](docs/arbiter.md) — System-level overview of the governance decision system (MARSHAL, BEACON, PATROL, VIGIL)
- [Appeal Flow](docs/appeal-flow.md) — Process for appealing a MARSHAL REFUSE or HARD STOP decision
- [Dry Run and Drill Procedure](docs/dry-run.md) — Dry-run mode for Kerkese evaluation and quarterly Hard Stop drill procedure
- [Separation of Duties](docs/sod.md) — SoD enforcement rules; violations trigger immediate HARD STOP

### WORM (Audit Ledger)

- [WORM Log Specification](docs/worm-log.md) — Append-only immutable evidence ledger (INSERT-only, no UPDATE, no DELETE)
- [Chain Anchor Algorithm](docs/chain-anchor.md) — SHA-256 cryptographic chain proving WORM log integrity
- [Triple Hash](docs/triple-hash.md) — Three-algorithm content hashing scheme for defence-in-depth against collisions
- [Evidence Vault](docs/evidence-vault.md) — Forensic evidence store with chain of custody for all governance evidence

### VIGIL (Monitoring)

- [VIGIL Monitoring Layer](docs/vigil.md) — Two-tier monitoring: real-time governance health and deep periodic audit scanning
- [BEACON Advisory Intelligence](docs/beacon.md) — Analytical advisory intelligence returning normative signals (no execution authority)
- [PATROL Audit Intelligence](docs/patrol.md) — Audit verification intelligence with continuous and deep audit verdicts

### AUGUR (Threat Advisories)

- [AUGUR Predictive Advisory](docs/augur.md) — Pre-emptive governance advisories based on mirror data analysis
- [Multi-ERP Mirror Configuration](docs/multi-erp.md) — Configuration for AUGUR reading from multiple ERP mirror sources

### Security / Auth

- [Security Model](docs/security-model.md) — Security properties, trust boundaries, and threat model for CITADEL
- [SOP-012: Incident Response](docs/sop-012-incident.md) — Standard operating procedure for security incident management

### Operations / Runbooks

- [Operator Runbook](docs/operator-runbook.md) — Day-to-day operational procedures for CITADEL administrators
- [Hard Stop Playbook](docs/hard-stop-playbook.md) — Procedures when MARSHAL issues a HARD STOP (notifications, resolution steps)
- [Pre-Freeze Checklist](docs/pre-freeze-checklist.md) — Checklist to complete before applying a project freeze in CITADEL

### Integration / Connectors

- [Connector Guide](docs/connector-guide.md) — Integration layer for submitting Kerkese requests to MARSHAL from external systems
- [GitHub Task Integration](docs/task-github.md) — Creating and managing GitHub Issues as governance task artifacts from MARSHAL decisions

## Name History

| Legacy Name | Current Name | Meaning |
|-------------|-------------|---------|
| AIG (Atlas Intelligence Group) | SIG (Security Intelligence Group) | Security-focused intelligence with clear visibility |
| FORGE | CITADEL | Innermost fortress — most protected layer |
| DEA_GATE | MARSHAL | Enforcer who makes binding decisions from evidence |
| NORA | BEACON | Emits advisory signals, gives formal advice, cannot authorise |
| ARGIUS | PATROL | Continuous watchfulness, reports anomalies |
| VIG (Vantage Intelligence Group) | SIG (Security Intelligence Group) | Renamed for IP clarity |
| ARBITER | MARSHAL | Renamed for IP clarity |
| AUGUR | BEACON | Renamed for IP clarity |
| VIGIL | PATROL | Renamed for IP clarity |
