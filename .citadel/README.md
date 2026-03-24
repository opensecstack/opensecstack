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

- [Architecture](docs/architecture.md)
- [MARSHAL Engine](docs/marshal.md)
- [BEACON Advisory Intelligence](docs/beacon.md)
- [PATROL Audit Intelligence](docs/patrol.md)
- [Evidence Vault](docs/evidence-vault.md)
- [WORM Log Specification](docs/worm-log.md)
- [Chain Anchor Algorithm](docs/chain-anchor.md)
- [Separation of Duties](docs/sod.md)

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
