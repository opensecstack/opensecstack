# NIS2 Compass Roadmap

---

## v0.1.0 — Core Platform (current)

- Organisation and assessment management
- 10 NIS2 Article 21(2) control measures
- Evidence (artifact) upload and management
- Remediation tracking per control
- Immutable audit log with chain hash
- API key + JWT authentication
- React web dashboard
- APIGuard webhook receiver

## v0.2.0 — Platform Integrations

- IRFlow integration: automatically import incident records as evidence for Art.21(2)(b)
- ThreatFlow integration: import threat intelligence feeds as evidence for Art.21(2)(a)
- OpenCSIRT integration: import CSIRT advisories as evidence for Art.21(2)(e)
- APIGuard scan-to-control mapping: map scan findings to specific Article 21 measures automatically
- SDK Go + Python clients for NIS2 Compass published as part of the opensecstack SDK
- Bulk control assessment API for programmatic evidence import

## v0.3.0 — CITADEL Integration + Evidence Integrity

- CITADEL WORM log integration: export audit log entries to the CITADEL immutable governance chain
- Chain anchor: anchor audit log chains to CITADEL for external verifiability
- Evidence fingerprint: SHA-256 fingerprint of each evidence artifact stored in CITADEL
- Dry-run mode: validate an assessment without writing to the audit log
- Multi-approver workflow: require second approver for assessment status transitions (SoD)

## v0.4.0 — Reporting and Gap Analysis

- Automated gap analysis: compute compliance score per NIS2 measure based on control status and evidence
- NIS2 compliance report generator: PDF and HTML reports suitable for regulatory submission
- CSAF 2.0 export: export findings in CSAF format for interoperability with CERT/CSIRT tools
- Executive summary dashboard: organisation-level compliance posture visualisation
- Remediation roadmap generator: prioritised remediation list based on gap severity and effort

## v1.0.0 — Production Release

- Full NIS2 Article 21 coverage with documented evidence requirements per measure
- Multi-entity support: manage NIS2 compliance for multiple group entities from one instance
- Role-based access control: admin, assessor, auditor, viewer roles with per-organisation scope
- Notification system: email/webhook alerts on assessment due dates, control status changes
- Compliance history: track compliance posture over time, trend charts
- NCA (National Competent Authority) export format support
- SOC 2 / ISO 27001 control mapping (additional frameworks beyond NIS2)
- Penetration testing evidence type: structured import of pentest reports
- API stability guarantee: v1 API contract locked, backward compatibility maintained
