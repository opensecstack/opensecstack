# NIS2 Compliance Mapping

CyberPath supports organizational compliance with NIS2 Directive Article 21, which requires essential and important entities to implement technical and organizational measures including cybersecurity training. This document maps CyberPath learning paths to specific Article 21 measures and explains how to generate audit evidence.

## NIS2 Article 21 Training Obligations

Article 21(2) lists the following measure areas relevant to training:

| Code | Measure Area |
|---|---|
| `risk-management` | Risk analysis and information system security policies |
| `incident-handling` | Incident handling and response |
| `business-continuity` | Business continuity and crisis management |
| `supply-chain` | Supply chain security |
| `network-security` | Security in network and information systems acquisition, development, and maintenance |
| `access-control` | Access control policies and asset management |
| `cryptography` | Use of cryptography and encryption |

## Learning Path to NIS2 Measure Mapping

| Path ID | Path Title | NIS2 Measures |
|---|---|---|
| `owasp-api-top10` | OWASP API Security Top 10 | `network-security`, `access-control` |
| `nis2-fundamentals` | NIS2 Directive Fundamentals | `risk-management`, `incident-handling`, `business-continuity` |
| `network-defense` | Network Defense Fundamentals | `network-security`, `access-control` |
| `incident-response` | Incident Response Operations | `incident-handling`, `business-continuity` |
| `sovereign-os` | Sovereign OS and Hardening | `network-security`, `cryptography`, `access-control` |

These mappings are declared in each `path.yaml` under the `nis2_measures` field. Adding a new path that addresses NIS2 obligations requires that field to be populated; the compliance report engine reads it at report generation time.

## Recommended Training Frequency by Role

These are minimum recommended frequencies. Higher-risk roles or roles with elevated system access should train more often.

| Role | Recommended Paths | Frequency |
|---|---|---|
| All staff | `nis2-fundamentals` | Annual |
| Network operator | `network-defense`, `owasp-api-top10` | Annual |
| Security analyst | `owasp-api-top10`, `incident-response`, `network-defense` | Semi-annual |
| CSIRT lead | `incident-response`, `nis2-fundamentals`, `network-defense` | Semi-annual |
| System administrator | `sovereign-os`, `network-defense` | Annual |
| Developer | `owasp-api-top10`, `sovereign-os` | Annual |

Frequency targets should be encoded in your organization's security policy and referenced in audit documentation. CyberPath does not enforce training schedules but provides the tooling to report on completion against them.

## Generating a Training Compliance Report

The compliance report endpoint aggregates certificate records and maps them to NIS2 measures:

```
GET /admin/reports/training-compliance
```

Query parameters:

| Parameter | Description |
|---|---|
| `from` | Start date (ISO 8601), e.g. `2024-01-01` |
| `to` | End date (ISO 8601), e.g. `2024-12-31` |
| `measure` | Filter by NIS2 measure code, e.g. `incident-handling` |
| `role` | Filter by user role as defined in CITADEL |
| `format` | `json` (default) or `csv` |

Example request:

```bash
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  "https://cyberpath.example.com/admin/reports/training-compliance?from=2024-01-01&to=2024-12-31&format=csv"
```

The CSV output includes: `user_id`, `learner_name`, `learner_email`, `role`, `path_title`, `nis2_measures`, `completion_date`, `score`, `certificate_id`, `verification_url`.

## Certificate Evidence for Audits

Each issued certificate includes:

- The learner's full name and email.
- The path title and completion date.
- The NIS2 measure codes addressed.
- A publicly verifiable URL (`/verify/{certificate_id}`) that auditors can check without access to internal systems.

For audit submissions, export the compliance report as CSV and attach selected PDF certificates. The verification URL on each certificate allows auditors to independently confirm validity without contacting your organization.

Store compliance reports and certificate PDFs in your organization's document management system alongside other Article 21 evidence (risk assessments, incident logs, access control reviews).

## CITADEL Integration

User roles are synchronized from CITADEL into CyberPath. The compliance report uses CITADEL role assignments when filtering by role. Ensure role data is kept current in CITADEL; stale roles will cause the compliance report to misclassify users. Role synchronization runs on the `citadel.user_updated` event; no manual sync step is needed under normal operation.
