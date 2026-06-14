# NIS2 Compliance Mapping

SecureLab supports compliance with specific requirements of the NIS2 Directive (Directive (EU) 2022/2555). This document maps SecureLab capabilities to the relevant articles.

## Article 21 — Cybersecurity risk-management measures

Article 21 requires essential and important entities to implement security measures that include, among others, security testing and post-incident analysis procedures.

### Article 21(2)(e) — Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure

| NIS2 Requirement | SecureLab Support |
|---|---|
| Regular security testing of information systems | SecureLab provides automated, repeatable attack simulation that can be scheduled to run at defined intervals |
| Vulnerability handling | Detection gaps identified by SecureLab represent unfixed detection weaknesses that feed directly into a vulnerability management workflow |
| Evidence of testing | Every SecureLab run emits a `securelab.run_completed` event to CITADEL, providing an immutable, timestamped record of security testing activity |

### Article 21(2)(f) — Policies and procedures to assess the effectiveness of cybersecurity risk-management measures

| NIS2 Requirement | SecureLab Support |
|---|---|
| Effectiveness assessment of security controls | The detection validation pipeline provides quantitative measurement: detection rate %, latency P95, and per-technique gap lists |
| MITRE ATT&CK coverage matrix | SecureLab generates a coverage report showing which ATT&CK techniques are tested and which have confirmed detections |
| Documented test results | Run results are stored in PostgreSQL and referenced by CITADEL WORM records, providing audit-ready documentation |

### Recommended scenario set for NIS2 Article 21 evidence

To generate Article 21 compliance evidence, run the following scenarios quarterly:

1. `combined/apt-simulation` — multi-stage attack across recon, initial access, and exfil
2. `combined/full-kill-chain` — full kill chain simulation
3. `api/bola-basic` + `api/auth-jwt-none` + `api/mass-assignment-role` — OWASP API Top 10 coverage
4. `network/syn-flood-100kpps` + `network/http-flood` — DoS resilience validation
5. `recon/port-scan` + `recon/api-endpoint-enum` — reconnaissance detection validation

---

## Article 23 — Reporting obligations

Article 23 requires entities to notify competent authorities of significant incidents within defined timeframes. SecureLab supports Article 23 readiness by validating that the detection and alerting pipeline can identify incidents that would trigger reporting obligations.

### How SecureLab validates Article 23 readiness

| Validation Goal | SecureLab Scenario | Expected Detection |
|---|---|---|
| Validate that unauthorized access to sensitive data is detected within 24 hours | `api/bola-basic`, `combined/apt-simulation` | OpenScrub alert within detection window |
| Validate that credential theft attempts are detected | `api/auth-jwt-none`, `api/jwt-brute` | APIGuard auth alert |
| Validate that exfiltration attempts are detected | `combined/full-kill-chain` | ThreatFlow exfil IOC; OpenScrub bulk export alert |
| Validate incident detection latency | All scenarios with detection validation | `detection_latency_ms` in run report |

### Incident reporting validation workflow

1. Run `combined/full-kill-chain` with all three detection platforms enabled.
2. Retrieve the run report: `GET /api/v1/runs/{run_id}/report`.
3. Confirm all stages have `detected` verdict.
4. Record the detection latency: confirm P95 latency is under your Article 23 notification SLA.
5. The CITADEL `securelab.run_completed` event serves as immutable evidence of the validation exercise.

---

## NIS2 audit evidence package

To produce an NIS2 audit evidence package:

1. Run the recommended scenario set above.
2. Export CITADEL records for all `securelab.run_completed` events.
3. Export the MITRE ATT&CK coverage report: `GET /api/v1/coverage`.
4. Export the detection gap report for each run.
5. Document remediation actions taken for any `not_detected` gaps.

This package demonstrates to a NIS2 competent authority that:
- Security testing is performed regularly and documented.
- Detection effectiveness is quantitatively measured.
- Detection gaps are identified and tracked.
- Testing results are retained in an immutable audit trail (CITADEL WORM).
