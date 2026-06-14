# NIS2 Directive Mapping

APIGuard findings map directly to NIS2 Article 21 security measures. This document explains the mapping and how to use APIGuard scan results as compliance evidence.

---

## NIS2 Article 21 — Security Measures

Article 21(2) requires essential and important entities to implement measures covering:

| Ref | Measure |
|-----|---------|
| Art.21(2)(a) | Risk analysis and information system security policies |
| Art.21(2)(b) | Incident handling |
| Art.21(2)(c) | Business continuity and crisis management |
| Art.21(2)(d) | Supply chain security |
| Art.21(2)(e) | Security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure |
| Art.21(2)(f) | Policies and procedures to assess the effectiveness of cybersecurity risk-management measures |
| Art.21(2)(g) | Basic cyber hygiene practices and cybersecurity training |
| Art.21(2)(h) | Policies and procedures regarding the use of cryptography and encryption |
| Art.21(2)(i) | Human resources security, access control policies and asset management |
| Art.21(2)(j) | Use of multi-factor authentication or continuous authentication solutions |

---

## OWASP API Top 10 → NIS2 Article 21 Mapping

| OWASP ID | OWASP Name | NIS2 Article | NIS2 Requirement | Evidence Generated |
|----------|-----------|--------------|-------------------|-------------------|
| API1:2023 | Broken Object Level Authorization | Art.21(2)(e), Art.21(2)(i) | Vulnerability handling; Access control | Finding record with endpoint, evidence of unauthorised access, CVSS score |
| API2:2023 | Broken Authentication | Art.21(2)(e), Art.21(2)(j) | Vulnerability handling; Authentication controls | Finding with auth bypass evidence, token handling flaws |
| API3:2023 | Broken Object Property Level Authorization | Art.21(2)(e), Art.21(2)(i) | Vulnerability handling; Access control | Finding with over-exposed field evidence |
| API4:2023 | Unrestricted Resource Consumption | Art.21(2)(e), Art.21(2)(a) | Vulnerability handling; Risk analysis | Finding with rate limit absence evidence |
| API5:2023 | Broken Function Level Authorization | Art.21(2)(e), Art.21(2)(i) | Vulnerability handling; Access control | Finding with privilege escalation evidence |
| API6:2023 | Unrestricted Access to Sensitive Business Flows | Art.21(2)(a), Art.21(2)(e) | Risk analysis; Vulnerability handling | Finding with business flow abuse evidence |
| API7:2023 | Server Side Request Forgery | Art.21(2)(e), Art.21(2)(h) | Vulnerability handling; Network security | Finding with SSRF evidence |
| API8:2023 | Security Misconfiguration | Art.21(2)(e), Art.21(2)(h) | Vulnerability handling; Cryptography/TLS | Finding with misconfiguration detail |
| API9:2023 | Improper Inventory Management | Art.21(2)(a), Art.21(2)(e) | Risk analysis; Vulnerability management | Finding with undocumented endpoint discovery |
| API10:2023 | Unsafe Consumption of APIs | Art.21(2)(d), Art.21(2)(e) | Supply chain security; Vulnerability handling | Finding with third-party API risk evidence |

---

## Using APIGuard as NIS2 Compliance Evidence

### What Counts as Evidence

Under NIS2, evidence of security testing is accepted for Art.21(2)(e) (vulnerability handling). An APIGuard scan report provides:

1. **Test scope** — which API endpoints were tested, on which date
2. **Methodology** — OWASP API Security Top 10, automated scanning
3. **Findings** — identified vulnerabilities with CVSS scores
4. **Remediation record** — finding triage status, fix timeline
5. **Chain of custody** — scan spec hash, timestamp, audit log entry

### Minimum Evidence Requirements

For an APIGuard scan to constitute NIS2 compliance evidence:

- [ ] Scan completed against the production or production-equivalent API
- [ ] Spec hash recorded (proves which API version was tested)
- [ ] All CRITICAL and HIGH findings either fixed (`status: fixed`) or risk-accepted with justification
- [ ] Scan report exported and stored with timestamp
- [ ] If CITADEL integration is enabled: scan event logged to WORM chain

### Scan Frequency

NIS2 does not specify a mandatory scanning frequency. Recommended:

| Context | Frequency |
|---------|-----------|
| Before each production release | Per-release |
| As part of CI/CD pipeline | Per PR |
| Periodic compliance assessment | Monthly |
| After security incidents | Immediate |

---

## NIS2 Compass Integration

APIGuard scan results are automatically forwarded to NIS2 Compass when the integration is configured. NIS2 Compass maps each scan to the correct Article 21 measure and tracks evidence over time.

```yaml
integrations:
  nis2compass:
    enabled: true
    url: "https://nis2compass.internal"
    api_key: "${NIS2COMPASS_API_KEY}"
    org_id: "uuid"
    measure_mapping:
      default: "art21_e"
      a1_bola: "art21_e"
      a2_auth: "art21_j"
      a8_misconfig: "art21_h"
      a9_inventory: "art21_a"
      a10_unsafe_consumption: "art21_d"
```

---

## Generating a NIS2 Compliance Report

```bash
# Export scan results in JSON for NIS2 Compass import
apiguard scan \
  --spec ./api/openapi.yaml \
  --target https://api.example.com \
  --format json \
  --output nis2-evidence-$(date +%Y%m%d).json

# HTML report for regulatory submission
apiguard scan \
  --spec ./api/openapi.yaml \
  --target https://api.example.com \
  --format html \
  --output nis2-report-$(date +%Y%m%d).html
```

The JSON report includes: scan metadata (date, spec hash, target URL), full findings list with CVSS scores, per-finding evidence, and remediation status. This constitutes a complete technical evidence package for NIS2 Article 21(2)(e).

---

## Sector-Specific Notes

NIS2 applies differently to essential vs. important entities. Essential entities face stricter supervision. For essential entity operators:

- Run APIGuard on every API endpoint in scope (not just external-facing)
- Retain scan records for at least 12 months
- Ensure the CITADEL WORM log captures all scan lifecycle events for tamper-evident chain of custody
- Include scan results in annual security reporting to the National Competent Authority
