# APIGuard Validation

This guide explains how to use SecureLab to validate APIGuard detection coverage across the OWASP API Security Top 10.

## Overview

APIGuard blocks and alerts on OWASP API Security Top 10 attacks. SecureLab runs the full OWASP scenario suite against a test target and verifies that APIGuard generates the expected blocks and alerts for each attack category.

## Prerequisites

1. APIGuard deployed in front of the test environment (or configured in observation mode).
2. `SECURELAB_APIGUARD_URL` and `SECURELAB_APIGUARD_API_KEY` configured.
3. Test environment running.

## Recommended scenarios by OWASP category

| OWASP Category | Scenario | Expected APIGuard Response |
|---|---|---|
| API1 — BOLA | `api/bola-basic`, `api/bola-uuid` | BOLA alert on sequential/bulk ID access |
| API2 — Authentication | `api/auth-jwt-none`, `api/auth-weak-secret` | JWT validation failure alert; brute force detection |
| API3 — Broken Object Property Level Authorization | `api/mass-assignment-role` | Mass assignment alert on privileged field write |
| API8 — Security Misconfiguration | `api/ssrf-metadata` | SSRF detection alert |
| API4 — Rate Limiting | `api/rate-limit-bypass` | Rate limit bypass attempt alert |

## Running the OWASP suite

```bash
# Run all API scenarios in sequence
for scenario in api/bola-basic api/bola-uuid api/auth-jwt-none api/auth-weak-secret \
                api/mass-assignment-role api/ssrf-metadata api/rate-limit-bypass; do
  curl -X POST http://localhost:8080/api/v1/runs \
    -H "Authorization: Bearer <admin-jwt>" \
    -H "Content-Type: application/json" \
    -d "{\"scenario\": \"$scenario\", \"environment_id\": \"env_test_01\", \"detection_platforms\": [\"apiguard\"]}"
done
```

## Gap analysis workflow

1. Fetch the MITRE coverage report: `GET /api/v1/coverage`
2. Identify techniques with `not_detected` verdict.
3. Cross-reference with APIGuard rule configuration.
4. Enable or tune the relevant APIGuard rule.
5. Re-run the corresponding SecureLab scenario to validate the fix.

## Common gaps and remediation

| Gap | Likely cause | Remediation |
|---|---|---|
| JWT none not detected | APIGuard JWT validation not enabled for this endpoint | Add the endpoint to APIGuard's JWT-protected route list |
| Mass assignment not detected | Field-level blocking not configured | Enable OWASP A3 rules in APIGuard config |
| SSRF not detected | SSRF filter blocklist not including `169.254.169.254` | Add cloud metadata IP ranges to APIGuard SSRF blocklist |
| Rate limit bypass not detected | APIGuard trusting X-Forwarded-For header | Disable header-based IP override or add it to untrusted list |
