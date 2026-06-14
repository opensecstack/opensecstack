# APIGuard User Guide

## Overview

APIGuard scans REST APIs against the OWASP API Security Top 10 (2023). This guide covers the full workflow: running scans, reading results, managing findings, and using the dashboard.

---

## Running Your First Scan

### CLI

```bash
apiguard scan \
  --spec ./api/openapi.yaml \
  --target https://api.example.com \
  --format html \
  --output report.html
```

The scan runs all enabled OWASP modules against the live target. Output goes to `report.html`. Exit code `1` means findings were found at or above the `--fail-on` threshold (default: `HIGH`).

### API

```bash
# Create a scan
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"spec_url":"https://petstore3.swagger.io/api/v3/openapi.json","target":"https://petstore3.swagger.io"}'

# Poll status
curl http://localhost:8080/api/v1/scans/{id} \
  -H "Authorization: Bearer $TOKEN"
```

---

## Scan Lifecycle

```
pending → running → completed
                 ↘ failed
```

| Status | Meaning |
|--------|---------|
| `pending` | Queued, not yet started |
| `running` | Actively scanning the target |
| `completed` | Finished — findings available |
| `failed` | Scanner error — check `error_message` field |
| `cancelled` | Manually cancelled before completion |

---

## Understanding Findings

Each finding maps to one OWASP API Top 10 category and carries a CVSS 3.1 score.

### Severity Levels

| Severity | CVSS Range | Action Required |
|----------|-----------|-----------------|
| CRITICAL | 9.0–10.0 | Fix before deployment. Block CI/CD pipeline. |
| HIGH | 7.0–8.9 | Fix in current sprint. |
| MEDIUM | 4.0–6.9 | Fix within 30 days. |
| LOW | 0.1–3.9 | Fix when capacity allows. |
| INFO | 0.0 | Informational. No CVSS score. Review manually. |

### Finding Fields

| Field | Description |
|-------|-------------|
| `owasp_id` | OWASP category (e.g. `API1:2023`) |
| `module_id` | Internal module that produced the finding |
| `title` | Short description of the vulnerability |
| `description` | Full explanation of the issue |
| `severity` | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | Numeric score 0.0–10.0 |
| `cvss_vector` | Full CVSS 3.1 vector string |
| `endpoint_path` | Affected API path (e.g. `/api/v1/users/{id}`) |
| `endpoint_method` | HTTP method (GET, POST, etc.) |
| `evidence` | Raw HTTP request/response pair proving the issue |
| `remediation` | How to fix the vulnerability |
| `status` | Triage state: `open`, `confirmed`, `false_positive`, `accepted`, `fixed` |

### Evidence

Every finding includes a request/response evidence block:

```json
{
  "evidence": {
    "request": {
      "method": "GET",
      "url": "https://api.example.com/api/v1/users/2",
      "headers": {"Authorization": "Bearer <user_a_token>"},
      "body": null
    },
    "response": {
      "status_code": 200,
      "headers": {"Content-Type": "application/json"},
      "body": "{\"id\":2,\"email\":\"user_b@example.com\",\"phone\":\"...\"}"
    },
    "note": "User A token retrieved User B's private data — BOLA confirmed"
  }
}
```

---

## Triaging Findings

Update a finding's status after review:

```bash
curl -X PATCH http://localhost:8080/api/v1/findings/{id} \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"status":"false_positive","note":"Test endpoint only, not reachable in production"}'
```

| Status | When to Use |
|--------|-------------|
| `open` | Default — not yet reviewed |
| `confirmed` | Verified as a real vulnerability |
| `false_positive` | Reviewed and determined to be a false alarm |
| `accepted` | Risk accepted — known issue, will not fix |
| `fixed` | Remediated — verify with next scan |

---

## Authentication Configuration

APIGuard needs credentials to test authenticated endpoints. Set auth via config file, env var, or CLI flag.

### Bearer Token

```yaml
auth:
  type: bearer
  token: "${APIGUARD_AUTH_TOKEN}"
```

### OAuth2 (client credentials)

```yaml
auth:
  type: oauth2
  oauth2:
    token_url: "https://auth.example.com/oauth/token"
    client_id: "apiguard"
    client_secret: "${APIGUARD_OAUTH2_CLIENT_SECRET}"
    scopes: [read, write]
    grant_type: client_credentials
```

### API Key

```yaml
auth:
  type: apikey
  apikey:
    header: X-API-Key
    value: "${APIGUARD_API_KEY}"
```

For BOLA testing (A1), provide a second token so APIGuard can attempt cross-user access:

```yaml
modules:
  a1_bola:
    extra_tokens:
      - "${APIGUARD_TOKEN_USER_B}"
```

---

## Using the Dashboard

The dashboard runs at `http://localhost:3000` by default.

### Scan History

The Scans page lists all past scans with status, finding counts by severity, and scan duration. Click any scan to view the full finding list.

### Finding Details

Each finding page shows: the OWASP category, CVSS score and vector, the affected endpoint, the raw evidence (request/response), and the remediation guidance. Use the status dropdown to triage directly from the UI.

### Audit Log

The Audit Log page shows every action taken in the system — scans created, findings triaged, API keys created — with actor, timestamp, and a chain hash for tamper detection.

---

## Exporting Reports

### CLI

```bash
# JSON (machine-readable)
apiguard scan --spec ./openapi.yaml --target https://api.example.com --format json --output results.json

# HTML (human-readable, shareable)
apiguard scan --spec ./openapi.yaml --target https://api.example.com --format html --output report.html

# SARIF (GitHub Advanced Security, CI/CD tools)
apiguard scan --spec ./openapi.yaml --target https://api.example.com --format sarif --output results.sarif

# PDF (formal compliance artifact)
apiguard scan --spec ./openapi.yaml --target https://api.example.com --format pdf --output report.pdf
```

### API

```bash
# Download a completed scan's JSON report
curl http://localhost:8080/api/v1/scans/{id}/report?format=json \
  -H "Authorization: Bearer $TOKEN" \
  -o report.json
```

---

## False Positive Suppression

Suppress known false positives by path and module in the config file:

```yaml
suppress:
  - endpoint: "/api/v1/internal/debug"
    method: "*"
    reason: "Internal endpoint, not exposed in production"
  - endpoint: "/api/v1/users/{id}"
    method: "GET"
    module: "a1_bola"
    reason: "Intentional admin read-all access, reviewed 2026-01-15"
```

Suppressed findings still appear in reports but are marked `suppressed` and excluded from the exit code threshold check.

---

## Running Only Specific Modules

```bash
# Run only BOLA and auth modules
apiguard scan --spec ./openapi.yaml --target https://api.example.com --modules a1_bola,a2_auth

# Disable a single module in config
# .apiguard.yaml
modules:
  a6_business_flow:
    enabled: false
```

---

## Next Steps

- [Configuration Reference](configuration.md) — all settings
- [CLI Reference](cli-reference.md) — all commands and flags
- [OWASP Coverage](owasp-coverage.md) — what each module tests
- [CI/CD Integration](cicd-integration.md) — GitHub Actions, GitLab CI, Jenkins
- [Custom Rules](custom-rules.md) — write organisation-specific checks
- [Data Model](data-model.md) — scan and finding schema reference
