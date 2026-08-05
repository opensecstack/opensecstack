# Report Formats

APIGuard's Report Generator (L7) supports three formats today — JSON,
SARIF, and HTML, all generated natively in Go
(`internal/reporter/{json,sarif,html}.go`). PDF is documented below as
target design; see the caveat in that section — it is not a recognized
`--format` value yet.

## Format Overview

| Format | Generator | Primary Use Case | CI/CD Friendly | Stdout Default |
|--------|-----------|-----------------|----------------|----------------|
| JSON | Go | Archival, programmatic consumption, custom tooling | Yes | Yes |
| SARIF | Go | GitHub Security tab, Azure DevOps, IDE integration | Yes | Yes |
| HTML | Go | Human review, team distribution, presentations | No | No |
| PDF | Not implemented (see below) | Compliance, audit evidence, offline distribution | No | No |

---

## JSON Format

The JSON report is the canonical machine-readable output. All other formats are derived from the same internal finding data.

### Schema

```json
{
  "schema_version": "1.0",
  "scan": {
    "id": "string (UUIDv4)",
    "timestamp": "string (ISO 8601)",
    "duration_seconds": "number",
    "apiguard_version": "string (semver)",
    "target_url": "string (URL)",
    "schema_source": "string (file path or URL)",
    "schema_hash": "string (SHA-256)",
    "modules_enabled": ["string"],
    "auth_mode": "string (jwt | oauth2 | apikey | session | none)"
  },
  "summary": {
    "total_findings": "integer",
    "by_severity": {
      "critical": "integer",
      "high": "integer",
      "medium": "integer",
      "low": "integer",
      "info": "integer"
    },
    "by_module": {
      "<module_id>": "integer"
    },
    "pass": "boolean",
    "pass_threshold": "string (severity level)"
  },
  "findings": [
    {
      "id": "string (UUIDv4)",
      "title": "string",
      "module": "string (e.g. a1_bola)",
      "owasp_id": "string (e.g. API1:2023)",
      "severity": "string (CRITICAL | HIGH | MEDIUM | LOW | INFO)",
      "cvss_score": "number (0.0 - 10.0)",
      "cvss_vector": "string (CVSS:3.1/AV:N/AC:L/...)",
      "endpoint": "string (path)",
      "method": "string (GET | POST | PUT | PATCH | DELETE | ...)",
      "evidence": {
        "request": {
          "url": "string",
          "method": "string",
          "headers": {"string": "string"},
          "body": "string | null"
        },
        "response": {
          "status_code": "integer",
          "headers": {"string": "string"},
          "body": "string (truncated to 4KB)",
          "latency_ms": "number"
        }
      },
      "description": "string",
      "remediation": "string",
      "references": ["string (URL)"],
      "confidence": "string (HIGH | MEDIUM | LOW)",
      "false_positive": "boolean (default false)"
    }
  ]
}
```

### Example Output

```json
{
  "schema_version": "1.0",
  "scan": {
    "id": "a3f8c2e1-7b4d-4e9a-b6c1-2d5f8a3e7b9c",
    "timestamp": "2026-03-24T14:32:08Z",
    "duration_seconds": 47,
    "apiguard_version": "0.4.0",
    "target_url": "https://api.example.com",
    "schema_source": "openapi.yaml",
    "schema_hash": "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "modules_enabled": ["a1_bola", "a2_auth", "a3_mass_assignment", "a8_misconfig"],
    "auth_mode": "jwt"
  },
  "summary": {
    "total_findings": 3,
    "by_severity": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0,
      "info": 0
    },
    "by_module": {
      "a1_bola": 1,
      "a2_auth": 1,
      "a8_misconfig": 1
    },
    "pass": false,
    "pass_threshold": "high"
  },
  "findings": [
    {
      "id": "d4e5f6a7-b8c9-4d0e-a1f2-3b4c5d6e7f8a",
      "title": "BOLA: Horizontal access to user profile",
      "module": "a1_bola",
      "owasp_id": "API1:2023",
      "severity": "CRITICAL",
      "cvss_score": 9.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
      "endpoint": "/api/v1/users/{id}/profile",
      "method": "GET",
      "evidence": {
        "request": {
          "url": "https://api.example.com/api/v1/users/1002/profile",
          "method": "GET",
          "headers": {
            "Authorization": "Bearer eyJhbG....[REDACTED]",
            "Accept": "application/json"
          },
          "body": null
        },
        "response": {
          "status_code": 200,
          "headers": {
            "Content-Type": "application/json"
          },
          "body": "{\"id\":1002,\"email\":\"other-user@example.com\",\"ssn\":\"***-**-1234\"...",
          "latency_ms": 42
        }
      },
      "description": "User A's JWT token was used to access User B's profile at /api/v1/users/{id}/profile. The server returned 200 with full profile data including PII. No object-level authorisation check is enforced.",
      "remediation": "Implement object-level authorisation. Verify that the authenticated user owns or has explicit permission to access the requested resource. Do not rely on obscurity of object IDs.",
      "references": [
        "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
      ],
      "confidence": "HIGH",
      "false_positive": false
    }
  ]
}
```

Response bodies in the `evidence` field are truncated to 4KB. Sensitive header values (cookies, authorization tokens) are partially redacted in the output. To disable redaction, pass `--no-redact`.

---

## SARIF Format (v2.1.0)

### What is SARIF

SARIF (Static Analysis Results Interchange Format) is an OASIS standard (v2.1.0) for encoding the output of static and dynamic analysis tools. APIGuard produces SARIF output that is consumed by:

- **GitHub Security tab** -- findings appear as code scanning alerts
- **Azure DevOps** -- results integrate into the Advanced Security dashboard
- **VS Code SARIF Viewer** -- browse findings in-editor with the SARIF Viewer extension
- **Any SARIF-compatible tool** -- the format is an open standard

### APIGuard to SARIF Mapping

| APIGuard Concept | SARIF Element | Notes |
|-----------------|---------------|-------|
| APIGuard tool info | `tool.driver` | Name, version, semantic version, information URI |
| Scan execution | `runs[0]` | One run per scan invocation |
| OWASP module | `tool.driver.rules[]` | Each module registers as a SARIF rule |
| Finding | `runs[0].results[]` | One result per finding |
| Severity | `results[].level` | Mapped: CRITICAL/HIGH -> `error`, MEDIUM -> `warning`, LOW/INFO -> `note` |
| CVSS score | `results[].properties.cvss_score` | Stored in property bag |
| Endpoint + method | `results[].locations[]` | Encoded as `physicalLocation` with `artifactLocation.uri` set to endpoint path |
| Evidence | `results[].properties.evidence` | Request/response stored in property bag |
| Remediation | `rules[].help` | Markdown-formatted help text on the rule |

### OWASP Module to SARIF Rule Mapping

Each OWASP module registers as a distinct rule in the SARIF `tool.driver.rules` array:

| Module | Rule ID | Short Description |
|--------|---------|-------------------|
| `a1_bola` | `apiguard/a1-bola` | Broken Object Level Authorization |
| `a2_auth` | `apiguard/a2-broken-auth` | Broken Authentication |
| `a3_mass_assignment` | `apiguard/a3-property-auth` | Broken Object Property Level Authorization |
| `a4_rate_limiting` | `apiguard/a4-resource-consumption` | Unrestricted Resource Consumption |
| `a5_function_auth` | `apiguard/a5-function-auth` | Broken Function Level Authorization |
| `a6_business_flow` | `apiguard/a6-business-flow` | Unrestricted Access to Sensitive Business Flows |
| `a7_ssrf` | `apiguard/a7-ssrf` | Server Side Request Forgery |
| `a8_misconfig` | `apiguard/a8-misconfig` | Security Misconfiguration |
| `a9_inventory` | `apiguard/a9-inventory` | Improper Inventory Management |
| `a10_unsafe_consumption` | `apiguard/a10-unsafe-consumption` | Unsafe Consumption of APIs |

### Example SARIF Snippet

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "APIGuard",
          "version": "0.4.0",
          "informationUri": "https://github.com/opensecstack/apiguard",
          "rules": [
            {
              "id": "apiguard/a1-bola",
              "name": "BrokenObjectLevelAuthorization",
              "shortDescription": {
                "text": "Broken Object Level Authorization (OWASP API1:2023)"
              },
              "help": {
                "text": "Implement object-level authorisation. Verify that the authenticated user owns or has explicit permission to access the requested resource.",
                "markdown": "**Remediation**: Implement object-level authorisation. Verify that the authenticated user owns or has explicit permission to access the requested resource."
              },
              "properties": {
                "owasp_id": "API1:2023"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "apiguard/a1-bola",
          "level": "error",
          "message": {
            "text": "BOLA: Horizontal access to user profile at GET /api/v1/users/{id}/profile"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "/api/v1/users/{id}/profile",
                  "uriBaseId": "API_ROOT"
                }
              },
              "properties": {
                "method": "GET"
              }
            }
          ],
          "properties": {
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
            "confidence": "HIGH",
            "evidence": {
              "request_url": "https://api.example.com/api/v1/users/1002/profile",
              "response_status": 200,
              "response_latency_ms": 42
            }
          }
        }
      ]
    }
  ]
}
```

### GitHub Code Scanning Integration

To upload SARIF results to GitHub:

```bash
apiguard scan --spec openapi.yaml --format sarif --output results.sarif
gh api -X POST /repos/{owner}/{repo}/code-scanning/sarifs \
  -f "commit_sha=$(git rev-parse HEAD)" \
  -f "ref=$(git symbolic-ref HEAD)" \
  -f "sarif=$(gzip -c results.sarif | base64 -w0)"
```

Or use the `apiguard/upload-sarif` GitHub Action step, which handles this automatically.

---

## HTML Format

The HTML report is a self-contained single-file document designed for human review. All CSS and images are inlined -- no external dependencies at render time.

### Report Sections

1. **Executive Summary** -- scan metadata, target URL, scan duration, pass/fail status, severity distribution chart.
2. **Findings by Severity** -- grouped tables: critical first, then high, medium, low, info. Each row links to the detail section.
3. **Finding Detail Pages** -- one section per finding containing:
   - Title, module, OWASP ID
   - CVSS 3.1 score with vector breakdown (Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, Confidentiality, Integrity, Availability)
   - Endpoint and HTTP method
   - Evidence: full request and response with syntax highlighting
   - Description
   - Remediation steps
   - External references
4. **Module Coverage Summary** -- which modules ran, which were skipped, endpoint coverage percentage.

### Custom Templates

Override the default HTML template with `--template`:

```bash
apiguard scan --spec openapi.yaml --format html --template ./my-template.html.j2
```

#### Jinja2 Template Variables

The following variables are available in the template context:

| Variable | Type | Description |
|----------|------|-------------|
| `scan` | object | Scan metadata (id, timestamp, duration, version, target, schema source) |
| `summary` | object | Finding counts by severity and module, pass/fail status |
| `findings` | list | All findings, each with full detail (see JSON schema above) |
| `findings_critical` | list | Findings filtered to CRITICAL severity |
| `findings_high` | list | Findings filtered to HIGH severity |
| `findings_medium` | list | Findings filtered to MEDIUM severity |
| `findings_low` | list | Findings filtered to LOW severity |
| `findings_info` | list | Findings filtered to INFO severity |
| `modules` | list | Module execution status (name, enabled, findings count, duration) |
| `generated_at` | string | Report generation timestamp (ISO 8601) |
| `apiguard_version` | string | APIGuard version string |

#### Template Example

```html+jinja
<!DOCTYPE html>
<html>
<head><title>{{ scan.target_url }} - APIGuard Report</title></head>
<body>
  <h1>Scan Results: {{ scan.target_url }}</h1>
  <p>Scanned at {{ scan.timestamp }} in {{ scan.duration_seconds }}s</p>
  <p>Status: {% if summary.pass %}PASS{% else %}FAIL{% endif %}</p>

  {% for finding in findings %}
  <div class="finding finding-{{ finding.severity | lower }}">
    <h2>{{ finding.title }}</h2>
    <span class="badge">{{ finding.severity }}</span>
    <span class="cvss">CVSS {{ finding.cvss_score }}</span>
    <p>{{ finding.description }}</p>
    <pre><code>{{ finding.evidence.request.method }} {{ finding.evidence.request.url }}</code></pre>
  </div>
  {% endfor %}
</body>
</html>
```

### Styling

The built-in template includes CSS for:

- Severity-coloured badges (critical: red, high: orange, medium: yellow, low: blue, info: grey)
- Syntax-highlighted request/response evidence blocks
- Responsive layout for screen and print media
- Dark mode via `prefers-color-scheme`

To override styles without replacing the entire template, use `--css`:

```bash
apiguard scan --spec openapi.yaml --format html --css ./company-branding.css
```

The custom CSS is appended after the built-in styles, so it takes precedence.

---

## PDF Format

> **Not wired up.** `--format pdf` is not a recognized format in the Go
> report pipeline (`internal/reporter/reporter.go`) — a real WeasyPrint
> implementation exists at `python/reporter/pdf_reporter.py`, but nothing
> in the Go CLI ever invokes it. Everything below describes the intended
> behavior once that's connected, not what running the command below does
> today.

The PDF report contains identical content to the HTML report. It is generated from the rendered HTML using [WeasyPrint](https://weasyprint.org/).

### Generation

```bash
apiguard scan --spec openapi.yaml --format pdf --output report.pdf
```

WeasyPrint is a Python dependency bundled with the APIGuard report generator. It renders the HTML template to PDF with:

- Print-optimised page layout (A4 by default, configurable with `--page-size`)
- Page headers with scan target and date
- Page footers with page numbers
- Automatic page breaks between finding detail sections
- Table of contents with hyperlinks

### Custom Templates

PDF generation uses the same Jinja2 template system as HTML. The `--template` and `--css` flags apply to PDF output as well:

```bash
apiguard scan --spec openapi.yaml --format pdf --template ./my-template.html.j2 --css ./print.css
```

### When to Use PDF

- Compliance audits requiring signed-off evidence documents
- Distribution to stakeholders without access to CI/CD or the APIGuard dashboard
- Archival in document management systems that require PDF format

---

## Format Comparison

| Use Case | Recommended Format | Reason |
|----------|--------------------|--------|
| CI/CD pipeline gate | SARIF | Native integration with GitHub Security, Azure DevOps. Triggers alerts and blocks merges. |
| CI/CD artifact storage | JSON | Structured, parseable, diffable. Feed into custom dashboards or trend analysis. |
| Human review | HTML | Visual layout, severity colours, expandable evidence sections. |
| Compliance / audit | PDF | Portable, print-ready, suitable for sign-off workflows. |
| IDE integration | SARIF | VS Code SARIF Viewer shows findings inline. |
| Custom tooling | JSON | Stable schema, easy to parse in any language. |
| Team distribution (email) | PDF or HTML | Self-contained, no tooling required to view. |
| Regression tracking | JSON | Diff JSON reports between scan runs to detect new/resolved findings. |

---

## Output Options

### Single Format

```bash
# Write JSON to file
apiguard scan --spec openapi.yaml --format json --output results.json

# Write SARIF to stdout (default behaviour for JSON and SARIF)
apiguard scan --spec openapi.yaml --format sarif

# Write HTML to file (required -- HTML cannot stream to stdout)
apiguard scan --spec openapi.yaml --format html --output report.html

# Write PDF to file (required -- PDF is binary)
apiguard scan --spec openapi.yaml --format pdf --output report.pdf
```

### Multiple Formats in One Scan

Generate multiple formats from a single scan run. The scan executes once; only report generation runs per format.

```bash
apiguard scan --spec openapi.yaml --format json,sarif,html --output ./reports/
```

When `--output` is a directory and multiple formats are requested, files are named automatically:

```
reports/
  apiguard-20260324-143208.json
  apiguard-20260324-143208.sarif
  apiguard-20260324-143208.html
```

### Stdout Behaviour

| Format | Default Output | `--output` Required |
|--------|---------------|---------------------|
| JSON | stdout | No |
| SARIF | stdout | No |
| HTML | N/A | Yes |
| PDF | N/A | Yes |

HTML and PDF require `--output` because they are not plain-text formats suitable for terminal display. Omitting `--output` for these formats produces an error with a descriptive message.

### Combining with CI/CD Exit Codes

The exit code is independent of report format. APIGuard returns:

| Exit Code | Meaning |
|-----------|---------|
| `0` | Scan completed, all findings below threshold |
| `1` | Scan completed, findings at or above threshold |
| `2` | Scan failed (network error, invalid schema, configuration error) |
| `3` | Scan failed (internal error) |

The threshold is controlled by `--fail-on`:

```bash
# Fail if any HIGH or CRITICAL findings exist
apiguard scan --spec openapi.yaml --format sarif --fail-on high

# Fail only on CRITICAL
apiguard scan --spec openapi.yaml --format json,sarif --fail-on critical
```
