# Custom Rules Guide

This document explains how to write, load, and manage custom security-check rules for
APIGuard. Custom rules extend the built-in OWASP API Top 10 modules with
organisation-specific or environment-specific checks that run in the same scan pipeline.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Configuration](#configuration)
- [YAML Rule File Format](#yaml-rule-file-format)
  - [Top-Level Structure](#top-level-structure)
  - [Rule Fields](#rule-fields)
  - [Check Fields](#check-fields)
- [Check Types Reference](#check-types-reference)
  - [header\_missing](#header_missing)
  - [header\_value](#header_value)
  - [status\_code](#status_code)
  - [response\_body\_contains](#response_body_contains)
  - [response\_body\_not\_contains](#response_body_not_contains)
  - [response\_time\_exceeds](#response_time_exceeds)
- [Endpoint Matching](#endpoint-matching)
- [Severity Values](#severity-values)
- [Example Rule File](#example-rule-file)
- [Rule Lifecycle](#rule-lifecycle)

---

## How It Works

At scan startup, APIGuard reads all `*.yaml` and `*.yml` files from the configured custom
rules directory. Each rule is validated, wrapped in a `CustomRuleModule`, and registered
in the same module registry as the built-in OWASP modules. Custom modules run in exactly
the same way as built-in modules: they receive the test-suite test cases, execute HTTP
requests against the target, and return findings that appear in the scan report.

Validation errors are emitted as warnings — they do not abort the scan. Rules that fail
validation are still registered; the scanner logs the problems and continues.

---

## Configuration

Set the directory containing your custom rule files using the environment variable:

```bash
export APIGUARD_CUSTOM_RULES_DIR=/path/to/your/rules
```

Or add it to `apiguard.yaml`:

```yaml
scanner:
  custom_rules_dir: "./custom-rules"
```

When `APIGUARD_CUSTOM_RULES_DIR` (or `scanner.custom_rules_dir`) is empty or unset,
no custom rules are loaded and only built-in modules run.

---

## YAML Rule File Format

### Top-Level Structure

Every rule file must use the `rules:` top-level key. A single file may contain one or
more rules.

```yaml
rules:
  - id: CR-001
    name: ...
    # ...
  - id: CR-002
    name: ...
    # ...
```

### Rule Fields

| Field         | Type     | Required | Description |
|---------------|----------|----------|-------------|
| `id`          | string   | Yes      | Unique identifier for the rule, e.g. `CR-001`. Must be unique across all loaded rules. |
| `name`        | string   | Yes      | Human-readable name shown in reports. |
| `description` | string   | No       | Longer explanation of what the rule checks. Used as the finding remediation hint. |
| `owasp_ref`   | string   | No       | OWASP API Top 10 reference, e.g. `API8:2023`. Appears on the finding as `OWASPId`. |
| `severity`    | string   | Yes      | One of `critical`, `high`, `medium`, `low`, `info` (case-insensitive). |
| `enabled`     | bool     | No       | Set to `false` to skip this rule at load time. Defaults to `true`. |
| `checks`      | list     | Yes      | One or more check definitions (see below). |

### Check Fields

| Field     | Type              | Required | Description |
|-----------|-------------------|----------|-------------|
| `type`    | string            | Yes      | The check category. See [Check Types Reference](#check-types-reference). |
| `target`  | string            | Yes      | Endpoint path pattern to match. Use `"*"` for all paths. |
| `method`  | string            | Yes      | HTTP method to match (e.g. `GET`, `POST`). Use `"*"` for all methods. |
| `params`  | map[string]string | Varies   | Type-specific parameters. See each check type for required keys. |
| `message` | string            | Yes      | The finding message emitted when this check triggers. |

---

## Check Types Reference

### header_missing

Raises a finding when the **response is missing** the named header.

**Use case:** Detect absent security headers (`X-Request-ID`, `Strict-Transport-Security`,
`X-Content-Type-Options`, etc.).

**Required params:**

| Param    | Description                  |
|----------|------------------------------|
| `header` | The response header to check |

**Example:**

```yaml
- type: header_missing
  target: "*"
  method: "*"
  params:
    header: X-Request-ID
  message: "Response is missing X-Request-ID header for request tracing"
```

---

### header_value

Raises a finding when the response header **does not match** the given regular expression.
Also triggers when the header is absent (empty value fails the pattern).

**Use case:** Enforce that security headers contain specific values
(e.g. HSTS with `max-age`, Content-Security-Policy with required directives).

**Required params:**

| Param     | Description                          |
|-----------|--------------------------------------|
| `header`  | The response header to inspect       |
| `pattern` | Go `regexp` pattern the value must match |

**Example:**

```yaml
- type: header_value
  target: "*"
  method: "GET"
  params:
    header: Strict-Transport-Security
    pattern: "max-age=\\d+"
  message: "Strict-Transport-Security header is absent or does not include max-age"
```

---

### status_code

Raises a finding when the response status code **is one of** the expected values.

**Use case:** Detect that an endpoint returns `200 OK` when it should return `401` or
`403`, or flag unexpected `500` responses that may reveal internal errors.

**Required params:**

| Param      | Description                                                             |
|------------|-------------------------------------------------------------------------|
| `expected` | Comma-separated list of status codes that trigger a finding, e.g. `200,201` |

**Example:**

```yaml
- type: status_code
  target: "/api/admin/users"
  method: "GET"
  params:
    expected: "200,201"
  message: "Admin endpoint returned 2xx without authentication — possible missing auth"
```

---

### response_body_contains

Raises a finding when the response body **contains** the given text string.

**Use case:** Security leak detection — flag responses that expose stack traces, debug
output, internal hostnames, secret key fragments, or other sensitive strings.

**Required params:**

| Param  | Description                              |
|--------|------------------------------------------|
| `text` | Literal string to search for in the body |

**Example:**

```yaml
- type: response_body_contains
  target: "*"
  method: "*"
  params:
    text: "stack trace"
  message: "Error response exposes internal stack trace"
```

---

### response_body_not_contains

Raises a finding when the response body **does not contain** the given text string.

**Use case:** Verify that required fields or tokens are present in a response. For
example, every authenticated response might be required to include a `"request_id"` field.

**Required params:**

| Param  | Description                                    |
|--------|------------------------------------------------|
| `text` | Literal string that must be present in the body |

**Example:**

```yaml
- type: response_body_not_contains
  target: "/api/v1/health"
  method: "GET"
  params:
    text: "\"status\""
  message: "Health endpoint response is missing required 'status' field"
```

---

### response_time_exceeds

Raises a finding when the response time **exceeds** the given threshold in milliseconds.

**Use case:** Detect potential denial-of-service vectors, algorithmic complexity bugs,
or missing database indexes that allow an attacker to trigger expensive operations.

**Required params:**

| Param | Description                                          |
|-------|------------------------------------------------------|
| `ms`  | Response time threshold in milliseconds (as a string) |

**Example:**

```yaml
- type: response_time_exceeds
  target: "*"
  method: "*"
  params:
    ms: "5000"
  message: "Response time exceeded 5000 ms — potential DoS indicator"
```

---

## Endpoint Matching

Each check's `target` and `method` fields control which test cases the check runs
against.

| Value       | Behaviour                                    |
|-------------|----------------------------------------------|
| `"*"`       | Matches every endpoint path or method        |
| `""`        | Treated as `"*"` (match all)                 |
| Any string  | Case-insensitive exact match against the path or method |

The scanner iterates over the test-suite test cases generated from the OpenAPI spec.
For each test case whose path matches `target` and whose method matches `method`, the
check is executed. The first matching test case that triggers a finding stops further
iteration for that check (one finding per check per scan is sufficient).

---

## Severity Values

The `severity` field must be one of the following values (case-insensitive):

| Value      | Maps to                   |
|------------|---------------------------|
| `critical` | `domain.SeverityCritical` |
| `high`     | `domain.SeverityHigh`     |
| `medium`   | `domain.SeverityMedium`   |
| `low`      | `domain.SeverityLow`      |
| `info`     | `domain.SeverityInfo`     |

Unrecognised severity strings default to `info`.

---

## Example Rule File

The file at `custom-rules/example.yaml` in the repository demonstrates all check types:

```yaml
rules:
  - id: CR-001
    name: Missing X-Request-ID Header
    description: >
      API responses should include an X-Request-ID header so that individual
      requests can be correlated across logs, traces, and client-side error reports.
    owasp_ref: API8:2023
    severity: low
    enabled: true
    checks:
      - type: header_missing
        target: "*"
        method: "*"
        params:
          header: X-Request-ID
        message: "Response is missing X-Request-ID header for request tracing"

  - id: CR-002
    name: Sensitive Data in Error Response
    description: >
      Error responses must not expose internal stack traces or debug info.
    owasp_ref: API8:2023
    severity: high
    enabled: true
    checks:
      - type: response_body_contains
        target: "*"
        method: "*"
        params:
          text: "stack trace"
        message: "Error response exposes internal stack trace"
```

To use it:

```bash
export APIGUARD_CUSTOM_RULES_DIR=./custom-rules
apiguard scan --spec ./openapi.yaml --target https://api.example.com
```

---

## Rule Lifecycle

### Load order

1. APIGuard's built-in OWASP modules are always registered first.
2. If `APIGUARD_CUSTOM_RULES_DIR` (or `scanner.custom_rules_dir`) is set, all `*.yaml`
   and `*.yml` files in that directory are read in filesystem order.
3. Rules are validated. Validation warnings are logged but do not prevent the rule from
   running.
4. Enabled rules are registered in the module registry. If a custom rule's `id` collides
   with a built-in module's `id`, the last registration wins (custom rules loaded later
   can override built-ins).

### Disabling a rule

Set `enabled: false` in the rule YAML:

```yaml
rules:
  - id: CR-001
    enabled: false
    # ...
```

Disabled rules are skipped at load time and do not run.

### Targeting specific modules

Use the `--modules` flag to run only named modules. Custom rule IDs can be passed just
like built-in module IDs:

```bash
apiguard scan --spec ./openapi.yaml --target https://api.example.com \
  --modules CR-001,CR-002,a1_bola
```

### Findings

Custom rule findings appear in the scan report alongside built-in module findings. Each
finding includes:

- `module_id` — the rule's `id`
- `owasp_id` — the rule's `owasp_ref` (empty if not set)
- `title` — `[<id>] <name>`, e.g. `[CR-001] Missing X-Request-ID Header`
- `description` — the check's `message`
- `severity` — mapped from the rule's `severity`
- `remediation` — the rule's `description`
- `evidence.request` — the HTTP method and URL that triggered the finding
- `evidence.response` — the HTTP status code and response time
- `evidence.detail` — structured data specific to the check type
