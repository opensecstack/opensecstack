# Custom Rule Writing Guide

This document covers how to write, test, and manage custom rules for APIGuard. Custom rules extend the built-in OWASP API Top 10 modules with organisation-specific checks.

## Table of Contents

- [Rule Anatomy](#rule-anatomy)
- [YAML Rule Definition Format](#yaml-rule-definition-format)
- [Built-in Rule Helpers](#built-in-rule-helpers)
- [Testing Custom Rules](#testing-custom-rules)
- [Rule Lifecycle](#rule-lifecycle)
- [Example: API Versioning Header Check](#example-api-versioning-header-check)

---

## Rule Anatomy

Every rule consists of four components. These map directly to the APIGuard pipeline: L2 (test generation), L3 (execution), L5 (response analysis), and L6 (CVSS scoring).

### Rule Metadata

Metadata identifies and classifies the rule within the scan pipeline.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier. Custom rules must use the prefix `custom-`. Example: `custom-api-version-header`. |
| `name` | string | Yes | Human-readable name. Appears in reports and dashboard. |
| `severity` | enum | Yes | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`. |
| `owasp_category` | string | No | Maps to OWASP API Top 10 ID (e.g., `A8`). Use `CUSTOM` for rules outside the Top 10. |
| `description` | string | Yes | What the rule checks. One or two sentences. |
| `remediation` | string | Yes | What the developer should do to fix the finding. |
| `tags` | list | No | Arbitrary tags for filtering. Example: `[headers, compliance, internal]`. |
| `version` | string | No | Rule version. Defaults to `1.0.0`. Used for override precedence. |
| `author` | string | No | Rule author for attribution in reports. |

### Test Case Generator

The test case generator produces HTTP requests that the Go execution layer sends to the target API. Each rule defines:

- **Match conditions** -- which endpoints the rule applies to (path patterns, HTTP methods, parameter types).
- **Payloads** -- the HTTP requests to generate, including variable substitution from the APIGuard IR.

The Rust test generation layer (L2) evaluates match conditions against the parsed schema IR. For every matching endpoint, it produces one or more test case specs (JSON) that the Go HTTP client executes.

### Response Analyser

The response analyser (L5, Rust) evaluates the HTTP responses returned by the Go execution layer. It checks:

- Status codes (exact match, ranges, or negation).
- Header presence, absence, or value patterns.
- Body content patterns (regex or literal).
- Timing thresholds (response time comparisons).
- Response diffs (comparing two responses for unintended data leakage).

Each check produces a boolean result. The rule defines how checks combine (`all`, `any`, or `none`) to determine whether a finding is raised.

### CVSS Vector

Every rule includes a CVSS 3.1 base vector string. The L6 CVSS Scorer uses this to calculate a numeric score. The severity field in metadata must align with the CVSS range:

| Severity | CVSS Range |
|----------|-----------|
| CRITICAL | 9.0 -- 10.0 |
| HIGH | 7.0 -- 8.9 |
| MEDIUM | 4.0 -- 6.9 |
| LOW | 0.1 -- 3.9 |
| INFO | 0.0 |

```
cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
```

If severity and CVSS score conflict, `apiguard rule validate` will reject the rule.

---

## YAML Rule Definition Format

Custom rules are YAML files placed in the `.apiguard/rules/` directory at the root of your project, or in a directory specified by the `APIGUARD_RULES_DIR` environment variable.

### Full Example

```yaml
# .apiguard/rules/custom-api-version-header.yaml

rule:
  id: "custom-api-version-header"
  name: "API Versioning Header Missing"
  version: "1.0.0"
  severity: LOW
  owasp_category: A9
  description: >
    Checks that all API responses include an X-API-Version header.
    Missing version headers make API inventory management unreliable
    and complicate deprecation tracking.
  remediation: >
    Add an X-API-Version header to all API responses. The value should
    match the version declared in the OpenAPI specification.
  tags:
    - headers
    - inventory
    - compliance
  author: "security-team"

  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

match:
  endpoints:
    - pattern: "/**"           # glob pattern against endpoint path
  methods:
    - GET
    - POST
    - PUT
    - PATCH
    - DELETE
  parameters: []               # no parameter constraints
  exclude:
    - pattern: "/health"
    - pattern: "/ready"

payloads:
  - name: "standard-request"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Accept: "application/json"
    body: null
    variables:
      - source: endpoint
        fields: [method, path]
    auth: inherit               # use scan-level auth config

response_checks:
  mode: all                     # all checks must pass to NOT raise a finding
  checks:
    - type: header_present
      header: "X-API-Version"
      on_fail: finding          # raise finding if header absent

    - type: header_value
      header: "X-API-Version"
      pattern: "^\\d+\\.\\d+(\\.\\d+)?$"
      on_fail: finding          # raise finding if value is not semver

finding:
  title: "Missing or invalid X-API-Version header on {{endpoint.method}} {{endpoint.path}}"
  description: >
    The endpoint {{endpoint.method}} {{endpoint.path}} does not return
    a valid X-API-Version header. This makes it impossible to track
    which API version is serving traffic.
  evidence:
    format: |
      Request:  {{request.method}} {{request.url}}
      Status:   {{response.status}}
      Headers:  {{response.headers | json}}
    include_response_headers: true
    include_response_body: false
  remediation: >
    Set the X-API-Version response header to the current API version
    string (e.g., "2.1.0").
```

### Field Reference

#### `match` Block

Controls which endpoints the rule runs against.

| Field | Type | Description |
|-------|------|-------------|
| `endpoints[].pattern` | glob | Path pattern. Supports `*` (single segment) and `**` (any depth). |
| `methods` | list | HTTP methods to include. Omit to match all methods. |
| `parameters` | list | Filter by parameter presence. See below. |
| `exclude[].pattern` | glob | Paths to skip, evaluated after inclusion. |

Parameter matching:

```yaml
parameters:
  - name: "id"
    location: path             # path | query | header | cookie
    type: integer              # matches OpenAPI schema type

  - location: query
    type: string
    name_pattern: ".*_url$"    # regex against parameter name
```

#### `payloads` Block

Each payload entry generates one HTTP request per matching endpoint.

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Identifier for this payload. Referenced in response checks. |
| `method` | string/template | HTTP method. Use `{{endpoint.method}}` to match the endpoint. |
| `path` | string/template | Request path. Use `{{endpoint.path}}` for the endpoint path. |
| `headers` | map | Static or templated headers to send. |
| `body` | string/template/null | Request body. Supports `{{payload.*}}` for injection helpers. |
| `query_params` | map | Additional query parameters to append. |
| `variables[].source` | enum | `endpoint`, `auth`, `schema`, `env`. |
| `variables[].fields` | list | Fields to extract from the source. |
| `auth` | enum | `inherit` (use scan auth), `none` (no auth), or a named auth profile. |
| `delay_ms` | integer | Milliseconds to wait before sending. Used for timing tests. |

Variable substitution uses double-brace syntax: `{{source.field}}`. Available variables:

```
{{endpoint.method}}          HTTP method from schema
{{endpoint.path}}            Path from schema, with path params filled
{{endpoint.base_url}}        Base URL from schema servers[0]
{{auth.token}}               Current auth token
{{auth.header}}              Full auth header value (e.g., "Bearer xyz")
{{schema.version}}           API version from info.version
{{env.VARIABLE_NAME}}        Environment variable
{{param.name}}               Named parameter value (from parameter matching)
{{payload.sqli.basic}}       Built-in SQLi payload (see helpers)
{{payload.xss.reflected}}    Built-in XSS payload (see helpers)
{{payload.ssrf.localhost}}   Built-in SSRF payload (see helpers)
{{uuid.random}}              Random UUID v4
{{timestamp.now}}            Current UTC timestamp (ISO 8601)
{{random.string.16}}         Random alphanumeric string of length 16
```

#### `response_checks` Block

| Field | Type | Description |
|-------|------|-------------|
| `mode` | enum | `all` -- all checks must pass (logical AND). `any` -- at least one must pass (logical OR). `none` -- no check may pass (logical NOR). |
| `checks[].type` | enum | See check types below. |
| `checks[].on_fail` | enum | `finding` -- raise a finding. `skip` -- skip silently. |
| `checks[].severity_override` | enum | Override rule severity for this specific check. |

Check types:

| Type | Parameters | Description |
|------|-----------|-------------|
| `status_code` | `value`, `range`, `not` | Match exact code, range (`200-299`), or negation. |
| `header_present` | `header` | Header exists in response. |
| `header_absent` | `header` | Header does not exist in response. |
| `header_value` | `header`, `pattern` | Header value matches regex. |
| `body_contains` | `pattern` | Response body matches regex. |
| `body_not_contains` | `pattern` | Response body does not match regex. |
| `body_json_path` | `path`, `value`, `pattern` | JSONPath expression matches value or pattern. |
| `timing` | `max_ms`, `min_ms` | Response time within threshold. |
| `response_diff` | `baseline`, `max_similarity` | Compare response to a baseline payload's response. |
| `response_size` | `max_bytes`, `min_bytes` | Response body size bounds. |

#### `finding` Block

| Field | Type | Description |
|-------|------|-------------|
| `title` | string/template | Finding title. Supports variable substitution. |
| `description` | string/template | Detailed description of the issue. |
| `evidence.format` | string/template | Evidence string included in the report. |
| `evidence.include_response_headers` | bool | Attach full response headers. |
| `evidence.include_response_body` | bool | Attach response body (truncated to 4KB). |
| `evidence.max_body_size` | integer | Override body truncation limit (bytes). |
| `remediation` | string | Fix instructions. Overrides the rule-level remediation if set. |

---

## Built-in Rule Helpers

APIGuard provides helper functions accessible within payload templates and response checks. These are implemented in the Rust L2/L5 layers.

### Token Manipulation

Used for authentication bypass and privilege escalation testing.

```yaml
payloads:
  # Remove auth entirely
  - name: "no-auth"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    auth: none

  # Use an expired token
  - name: "expired-token"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Authorization: "{{auth.token | expire}}"

  # Swap to a different user's token
  - name: "swapped-user"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Authorization: "{{auth.token | swap_user: 'low_privilege'}}"

  # Tamper with JWT claims without re-signing
  - name: "tampered-jwt"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Authorization: "{{auth.token | jwt_tamper: 'role', 'admin'}}"

  # Use algorithm none attack
  - name: "alg-none"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Authorization: "{{auth.token | jwt_alg_none}}"
```

Token helper reference:

| Helper | Description |
|--------|-------------|
| `expire` | Set JWT `exp` claim to a past timestamp. |
| `swap_user: '<profile>'` | Replace token with one from a named auth profile. |
| `jwt_tamper: '<claim>', '<value>'` | Modify a JWT claim and re-encode without valid signature. |
| `jwt_alg_none` | Set JWT algorithm to `none` and strip signature. |
| `strip_bearer` | Remove `Bearer ` prefix from token. |

### ID Enumeration

Used for BOLA (A1) and IDOR testing.

```yaml
payloads:
  # Sequential integer IDs
  - name: "enum-sequential"
    method: GET
    path: "/api/users/{{param.id | enumerate: 1, 100, 1}}"

  # UUID prediction (nearby UUIDs)
  - name: "enum-uuid"
    method: GET
    path: "/api/resources/{{param.id | uuid_adjacent: 10}}"

  # Replace path ID with another user's known ID
  - name: "other-user-resource"
    method: GET
    path: "{{endpoint.path | replace_id: 'other_user_id_1'}}"
```

ID helper reference:

| Helper | Parameters | Description |
|--------|-----------|-------------|
| `enumerate` | `start, end, step` | Generate sequential values. |
| `uuid_adjacent` | `count` | Generate UUIDs close to the original in time-based sequence. |
| `replace_id` | `named_value` | Substitute path parameter with a value from auth profile or env. |
| `random_id` | `count` | Generate random IDs of the same format as the original. |

### Payload Injection

Pre-built attack payloads for common injection categories.

```yaml
payloads:
  # SQL injection in query parameter
  - name: "sqli-query"
    method: GET
    path: "{{endpoint.path}}"
    query_params:
      search: "{{payload.sqli.basic}}"

  # XSS in JSON body field
  - name: "xss-body"
    method: POST
    path: "{{endpoint.path}}"
    body: |
      {"name": "{{payload.xss.reflected}}"}

  # SSRF in URL parameter
  - name: "ssrf-url"
    method: POST
    path: "{{endpoint.path}}"
    body: |
      {"callback_url": "{{payload.ssrf.localhost}}"}
```

Available payload sets:

| Namespace | Payloads | Description |
|-----------|---------|-------------|
| `payload.sqli.basic` | `' OR 1=1--` and variants | Basic SQL injection probes. |
| `payload.sqli.union` | `UNION SELECT` variants | Union-based extraction probes. |
| `payload.sqli.time` | `SLEEP()`, `WAITFOR` variants | Time-based blind SQLi. |
| `payload.xss.reflected` | `<script>`, event handlers | Reflected XSS probes. |
| `payload.xss.stored` | Persistent XSS payloads | Stored XSS probes. |
| `payload.ssrf.localhost` | `http://127.0.0.1`, `http://[::1]` | Localhost SSRF. |
| `payload.ssrf.metadata` | Cloud metadata URLs | AWS/GCP/Azure metadata endpoints. |
| `payload.ssrf.dns_rebind` | DNS rebinding payloads | DNS rebinding SSRF. |
| `payload.path_traversal` | `../` sequences | Path traversal payloads. |
| `payload.crlf` | `%0d%0a` sequences | CRLF injection payloads. |
| `payload.template` | `{{7*7}}`, `${7*7}` | Server-side template injection. |

### Response Comparison

Compare two responses to detect data leakage or access control failures.

```yaml
payloads:
  - name: "authed-request"
    method: GET
    path: "{{endpoint.path}}"
    auth: inherit

  - name: "unauthed-request"
    method: GET
    path: "{{endpoint.path}}"
    auth: none

response_checks:
  mode: any
  checks:
    - type: response_diff
      baseline: "authed-request"
      compare: "unauthed-request"
      max_similarity: 0.95       # flag if responses are >95% similar
      on_fail: finding
      severity_override: HIGH

    - type: body_json_path
      payload: "unauthed-request"
      path: "$.data"
      value: null                # body should have no data field
      on_fail: finding
```

The `response_diff` check uses a normalised similarity score (0.0 to 1.0). A score above `max_similarity` means the unauthenticated response contains nearly the same data as the authenticated one -- a strong indicator of broken access control.

### Timing Analysis

Detect timing-based information leaks (e.g., user enumeration via login response times).

```yaml
payloads:
  - name: "valid-user"
    method: POST
    path: "/api/auth/login"
    body: |
      {"username": "{{env.VALID_USER}}", "password": "wrong"}

  - name: "invalid-user"
    method: POST
    path: "/api/auth/login"
    body: |
      {"username": "nonexistent_user_abc123", "password": "wrong"}

response_checks:
  mode: any
  checks:
    - type: timing
      payload: "valid-user"
      compare_payload: "invalid-user"
      max_delta_ms: 50           # flag if difference exceeds 50ms
      samples: 10                # repeat each request 10 times, use median
      on_fail: finding
```

Timing check parameters:

| Parameter | Description |
|-----------|-------------|
| `max_ms` | Absolute max response time (single payload). |
| `min_ms` | Absolute min response time (single payload). |
| `max_delta_ms` | Max allowed difference between two payloads' median response times. |
| `samples` | Number of repetitions for statistical significance. Default: 5. |
| `warmup` | Number of warmup requests to discard. Default: 1. |

---

## Testing Custom Rules

APIGuard provides CLI commands for validating and testing rules before using them in scans.

### Validate Rule Syntax

Check that a rule file is well-formed, all required fields are present, CVSS vector parses correctly, and severity aligns with the CVSS score.

```bash
apiguard rule validate ./my-rule.yaml
```

Output on success:

```
[OK] Rule 'custom-api-version-header' (v1.0.0)
     Severity: LOW (CVSS 0.0 - matches)
     Matches: all endpoints, methods: GET,POST,PUT,PATCH,DELETE
     Excludes: /health, /ready
     Payloads: 1
     Checks: 2
     Finding template: valid
```

Output on failure:

```
[ERROR] Rule 'custom-api-version-header'
        Line 8: severity HIGH does not match CVSS vector score 0.0 (expected LOW or INFO)
        Line 31: unknown check type 'header_presnt' (did you mean 'header_present'?)
```

Validate all rules in a directory:

```bash
apiguard rule validate .apiguard/rules/
```

### Test Against a Live Target

Run a single rule against a target API and display findings in the terminal.

```bash
apiguard rule test ./my-rule.yaml --target http://localhost:8080
```

Options:

| Flag | Description |
|------|-------------|
| `--target` | Target base URL. Required. |
| `--spec` | OpenAPI spec path. If omitted, only explicit paths in the rule are tested. |
| `--auth-token` | Bearer token for authenticated requests. |
| `--auth-profile` | Named auth profile from `apiguard.yaml`. |
| `--verbose` | Show full request/response pairs. |
| `--output` | Output format: `text` (default), `json`, `sarif`. |
| `--timeout` | Per-request timeout in seconds. Default: 30. |

Example with an OpenAPI spec:

```bash
apiguard rule test ./my-rule.yaml \
  --target http://localhost:8080 \
  --spec ./openapi.yaml \
  --auth-token "$API_TOKEN" \
  --verbose
```

### Dry Run

Show the generated HTTP requests without sending them. Useful for verifying that match conditions and payload templates produce the expected requests.

```bash
apiguard rule dry-run ./my-rule.yaml --spec ./openapi.yaml
```

Output:

```
Rule: custom-api-version-header (v1.0.0)
Matched 14 endpoints (excluded 2)

[1] GET /api/users
    Headers: Accept: application/json, Authorization: Bearer <redacted>
    Body: (none)

[2] POST /api/users
    Headers: Accept: application/json, Authorization: Bearer <redacted>
    Body: (none)

[3] GET /api/users/{id}
    Headers: Accept: application/json, Authorization: Bearer <redacted>
    Body: (none)

... (11 more)

Total requests that would be sent: 14
```

Add `--show-auth` to display full auth tokens in dry-run output (for debugging auth issues).

---

## Rule Lifecycle

### Load Order

Rules are loaded in a defined order. Later rules override earlier ones if they share the same `id`.

1. **Built-in rules** -- Bundled with the APIGuard binary. These implement the OWASP API Top 10 modules.
2. **Project rules** -- From `.apiguard/rules/` in the project root.
3. **User rules** -- From `$APIGUARD_RULES_DIR` if set.
4. **CLI rules** -- Passed via `--rules` flag.

```bash
apiguard scan --spec ./openapi.yaml --rules ./extra-rules/
```

### Override Built-in Rules

To override a built-in rule, create a custom rule with the same `id` and place it in `.apiguard/rules/`. The custom version replaces the built-in.

```yaml
# .apiguard/rules/a8-override-cors.yaml
rule:
  id: "a8-cors-misconfiguration"    # same ID as the built-in
  name: "CORS Misconfiguration (Custom)"
  severity: HIGH                     # upgrade severity from MEDIUM
  # ... rest of the rule
```

To verify which version is active:

```bash
apiguard rule list --show-source
```

```
ID                          Source              Version
a1-bola-horizontal          built-in            3.2.0
a2-missing-auth             built-in            3.2.0
a8-cors-misconfiguration    .apiguard/rules/    1.0.0    (overrides built-in)
custom-api-version-header   .apiguard/rules/    1.0.0
```

### Disable Rules

Disable rules in `apiguard.yaml` or via CLI flags.

In configuration:

```yaml
# apiguard.yaml
rules:
  disabled:
    - "a4-rate-limiting"           # disable by ID
    - "custom-api-version-header"
```

Via CLI:

```bash
apiguard scan --spec ./openapi.yaml --disable-rules a4-rate-limiting,custom-api-version-header
```

To disable all custom rules and run only built-ins:

```bash
apiguard scan --spec ./openapi.yaml --builtin-only
```

### Enable-Only Mode

Run only specific rules:

```bash
apiguard scan --spec ./openapi.yaml --only-rules custom-api-version-header,a1-bola-horizontal
```

---

## Example: API Versioning Header Check

This complete example checks that all API responses include a valid `X-API-Version` header. It maps to OWASP A9 (Improper Inventory Management) because missing version headers indicate poor API lifecycle management.

Create the file `.apiguard/rules/custom-api-version-header.yaml`:

```yaml
rule:
  id: "custom-api-version-header"
  name: "API Versioning Header Missing"
  version: "1.0.0"
  severity: LOW
  owasp_category: A9
  description: >
    Checks that all API responses include an X-API-Version header with
    a valid semver value. Missing version headers make API inventory
    management unreliable and complicate deprecation tracking.
  remediation: >
    Configure your API gateway or application middleware to set the
    X-API-Version response header on all endpoints. The value should
    follow semantic versioning (e.g., 2.1.0) and match the version
    declared in the OpenAPI specification.
  tags:
    - headers
    - inventory
    - compliance
    - a9
  author: "security-team"

  cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"

match:
  endpoints:
    - pattern: "/**"
  methods:
    - GET
    - POST
    - PUT
    - PATCH
    - DELETE
  exclude:
    - pattern: "/health"
    - pattern: "/ready"
    - pattern: "/metrics"
    - pattern: "/docs/**"
    - pattern: "/swagger**"

payloads:
  - name: "standard-request"
    method: "{{endpoint.method}}"
    path: "{{endpoint.path}}"
    headers:
      Accept: "application/json"
    auth: inherit

response_checks:
  mode: all
  checks:
    - type: status_code
      range: "200-499"
      on_fail: skip              # skip if server error (5xx)

    - type: header_present
      header: "X-API-Version"
      on_fail: finding

    - type: header_value
      header: "X-API-Version"
      pattern: "^\\d+\\.\\d+(\\.\\d+)?$"
      on_fail: finding

finding:
  title: "Missing or invalid X-API-Version header on {{endpoint.method}} {{endpoint.path}}"
  description: >
    The endpoint {{endpoint.method}} {{endpoint.path}} returned a response
    without a valid X-API-Version header. API responses should include this
    header to enable version tracking, deprecation enforcement, and inventory
    management. This is especially important in environments with multiple
    API versions running concurrently.
  evidence:
    format: |
      Request:  {{request.method}} {{request.url}}
      Status:   {{response.status}}
      X-API-Version header: {{response.headers.X-API-Version | default: "(absent)"}}
    include_response_headers: true
    include_response_body: false
  remediation: >
    Add middleware or gateway configuration to set the X-API-Version header.

    Example (Express.js):
      app.use((req, res, next) => {
        res.setHeader('X-API-Version', '2.1.0');
        next();
      });

    Example (Go chi):
      r.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
          w.Header().Set("X-API-Version", "2.1.0")
          next.ServeHTTP(w, r)
        })
      })
```

Validate and test it:

```bash
# Validate syntax and consistency
apiguard rule validate .apiguard/rules/custom-api-version-header.yaml

# Preview generated requests against your spec
apiguard rule dry-run .apiguard/rules/custom-api-version-header.yaml \
  --spec ./openapi.yaml

# Run against local target
apiguard rule test .apiguard/rules/custom-api-version-header.yaml \
  --target http://localhost:8080 \
  --spec ./openapi.yaml \
  --auth-token "$API_TOKEN" \
  --verbose

# Include in a full scan
apiguard scan \
  --spec ./openapi.yaml \
  --target http://localhost:8080 \
  --output json
```
