# Configuration Reference

APIGuard is configured through three mechanisms. When the same setting is specified in more than one place, the highest-precedence source wins:

```
CLI flags  >  Environment variables  >  Config file (.apiguard.yaml)  >  Built-in defaults
```

This document covers every configurable setting across all three sources.

---

## Configuration File

APIGuard looks for `.apiguard.yaml` in the following locations, in order:

1. Path specified by `--config` flag
2. Current working directory (`./.apiguard.yaml`)
3. Home directory (`~/.apiguard.yaml`)
4. `/etc/apiguard/.apiguard.yaml`

### Full Example

```yaml
# .apiguard.yaml — APIGuard configuration file

# ---------------------------------------------------------------------------
# Scanner settings
# ---------------------------------------------------------------------------
scanner:
  concurrency: 10              # Max concurrent HTTP requests to the target
  timeout_seconds: 30          # Per-request timeout
  max_spec_size_mb: 10         # Reject schemas larger than this
  rate_limit_rps: 50           # Max requests per second to the target
  follow_redirects: true       # Follow HTTP 3xx redirects
  tls_skip_verify: false       # Skip TLS certificate verification (use only in dev)

# ---------------------------------------------------------------------------
# OWASP modules — enable or disable individual A1–A10 modules
# ---------------------------------------------------------------------------
modules:
  a1_bola:
    enabled: true
    # Requires at least 2 auth tokens for cross-user testing
    extra_tokens:
      - "${APIGUARD_TOKEN_USER_B}"
  a2_auth:
    enabled: true
  a3_mass_assignment:
    enabled: true
  a4_rate_limiting:
    enabled: true
    threshold_rps: 100         # Requests/sec before rate limiting is expected
  a5_function_auth:
    enabled: true
    admin_tags:                # OpenAPI tags that indicate admin-only endpoints
      - admin
      - internal
  a6_business_flow:
    enabled: false             # Disabled by default — requires manual config
    sensitive_endpoints:
      - POST /api/v1/orders
      - POST /api/v1/payments
  a7_ssrf:
    enabled: true
    oast_url: ""               # Out-of-band application security testing URL
  a8_misconfig:
    enabled: true
  a9_inventory:
    enabled: true
    version_paths:             # Additional version prefixes to probe
      - /v1
      - /v2
      - /v3
      - /internal
  a10_unsafe_consumption:
    enabled: false             # Disabled by default — requires OAST setup
    oast_url: ""

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------
auth:
  type: bearer                 # One of: jwt, oauth2, apikey, basic, bearer
  token: "${APIGUARD_AUTH_TOKEN}"

  # --- JWT-specific ---
  jwt:
    secret: "${APIGUARD_JWT_SECRET}"
    algorithm: HS256           # HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
    issuer: ""
    audience: ""
    expiry_seconds: 3600

  # --- OAuth2-specific ---
  oauth2:
    token_url: ""
    client_id: ""
    client_secret: "${APIGUARD_OAUTH2_CLIENT_SECRET}"
    scopes:
      - read
      - write
    grant_type: client_credentials  # client_credentials, authorization_code, password

  # --- API key-specific ---
  apikey:
    header: X-API-Key          # Header name for the API key
    value: "${APIGUARD_API_KEY}"

  # --- Basic auth-specific ---
  basic:
    username: "${APIGUARD_BASIC_USER}"
    password: "${APIGUARD_BASIC_PASS}"

# ---------------------------------------------------------------------------
# Report output
# ---------------------------------------------------------------------------
report:
  format: json                 # html, pdf, json, sarif
  output_dir: ./reports        # Directory for report files
  template: ""                 # Path to custom Jinja2 template (HTML/PDF only)
  include_evidence: true       # Include raw HTTP request/response evidence
  include_remediation: true    # Include remediation guidance per finding

# ---------------------------------------------------------------------------
# Database (L8 Persistence)
# ---------------------------------------------------------------------------
database:
  url: "${APIGUARD_DB_URL}"
  max_open_conns: 25
  max_idle_conns: 5
  conn_max_lifetime_seconds: 300
  auto_migrate: true           # Run schema migrations on startup
  ssl_mode: disable            # disable, require, verify-ca, verify-full

# ---------------------------------------------------------------------------
# Dashboard (L9)
# ---------------------------------------------------------------------------
dashboard:
  enabled: true
  port: 3000
  api_port: 8080               # Port for the APIGuard API server
  cors_origins:
    - "http://localhost:3000"
  session_timeout_minutes: 60

# ---------------------------------------------------------------------------
# CITADEL integration (optional)
# ---------------------------------------------------------------------------
citadel:
  enabled: false
  webhook_url: ""              # CITADEL ingest endpoint
  api_key: "${CITADEL_API_KEY}"
  emit_events:
    - scan_started
    - scan_completed
    - finding_critical
    - finding_high
  verify_tls: true

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
log:
  level: info                  # trace, debug, info, warn, error
  format: text                 # text, json
  output: stderr               # stderr, stdout, or a file path
```

---

## Environment Variables

Every environment variable is prefixed with `APIGUARD_`. Variables map directly to config file fields.

| Variable | Config File Equivalent | Type | Default | Description |
|----------|----------------------|------|---------|-------------|
| `APIGUARD_DB_URL` | `database.url` | string | (none) | PostgreSQL connection string. Required for persistence and dashboard. |
| `APIGUARD_JWT_SECRET` | `auth.jwt.secret` | string | (none) | Secret for signing/verifying JWT tokens. |
| `APIGUARD_PORT` | `dashboard.api_port` | int | `8080` | Port for the APIGuard API server. |
| `APIGUARD_LOG_LEVEL` | `log.level` | string | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error`. |
| `APIGUARD_REDIS_URL` | (internal) | string | `redis://localhost:6379` | Redis connection string. Used for scan job queuing and caching. |
| `APIGUARD_AUTH_TOKEN` | `auth.token` | string | (none) | Bearer/JWT token for authenticating against the target API. |
| `APIGUARD_AUTH_TYPE` | `auth.type` | string | `bearer` | Auth type: `jwt`, `oauth2`, `apikey`, `basic`, `bearer`. |
| `APIGUARD_API_KEY` | `auth.apikey.value` | string | (none) | API key value when `auth.type` is `apikey`. |
| `APIGUARD_BASIC_USER` | `auth.basic.username` | string | (none) | Username for HTTP Basic auth. |
| `APIGUARD_BASIC_PASS` | `auth.basic.password` | string | (none) | Password for HTTP Basic auth. |
| `APIGUARD_OAUTH2_CLIENT_SECRET` | `auth.oauth2.client_secret` | string | (none) | OAuth2 client secret. |
| `APIGUARD_CONCURRENCY` | `scanner.concurrency` | int | `10` | Maximum concurrent HTTP requests. |
| `APIGUARD_TIMEOUT` | `scanner.timeout_seconds` | int | `30` | Per-request timeout in seconds. |
| `APIGUARD_RATE_LIMIT` | `scanner.rate_limit_rps` | int | `50` | Maximum requests per second to the target. |
| `APIGUARD_TLS_SKIP_VERIFY` | `scanner.tls_skip_verify` | bool | `false` | Skip TLS certificate verification. |
| `APIGUARD_REPORT_FORMAT` | `report.format` | string | `json` | Default report format. |
| `APIGUARD_REPORT_DIR` | `report.output_dir` | string | `./reports` | Default report output directory. |
| `APIGUARD_DASHBOARD_PORT` | `dashboard.port` | int | `3000` | Dashboard UI port. |
| `CITADEL_API_KEY` | `citadel.api_key` | string | (none) | API key for CITADEL webhook authentication. |
| `CITADEL_WEBHOOK_URL` | `citadel.webhook_url` | string | (none) | CITADEL event ingest endpoint. |

---

## CLI Flags

All flags are passed to the `apiguard scan` command unless noted otherwise.

| Flag | Short | Type | Default | Config Equivalent | Description |
|------|-------|------|---------|-------------------|-------------|
| `--spec` | `-s` | string | (required) | (none) | Path or URL to OpenAPI/Swagger/GraphQL schema. |
| `--target` | `-t` | string | (required) | (none) | Base URL of the live API to test. |
| `--format` | `-f` | string | `json` | `report.format` | Output format: `html`, `pdf`, `json`, `sarif`. |
| `--output` | `-o` | string | stdout | `report.output_dir` | File path for report output. Writes to stdout when omitted. |
| `--fail-on` | | string | `HIGH` | (none) | Minimum severity that causes a non-zero exit code. Values: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`. |
| `--modules` | `-m` | string | (all enabled) | `modules.*` | Comma-separated list of modules to run. Example: `a1_bola,a2_auth,a8_misconfig`. |
| `--timeout` | | int | `30` | `scanner.timeout_seconds` | Per-request timeout in seconds. |
| `--auth-token` | | string | (none) | `auth.token` | Auth token for the target API. |
| `--auth-type` | | string | `bearer` | `auth.type` | Auth type: `jwt`, `oauth2`, `apikey`, `basic`, `bearer`. |
| `--config` | `-c` | string | `.apiguard.yaml` | (none) | Path to config file. |
| `--verbose` | `-v` | bool | `false` | `log.level: debug` | Enable verbose output (sets log level to `debug`). |
| `--quiet` | `-q` | bool | `false` | `log.level: error` | Suppress all output except errors. |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed. No findings at or above `--fail-on` severity. |
| `1` | Scan completed. Findings found at or above `--fail-on` severity. |
| `2` | Scan failed. Configuration error, unreachable target, or invalid schema. |
| `3` | Scan failed. Internal error. |

### Examples

```bash
# Minimal scan — HTML report, fail on HIGH or CRITICAL
apiguard scan --spec ./openapi.yaml --target https://api.example.com

# SARIF output for CI/CD, fail on MEDIUM and above
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.staging.example.com \
  --format sarif \
  --output ./results \
  --fail-on MEDIUM

# Run only specific modules with a custom config file
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --modules a1_bola,a2_auth,a8_misconfig \
  --config ./custom-config.yaml

# API key auth with verbose logging
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --auth-type apikey \
  --auth-token "sk-live-abc123" \
  --verbose
```

---

## Module Configuration

Each OWASP module can be independently enabled or disabled in the config file under `modules.<module_name>.enabled`.

| Module Key | OWASP ID | Default | Requires |
|-----------|----------|---------|----------|
| `a1_bola` | API1:2023 | Enabled | At least 2 auth tokens (`auth.token` + `modules.a1_bola.extra_tokens[]`) |
| `a2_auth` | API2:2023 | Enabled | -- |
| `a3_mass_assignment` | API3:2023 | Enabled | Schema with defined request/response bodies |
| `a4_rate_limiting` | API4:2023 | Enabled | -- |
| `a5_function_auth` | API5:2023 | Enabled | Best results when schema tags admin endpoints |
| `a6_business_flow` | API6:2023 | **Disabled** | Manual `sensitive_endpoints` configuration |
| `a7_ssrf` | API7:2023 | Enabled | Best with `oast_url` configured |
| `a8_misconfig` | API8:2023 | Enabled | -- |
| `a9_inventory` | API9:2023 | Enabled | -- |
| `a10_unsafe_consumption` | API10:2023 | **Disabled** | `oast_url` configuration |

To run only specific modules via CLI:

```bash
apiguard scan --spec ./openapi.yaml --target https://api.example.com --modules a1_bola,a2_auth
```

To disable a single module in the config file:

```yaml
modules:
  a4_rate_limiting:
    enabled: false
```

---

## Auth Configuration

APIGuard supports five authentication methods for target API testing. Set the method via `auth.type` in the config file, `APIGUARD_AUTH_TYPE` environment variable, or `--auth-type` CLI flag.

### Bearer Token

The simplest method. Sends an `Authorization: Bearer <token>` header with every request.

```yaml
auth:
  type: bearer
  token: "eyJhbGciOiJIUzI1NiIs..."
```

### JWT

APIGuard generates and manages JWT tokens using the provided secret. Tokens are refreshed automatically before expiry.

```yaml
auth:
  type: jwt
  jwt:
    secret: "your-jwt-secret"
    algorithm: HS256
    issuer: "apiguard"
    audience: "api.example.com"
    expiry_seconds: 3600
```

| Field | Required | Default | Values |
|-------|----------|---------|--------|
| `secret` | Yes | -- | Signing secret or path to PEM key file for RS/ES algorithms |
| `algorithm` | No | `HS256` | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512` |
| `issuer` | No | `""` | `iss` claim value |
| `audience` | No | `""` | `aud` claim value |
| `expiry_seconds` | No | `3600` | Token lifetime |

### OAuth2

APIGuard performs the OAuth2 flow to obtain and refresh access tokens automatically.

```yaml
auth:
  type: oauth2
  oauth2:
    token_url: "https://auth.example.com/oauth/token"
    client_id: "apiguard-scanner"
    client_secret: "secret"
    scopes:
      - read
      - write
    grant_type: client_credentials
```

| Field | Required | Default | Values |
|-------|----------|---------|--------|
| `token_url` | Yes | -- | OAuth2 token endpoint |
| `client_id` | Yes | -- | Client identifier |
| `client_secret` | Yes | -- | Client secret |
| `scopes` | No | `[]` | Requested scopes |
| `grant_type` | No | `client_credentials` | `client_credentials`, `authorization_code`, `password` |

### API Key

Sends a custom header with the API key value.

```yaml
auth:
  type: apikey
  apikey:
    header: X-API-Key
    value: "sk-live-abc123"
```

### Basic Auth

Sends an `Authorization: Basic <base64(user:pass)>` header.

```yaml
auth:
  type: basic
  basic:
    username: "scanner"
    password: "password"
```

---

## Scanner Settings

| Setting | Config Path | Env Var | CLI Flag | Default | Description |
|---------|-----------|---------|----------|---------|-------------|
| Concurrency | `scanner.concurrency` | `APIGUARD_CONCURRENCY` | -- | `10` | Maximum number of concurrent HTTP requests sent to the target API. |
| Timeout | `scanner.timeout_seconds` | `APIGUARD_TIMEOUT` | `--timeout` | `30` | Per-request timeout in seconds. Requests exceeding this are aborted. |
| Max spec size | `scanner.max_spec_size_mb` | -- | -- | `10` | Maximum schema file size in MB. Schemas exceeding this are rejected by L1. |
| Rate limit | `scanner.rate_limit_rps` | `APIGUARD_RATE_LIMIT` | -- | `50` | Maximum requests per second. Prevents overwhelming the target. |
| Follow redirects | `scanner.follow_redirects` | -- | -- | `true` | Follow HTTP 3xx redirects. |
| TLS skip verify | `scanner.tls_skip_verify` | `APIGUARD_TLS_SKIP_VERIFY` | -- | `false` | Skip TLS certificate verification. Use only against dev/test environments. |

---

## Report Settings

| Setting | Config Path | Env Var | CLI Flag | Default | Description |
|---------|-----------|---------|----------|---------|-------------|
| Format | `report.format` | `APIGUARD_REPORT_FORMAT` | `--format` | `json` | Output format: `html`, `pdf`, `json`, `sarif`. |
| Output directory | `report.output_dir` | `APIGUARD_REPORT_DIR` | `--output` | `./reports` | Directory where report files are written. Created if it does not exist. |
| Template | `report.template` | -- | -- | (built-in) | Path to a custom Jinja2 template for HTML/PDF reports. |
| Include evidence | `report.include_evidence` | -- | -- | `true` | Include raw HTTP request/response pairs as evidence in findings. |
| Include remediation | `report.include_remediation` | -- | -- | `true` | Include OWASP remediation guidance for each finding. |

### Output Formats

| Format | Use Case | Generator |
|--------|----------|-----------|
| `html` | Human review. Share with stakeholders. | L7 Python + Jinja2 |
| `pdf` | Formal reports. Compliance artifacts. | L7 Python + Jinja2 |
| `json` | Machine consumption. Custom integrations. | L7 Go |
| `sarif` | GitHub Advanced Security, CI/CD tools. | L7 Go |

---

## Database Settings

PostgreSQL is required for scan persistence (L8) and the dashboard (L9). It is **not required** for CLI-only usage -- scans run without a database and output reports directly to the filesystem.

| Setting | Config Path | Env Var | Default | Description |
|---------|-----------|---------|---------|-------------|
| Connection URL | `database.url` | `APIGUARD_DB_URL` | (none) | PostgreSQL connection string. Format: `postgres://user:pass@host:port/dbname?sslmode=disable` |
| Max open connections | `database.max_open_conns` | -- | `25` | Maximum number of open database connections. |
| Max idle connections | `database.max_idle_conns` | -- | `5` | Maximum number of idle connections in the pool. |
| Connection lifetime | `database.conn_max_lifetime_seconds` | -- | `300` | Maximum lifetime of a connection in seconds before it is closed and replaced. |
| Auto migrate | `database.auto_migrate` | -- | `true` | Automatically run schema migrations on startup. Disable in production if you manage migrations externally. |
| SSL mode | `database.ssl_mode` | -- | `disable` | PostgreSQL SSL mode: `disable`, `require`, `verify-ca`, `verify-full`. |

---

## Dashboard Settings

The dashboard (L9) is the React-based web interface for viewing scan history, finding trends, and managing API inventory.

| Setting | Config Path | Env Var | Default | Description |
|---------|-----------|---------|---------|-------------|
| Enabled | `dashboard.enabled` | -- | `true` | Enable the dashboard. Set to `false` for CLI-only deployments. |
| UI port | `dashboard.port` | `APIGUARD_DASHBOARD_PORT` | `3000` | Port for the React dashboard UI. |
| API port | `dashboard.api_port` | `APIGUARD_PORT` | `8080` | Port for the APIGuard API server that the dashboard calls. |
| CORS origins | `dashboard.cors_origins` | -- | `["http://localhost:3000"]` | Allowed CORS origins. Add your domain in production. |
| Session timeout | `dashboard.session_timeout_minutes` | -- | `60` | Dashboard session timeout in minutes. |

---

## CITADEL Integration

APIGuard can emit scan lifecycle events to a [CITADEL](../../.citadel/README.md) governance engine instance. This is a one-way integration: APIGuard pushes events via webhook. CITADEL cannot write back to APIGuard scan data.

| Setting | Config Path | Env Var | Default | Description |
|---------|-----------|---------|---------|-------------|
| Enabled | `citadel.enabled` | -- | `false` | Enable CITADEL event emission. |
| Webhook URL | `citadel.webhook_url` | `CITADEL_WEBHOOK_URL` | (none) | CITADEL ingest endpoint. |
| API key | `citadel.api_key` | `CITADEL_API_KEY` | (none) | Authentication key for the CITADEL webhook. |
| Events | `citadel.emit_events` | -- | (all) | List of events to emit. |
| Verify TLS | `citadel.verify_tls` | -- | `true` | Verify TLS certificate of the CITADEL endpoint. |

### Available Events

| Event | Emitted When |
|-------|-------------|
| `scan_started` | A scan begins execution. |
| `scan_completed` | A scan finishes (success or failure). |
| `finding_critical` | A CRITICAL severity finding is detected. |
| `finding_high` | A HIGH severity finding is detected. |

---

## Precedence Order

When a setting is defined in multiple places, the highest-precedence source wins:

```
1. CLI flags           (highest precedence)
2. Environment variables
3. Config file (.apiguard.yaml)
4. Built-in defaults   (lowest precedence)
```

Example: if `scanner.timeout_seconds` is set to `60` in the config file, `APIGUARD_TIMEOUT=45` is set in the environment, and `--timeout 10` is passed on the command line, the effective timeout is **10 seconds**.

### Precedence by Setting

| Setting | CLI Flag | Env Var | Config File | Default |
|---------|----------|---------|-------------|---------|
| Log level | `--verbose` / `--quiet` | `APIGUARD_LOG_LEVEL` | `log.level` | `info` |
| Report format | `--format` | `APIGUARD_REPORT_FORMAT` | `report.format` | `json` |
| Output path | `--output` | `APIGUARD_REPORT_DIR` | `report.output_dir` | stdout |
| Auth token | `--auth-token` | `APIGUARD_AUTH_TOKEN` | `auth.token` | (none) |
| Auth type | `--auth-type` | `APIGUARD_AUTH_TYPE` | `auth.type` | `bearer` |
| Timeout | `--timeout` | `APIGUARD_TIMEOUT` | `scanner.timeout_seconds` | `30` |
| Modules | `--modules` | -- | `modules.*` | all enabled |
