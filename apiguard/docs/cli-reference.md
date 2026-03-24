# CLI Reference

APIGuard ships as a single Go binary (Layer 10 in the [architecture](architecture.md)). It wraps the full scan pipeline, report generation, and rule management into one executable suitable for local development, CI/CD, and scripting.

---

## Installation

### GitHub Releases

Download the latest binary from [GitHub Releases](https://github.com/opensecstack/apiguard/releases/latest). Binaries are published for every tagged version.

| OS      | Architecture | Asset                              |
|---------|--------------|------------------------------------|
| Linux   | amd64        | `apiguard-linux-amd64.tar.gz`      |
| Linux   | arm64        | `apiguard-linux-arm64.tar.gz`      |
| macOS   | amd64        | `apiguard-darwin-amd64.tar.gz`     |
| macOS   | arm64        | `apiguard-darwin-arm64.tar.gz`     |
| Windows | amd64        | `apiguard-windows-amd64.zip`       |
| Windows | arm64        | `apiguard-windows-arm64.zip`       |

```bash
# Example: Linux amd64
curl -sL https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-amd64.tar.gz | tar xz
sudo mv apiguard /usr/local/bin/
apiguard version
```

### Homebrew

```bash
brew install opensecstack/tap/apiguard
```

### Docker

```bash
docker run --rm ghcr.io/opensecstack/apiguard:latest scan \
  --spec /specs/openapi.yaml \
  --target https://api.example.com
```

Mount a local spec file:

```bash
docker run --rm -v $(pwd):/work ghcr.io/opensecstack/apiguard:latest scan \
  --spec /work/openapi.yaml \
  --target https://api.example.com \
  --output /work/report.json
```

### Go install

Requires Go 1.22 or later.

```bash
go install github.com/opensecstack/apiguard/cmd@latest
```

---

## Commands

### `apiguard scan`

Run an API security scan against a live target using an API specification.

```
apiguard scan --spec <path> --target <url> [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--spec`, `-s` | string | **(required)** | Path to the API specification file (OpenAPI 3.x, Swagger 2.x, or GraphQL schema). |
| `--target`, `-t` | string | **(required)** | Base URL of the API to scan. |
| `--format`, `-f` | string | `json` | Output format. One of `html`, `pdf`, `json`, `sarif`. |
| `--output`, `-o` | string | stdout | File path to write the report to. When omitted, output is written to stdout. |
| `--fail-on` | string | `HIGH` | Minimum severity that causes a non-zero exit code. One of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`. Set to `NONE` to always pass. |
| `--modules`, `-m` | string | all enabled | Comma-separated list of OWASP module IDs to run (e.g., `a1_bola,a3_mass_assignment,a8_misconfig`). By default all modules are enabled. |
| `--timeout` | duration | `30s` | Per-request timeout for HTTP calls to the target. |
| `--concurrency` | int | `10` | Maximum number of parallel requests sent to the target. |
| `--auth-token` | string | | Authentication token or credential value. |
| `--auth-type` | string | | Authentication scheme. One of `bearer`, `jwt`, `oauth2`, `apikey`, `basic`. |
| `--auth-header` | string | `Authorization` | Header name used to send the auth token. |
| `--baseline` | string | | Path to a previous scan result (JSON) for regression comparison. |
| `--config`, `-c` | string | | Path to a `.apiguard.yaml` configuration file. See [Configuration Reference](configuration.md). |
| `--verbose`, `-v` | bool | `false` | Enable verbose output. Prints each test case as it executes. |
| `--quiet`, `-q` | bool | `false` | Suppress all output except the final report. |
| `--log-requests` | bool | `false` | Log all HTTP requests and responses for debugging. |
| `--log-dir` | string | `./logs` | Directory for request/response logs. |
| `--tls-skip-verify` | bool | `false` | Skip TLS certificate verification for self-signed certs. |
| `--rate-limit` | int | `0` | Maximum requests per second (0 = unlimited). |
| `--log-level` | string | `info` | Log level: `debug`, `info`, `warn`, `error`. |

---

### `apiguard server`

Start the APIGuard API server. The server exposes a REST API consumed by the dashboard (Layer 9) and can be used to trigger scans programmatically.

```
apiguard server [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--port` | int | `8080` | Port to listen on. |
| `--db-url` | string | | PostgreSQL connection string. |
| `--redis-url` | string | | Redis connection string for job queue and caching. |
| `--jwt-secret` | string | | Secret used to sign and verify JWT tokens. |
| `--config` | string | | Path to a `.apiguard.yaml` configuration file. |

---

### `apiguard report`

Generate a report from a previously completed scan stored in the database.

```
apiguard report --scan-id <id> [flags]
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--scan-id` | string | **(required)** | UUID of the scan to generate a report for. |
| `--format` | string | `json` | Output format. One of `html`, `pdf`, `json`, `sarif`. |
| `--output` | string | stdout | File path to write the report to. |

---

### `apiguard rule validate`

Validate a custom rule YAML file against the APIGuard rule schema. Returns a non-zero exit code if validation fails.

```
apiguard rule validate <path-to-rule.yaml>
```

#### Arguments

| Argument | Description |
|----------|-------------|
| `path` | Path to the custom rule YAML file. |

---

### `apiguard rule test`

Execute a single custom rule against a target API to verify it works as expected before adding it to a full scan.

```
apiguard rule test <path-to-rule.yaml> --target <url> --spec <path>
```

#### Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | string | **(required)** | Base URL of the API to test against. |
| `--spec` | string | **(required)** | Path to the API specification file. |

#### Arguments

| Argument | Description |
|----------|-------------|
| `path` | Path to the custom rule YAML file. |

---

### `apiguard version`

Print version, commit hash, build date, and Go version.

```
apiguard version
```

Example output:

```
apiguard v0.4.0
  commit:  a1b2c3d
  built:   2026-03-20T14:30:00Z
  go:      go1.22.1
```

---

### `apiguard completion`

Generate shell completion scripts.

```
apiguard completion <shell>
```

Supported shells: `bash`, `zsh`, `fish`, `powershell`.

```bash
# Bash
apiguard completion bash > /etc/bash_completion.d/apiguard

# Zsh
apiguard completion zsh > "${fpath[1]}/_apiguard"

# Fish
apiguard completion fish > ~/.config/fish/completions/apiguard.fish

# PowerShell
apiguard completion powershell | Out-String | Invoke-Expression
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed. No findings at or above `--fail-on` severity. |
| `1` | Scan completed. Findings found at or above `--fail-on` severity. |
| `2` | Scan failed. Configuration error, unreachable target, or invalid schema. |
| `3` | Scan failed. Internal error. |

---

## Environment Variables

Every flag can be set via an environment variable. The variable name follows the pattern `APIGUARD_<FLAG>` with hyphens replaced by underscores and all letters uppercased.

| Environment Variable | Corresponding Flag | Example |
|----------------------|-------------------|---------|
| `APIGUARD_SPEC` | `--spec` | `./api/openapi.yaml` |
| `APIGUARD_TARGET` | `--target` | `https://api.example.com` |
| `APIGUARD_FORMAT` | `--format` | `sarif` |
| `APIGUARD_OUTPUT` | `--output` | `./report.sarif` |
| `APIGUARD_FAIL_ON` | `--fail-on` | `CRITICAL` |
| `APIGUARD_MODULES` | `--modules` | `a1_bola,a3_mass_assignment,a8_misconfig` |
| `APIGUARD_TIMEOUT` | `--timeout` | `60s` |
| `APIGUARD_CONCURRENCY` | `--concurrency` | `20` |
| `APIGUARD_AUTH_TOKEN` | `--auth-token` | `eyJhbGci...` |
| `APIGUARD_AUTH_TYPE` | `--auth-type` | `bearer` |
| `APIGUARD_AUTH_HEADER` | `--auth-header` | `X-API-Key` |
| `APIGUARD_BASELINE` | `--baseline` | `./previous-scan.json` |
| `APIGUARD_CONFIG` | `--config` | `./.apiguard.yaml` |
| `APIGUARD_PORT` | `--port` | `8080` |
| `APIGUARD_DB_URL` | `--db-url` | `postgres://user:pass@localhost:5432/apiguard` |
| `APIGUARD_REDIS_URL` | `--redis-url` | `redis://localhost:6379/0` |
| `APIGUARD_JWT_SECRET` | `--jwt-secret` | `your-secret-here` |
| `APIGUARD_VERBOSE` | `--verbose` | `true` |
| `APIGUARD_QUIET` | `--quiet` | `true` |
| `APIGUARD_LOG_LEVEL` | `--log-level` | `info` |
| `APIGUARD_RATE_LIMIT` | `--rate-limit` | `100` |
| `APIGUARD_TLS_SKIP_VERIFY` | `--tls-skip-verify` | `true` |
| `APIGUARD_LOG_REQUESTS` | `--log-requests` | `true` |
| `APIGUARD_LOG_DIR` | `--log-dir` | `./logs` |

Flags take precedence over environment variables. Environment variables take precedence over values in the configuration file.

---

## Examples

### Basic scan with JSON output to stdout

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com
```

### HTML report written to a file

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --format html \
  --output ./report.html
```

### CI pipeline with SARIF upload

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target "$API_TARGET_URL" \
  --format sarif \
  --output results.sarif \
  --fail-on HIGH
```

### Authenticated scan using a bearer token

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --auth-type bearer \
  --auth-token "$API_TOKEN"
```

### Authenticated scan using an API key in a custom header

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --auth-type apikey \
  --auth-header X-API-Key \
  --auth-token "$API_KEY"
```

### Run only specific OWASP modules

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --modules a1_bola,a2_auth,a8_misconfig
```

### Regression comparison against a baseline

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --baseline ./previous-scan.json \
  --output ./current-scan.json
```

### Scan with increased concurrency and timeout

```bash
apiguard scan \
  --spec ./openapi.yaml \
  --target https://api.example.com \
  --concurrency 50 \
  --timeout 60s
```

### Generate a report from a stored scan

```bash
apiguard report \
  --scan-id 550e8400-e29b-41d4-a716-446655440000 \
  --format pdf \
  --output ./scan-report.pdf
```

### Validate and test a custom rule

```bash
# Validate the rule file
apiguard rule validate ./rules/custom-header-check.yaml

# Test it against a live target
apiguard rule test ./rules/custom-header-check.yaml \
  --spec ./openapi.yaml \
  --target https://api.example.com
```

### Docker with environment variables

```bash
docker run --rm \
  -v $(pwd):/work \
  -e APIGUARD_SPEC=/work/openapi.yaml \
  -e APIGUARD_TARGET=https://api.example.com \
  -e APIGUARD_FORMAT=html \
  -e APIGUARD_OUTPUT=/work/report.html \
  -e APIGUARD_AUTH_TYPE=bearer \
  -e APIGUARD_AUTH_TOKEN="$API_TOKEN" \
  ghcr.io/opensecstack/apiguard:latest scan
```

### Use a configuration file for repeated scans

```bash
apiguard scan --config .apiguard.yaml
```

Where `.apiguard.yaml` contains defaults for spec, target, auth, modules, and other options. See [Configuration Reference](configuration.md) for the full schema.
