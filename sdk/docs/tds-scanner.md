# tds-scanner

`tds-scanner` is a static-analysis CLI tool that inspects Go, Python, and Rust
source code for Trust, Dependency, and Security (TDS) compliance issues. It is
part of the opensecstack SDK toolchain and is designed to be run locally during
development and as a mandatory gate in CI/CD pipelines.

TDS compliance means that integration code communicating with opensecstack
platforms (APIGuard, NIS2 Compass, ThreatFlow, CITADEL, IRFlow) adheres to a
minimum set of security hygiene rules: credentials are not hardcoded, TLS
verification is not bypassed, HTTP calls use retry logic, no private key
material leaks into source files, and HTTP clients carry the expected
correlation and identification headers.

---

## Installation

### Via `go install` (recommended)

```bash
go install github.com/opensecstack/sdk/tools/tds-scanner@latest
```

Requires Go 1.22 or later. The binary is self-contained and has no runtime
dependencies.

### Build from source

```bash
git clone https://github.com/opensecstack/opensecstack.git
cd opensecstack/sdk/tools/tds-scanner
go build -ldflags "-X github.com/opensecstack/tds-scanner/cmd.Version=$(git describe --tags)" \
    -o tds-scanner .
```

Verify the installation:

```bash
tds-scanner version
# tds-scanner 1.0.0 (commit abc1234)
```

---

## CLI Reference

### Global flags

These flags apply to every subcommand.

| Flag | Default | Description |
|------|---------|-------------|
| `--format` | `text` | Output format: `text` or `json`. |
| `-o`, `--output` | _(stdout)_ | Write the report to this file path instead of stdout. |
| `--severity` | `low` | Minimum severity to include in results. Accepted values: `info`, `low`, `medium`, `high`, `critical`. |

### `tds-scanner scan`

```
tds-scanner scan [flags] <target>
```

Scans a single file, a directory, or a project tree for TDS compliance issues.
`<target>` is the only required argument — it must be a path to a file or
directory that exists on disk.

#### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--lang` | `auto` | Language hint for file selection. Accepted values: `go`, `python`, `rust`, `auto`. In `auto` mode the scanner inspects the file-extension distribution in the target tree and selects the dominant language. |
| `--checks` | _(all)_ | Comma-separated list of check IDs to run. When omitted, all five check groups are executed. Example: `--checks TDS-AUTH-001,TDS-TLS-001`. |
| `--exit-code` | `true` | Exit with status code `1` when any finding at or above the `--severity` threshold is found. Set `--exit-code=false` to always exit `0` (useful when running in report-only mode). |

#### Examples

```bash
# Scan the entire SDK Go directory with default settings.
tds-scanner scan ./sdk/go

# Scan a Python integration, report only high and critical findings.
tds-scanner scan --lang python --severity high ./integrations/python

# Scan a Rust project, output JSON to a file.
tds-scanner scan --lang rust --format json -o results.json ./sdk/rust

# Run only authentication and TLS checks at critical severity, never fail the build.
tds-scanner scan --checks TDS-AUTH-001,TDS-TLS-001 --severity critical \
    --exit-code=false ./

# Pipe JSON output to jq to list unique check IDs that fired.
tds-scanner scan --format json ./sdk/go | jq -r '.findings[].check_id' | sort -u
```

### `tds-scanner version`

```
tds-scanner version
```

Prints the version string and the git commit hash baked in at build time.

---

## Check Reference

The scanner runs five check groups. Each group is identified by a prefix; the
full check ID is used in reports and with `--checks`.

### TDS-AUTH — Authentication

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `TDS-AUTH-001` | critical | API key or secret literal hardcoded directly in source (`api_key = "..."`, `secret: "..."`). |
| `TDS-AUTH-002` | high | JWT token stored in a `token` variable without an expiry check (`exp`, `expiry`, `ExpiresAt`, `expires_in`) visible within five lines. |
| `TDS-AUTH-003` | medium | HTTP Basic auth credentials embedded in a URL (`http://user:pass@host`). |

### TDS-TLS — Transport Security

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `TDS-TLS-001` | critical | TLS certificate verification disabled via `InsecureSkipVerify: true` (Go), `verify=False` (Python requests), or `danger_accept_invalid_certs=true`. |
| `TDS-TLS-002` | high | Plaintext `http://` base URL passed to a client constructor, transmitting data unencrypted. |
| `TDS-TLS-003` | medium | Python `ssl.CERT_NONE` or `ssl_context.check_hostname = False`, disabling hostname and certificate verification. |

### TDS-RETRY — Resilience

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `TDS-RETRY-001` | medium | `http.Get`, `http.Post`, `http.PostForm`, `http.Head`, or `.Do(req)` call without a retry or backoff loop visible within 20 lines. |
| `TDS-RETRY-002` | low | `time.Sleep` with a fixed integer multiplier and no jitter, which can trigger a thundering-herd problem on transient server errors. |

### TDS-SECRET — Secret Detection

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `TDS-SECRET-001` | critical | Variable whose name suggests a secret (`password`, `passwd`, `pwd`, `secret`, `token`, `auth_key`, `private_key`) assigned a hardcoded string of eight or more characters. |
| `TDS-SECRET-002` | high | PEM private key header (`-----BEGIN RSA PRIVATE KEY-----`, etc.) embedded in a source file. |
| `TDS-SECRET-003` | medium | Password embedded inline in a connection string or DSN (`://user:password@host`). |

### TDS-HDR — HTTP Headers

| Check ID | Severity | What it detects |
|----------|----------|-----------------|
| `TDS-HDR-001` | medium | HTTP client constructed in the file without an `X-Request-ID` header, making distributed tracing and log correlation impossible. |
| `TDS-HDR-002` | low | HTTP client constructed in the file without a `User-Agent` header; servers may reject or throttle unidentified clients. |

---

## Output Formats

### Text (default)

Human-readable output suitable for terminal inspection and log tailing.

```
TDS Scanner Results
===================
Target:   ./sdk/go
Language: go
Checks:   5 checks run

FINDINGS (2 total)
──────────────────────────────────────────────────
[CRITICAL] TDS-AUTH-001 — Hardcoded API Key or Secret
  File: ./sdk/go/client.go:14
  Code: api_key = "ag_key_EXAMPLE000000000000"
  Fix:  Remove the hardcoded credential and load it from an environment
        variable or a secrets manager (e.g. Vault, AWS Secrets Manager).

[MEDIUM] TDS-RETRY-001 — HTTP Call Without Retry Logic
  File: ./sdk/go/client.go:47
  Code: resp, err := http.Get(url)
  Fix:  Wrap HTTP calls with exponential backoff and jitter. Retry on
        429, 502, 503, 504.

SUMMARY
──────────────────────────────────────────────────
  Critical: 1    High: 0    Medium: 1    Low: 0    Info: 0
  Result: FAIL (findings at or above LOW threshold)
```

### JSON

Machine-readable output for downstream tooling, dashboards, and SARIF
converters. Schema version `1.0`.

```json
{
  "schema_version": "1.0",
  "target": "./sdk/go",
  "language": "go",
  "checks_run": 5,
  "findings": [
    {
      "check_id": "TDS-AUTH-001",
      "title": "Hardcoded API Key or Secret",
      "description": "A credential literal was found directly in source code.",
      "severity": "critical",
      "file_path": "./sdk/go/client.go",
      "line": 14,
      "column": 1,
      "snippet": "api_key = \"ag_key_EXAMPLE000000000000\"",
      "remediation": "Remove the hardcoded credential and load it from an environment variable or a secrets manager."
    }
  ],
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 1,
    "low": 0,
    "info": 0
  },
  "result": "fail",
  "scanned_at": "2026-05-06T09:00:00Z"
}
```

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `schema_version` | string | Always `"1.0"` for this release. |
| `target` | string | The path argument passed on the command line. |
| `language` | string | Detected or specified language: `go`, `python`, or `rust`. |
| `checks_run` | integer | Number of check groups that were executed. |
| `findings` | array | Zero or more finding objects (see below). |
| `summary` | object | Count of findings per severity level. |
| `result` | string | `"pass"` or `"fail"`. |
| `scanned_at` | string | RFC 3339 UTC timestamp of when the scan completed. |

Each finding object contains: `check_id`, `title`, `description`, `severity`,
`file_path`, `line`, `column`, `snippet`, and `remediation`.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed. No findings at or above the `--severity` threshold, or `--exit-code=false` was set. |
| `1` | Scan completed and findings were found at or above the `--severity` threshold (only when `--exit-code=true`, which is the default). |
| `1` | Fatal error — invalid target path, unreadable file, or bad flag value. The error message is written to stderr. |

---

## Configuration File

`tds-scanner` looks for a configuration file at `.tds-scanner.yaml` in the
current working directory (or the nearest parent directory that contains one).
Command-line flags always take precedence over file values.

```yaml
# .tds-scanner.yaml
# All fields are optional. Unset fields use the same defaults as the CLI.

# Minimum severity to report. Same values as --severity.
severity: low

# Output format: "text" or "json".
format: text

# Default output file path (equivalent to -o). Omit to write to stdout.
# output: tds-report.json

# Language hint. Same values as --lang.
lang: auto

# Check IDs to run. Omit or leave empty to run all checks.
checks: []

# Whether to exit 1 when findings are present. Same as --exit-code.
exit_code: true
```

Place `.tds-scanner.yaml` in the repository root so that both local runs and
CI/CD agents pick up the same baseline configuration without requiring flag
repetition.

---

## Integration with CI/CD Pipelines

### GitHub Actions

```yaml
# .github/workflows/tds-scan.yml
name: TDS Compliance Scan

on:
  pull_request:
  push:
    branches: [main]

jobs:
  tds-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Install tds-scanner
        run: go install github.com/opensecstack/sdk/tools/tds-scanner@latest

      - name: Run TDS scan
        run: tds-scanner scan --format json -o tds-report.json --severity medium ./

      - name: Upload scan report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: tds-report
          path: tds-report.json
```

The job fails automatically when `tds-scanner` exits with code `1` (the
default when findings are present). Set `--severity high` to fail only on
high and critical findings during early adoption.

### GitLab CI

```yaml
# .gitlab-ci.yml (excerpt)
tds-scan:
  stage: test
  image: golang:1.22
  script:
    - go install github.com/opensecstack/sdk/tools/tds-scanner@latest
    - tds-scanner scan --format json -o tds-report.json --severity medium ./
  artifacts:
    when: always
    paths:
      - tds-report.json
    expire_in: 30 days
```

### Pre-commit hook

```bash
#!/usr/bin/env bash
# .git/hooks/pre-commit
set -euo pipefail
tds-scanner scan --severity high --exit-code=true ./
```

---

## Example Usage by Platform

### APIGuard integration code

APIGuard client code typically contains API key construction, HTTP client
usage, and scan-polling loops. Run `tds-scanner` against the directory
containing your APIGuard integration:

```bash
tds-scanner scan --lang go ./internal/apiguard
```

Key checks that fire most often on APIGuard integrations:

- `TDS-AUTH-001` — API key string passed directly to `NewAPIGuardClient`
  instead of being read from an environment variable.
- `TDS-RETRY-001` — polling loop that calls `client.GetScan` via a bare
  `http.Get` without a backoff wrapper.
- `TDS-HDR-001` — custom HTTP client missing the `X-Request-ID` header,
  which prevents correlating scan requests in APIGuard's audit log.

Recommended invocation for a clean APIGuard integration:

```bash
tds-scanner scan --checks TDS-AUTH-001,TDS-TLS-001,TDS-RETRY-001 \
    --severity medium --format json -o apiguard-tds.json ./
```

### NIS2 Compass integration code

NIS2 Compass clients handle organisation records, assessment state, and
artifact uploads. The common failure modes are connection-string passwords
and missing retry logic on artifact-upload calls.

```bash
tds-scanner scan --lang go ./internal/nis2compass
```

Checks of particular relevance:

- `TDS-SECRET-003` — database or artifact-storage DSN with an inline
  password, a frequent finding in NIS2 Compass wrapper scripts.
- `TDS-RETRY-001` — `UploadArtifact` or `GenerateReport` calls made without
  retry, causing intermittent failures on large PDF uploads.

### ThreatFlow integration code

ThreatFlow produces `IOCBundle` payloads consumed by IRFlow. Because
ThreatFlow integrations often pull data from external feeds over HTTP,
transport checks are the most important category.

```bash
tds-scanner scan --lang python ./integrations/threatflow
```

Checks of particular relevance:

- `TDS-TLS-001` — `verify=False` on `requests.get` calls to external threat
  feeds, frequently added during development and never removed.
- `TDS-TLS-003` — `ssl.CERT_NONE` in custom SSL contexts used for internal
  feed endpoints.
- `TDS-AUTH-003` — feed URL containing embedded credentials in the form
  `http://user:token@feed.example.com/iocs`.

### CITADEL integration code

CITADEL clients sign events with HMAC-SHA256 and forward them to the WORM
audit chain. The shared secret must never appear in source.

```bash
tds-scanner scan --lang go ./internal/citadel
```

Checks of particular relevance:

- `TDS-SECRET-001` — `SharedSecret` variable assigned a hardcoded string.
  Load it from `os.Getenv("CITADEL_HMAC_SECRET")` at startup instead.
- `TDS-AUTH-001` — HMAC secret passed as a literal to `CITADELClientOptions`.

### IRFlow integration code

IRFlow incident records carry severity labels and WORM entry references.
Integration code should never expose credentials and should always use HTTPS.

```bash
tds-scanner scan --lang rust ./sdk/rust/irflow
```

Checks of particular relevance:

- `TDS-TLS-001` — `danger_accept_invalid_certs=true` in `reqwest::Client`
  configuration, a common shortcut for self-signed certificates in staging.
- `TDS-SECRET-002` — PEM private key embedded alongside TLS client-certificate
  authentication setup.

---

## Language Support and File Discovery

The scanner selects source files based on the dominant file extension found
under the target directory, or the explicit `--lang` flag.

| Language | Extensions scanned |
|----------|--------------------|
| Go | `.go` |
| Python | `.py` |
| Rust | `.rs` |

The following directories are always skipped during recursive walks:

- `.git`, `.github`, and any directory starting with `.`
- `vendor`
- `node_modules`
- `__pycache__`

Files with unrecognised extensions are only scanned when the target is a
single file path, not a directory.

---

## Related Documentation

- [go-client.md](go-client.md) — typed Go clients for APIGuard, NIS2 Compass,
  and CITADEL.
- [contracts.md](contracts.md) — cross-platform integration contracts
  (`ScanResult`, `IOCBundle`, `IncidentRecord`, etc.).
- [migration.md](migration.md) — SDK upgrade guidance between versions.
