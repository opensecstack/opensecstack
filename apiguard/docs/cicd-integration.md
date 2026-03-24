# CI/CD Integration

APIGuard integrates into any CI/CD pipeline. The CLI binary is distributed via [GitHub Releases](https://github.com/opensecstack/apiguard/releases), a Docker image is published to `ghcr.io/opensecstack/apiguard`, and a first-party GitHub Action is available at `opensecstack/apiguard-action@v1`.

All examples below assume your OpenAPI spec is committed to the repository and the target API is reachable from the CI runner.

---

## Table of Contents

- [GitHub Actions](#github-actions)
- [GitLab CI](#gitlab-ci)
- [Jenkins](#jenkins)
- [Generic CI](#generic-ci)
- [Configuration Reference](#configuration-reference)
- [SARIF Output](#sarif-output)
- [Docker Usage](#docker-usage)
- [Best Practices](#best-practices)

---

## GitHub Actions

The `opensecstack/apiguard-action@v1` action wraps the CLI binary and handles installation, execution, and output.

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `spec` | Yes | | Path to OpenAPI/Swagger/GraphQL schema file. |
| `target` | Yes | | Base URL of the API under test. |
| `fail-on` | No | `HIGH` | Minimum severity to fail the build: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`. |
| `format` | No | `sarif` | Output format: `sarif`, `json`, `html`, `pdf`. |
| `output` | No | `apiguard-results.sarif` | Output file path. |
| `modules` | No | (all enabled) | Comma-separated list of modules to run (e.g. `a1_bola,a2_auth,a8_misconfig`). |
| `auth-token` | No | | Bearer token or API key for authenticated endpoints. Use a secret. |

### Full Workflow Example

```yaml
# .github/workflows/api-security.yml
name: API Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  apiguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run APIGuard scan
        uses: opensecstack/apiguard-action@v1
        with:
          spec: ./api/openapi.yaml
          target: ${{ secrets.API_TARGET_URL }}
          fail-on: HIGH
          format: sarif
          output: apiguard-results.sarif
          modules: a1_bola,a2_auth,a3_mass_assignment,a4_rate_limiting,a5_function_auth,a7_ssrf,a8_misconfig,a9_inventory
          auth-token: ${{ secrets.API_AUTH_TOKEN }}

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: apiguard-results.sarif
          category: apiguard

      - name: Upload scan results as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: apiguard-report
          path: apiguard-results.sarif
```

### Baseline Comparison on Main

To avoid failing on pre-existing findings, use `--baseline` with a previous scan result committed to the repository or downloaded from a prior run:

```yaml
      - name: Download baseline from main
        uses: actions/download-artifact@v4
        with:
          name: apiguard-baseline
          path: ./baseline
        continue-on-error: true

      - name: Run APIGuard scan with baseline
        uses: opensecstack/apiguard-action@v1
        with:
          spec: ./api/openapi.yaml
          target: ${{ secrets.API_TARGET_URL }}
          fail-on: HIGH
          format: sarif
          output: apiguard-results.sarif
        env:
          APIGUARD_BASELINE: ./baseline/apiguard-results.sarif
```

---

## GitLab CI

Use the `ghcr.io/opensecstack/apiguard` Docker image directly.

```yaml
# .gitlab-ci.yml
stages:
  - test
  - security

api-security-scan:
  stage: security
  image: ghcr.io/opensecstack/apiguard:latest
  variables:
    APIGUARD_SPEC: "./api/openapi.yaml"
    APIGUARD_TARGET: "${API_TARGET_URL}"
  script:
    - apiguard scan
        --spec "${APIGUARD_SPEC}"
        --target "${APIGUARD_TARGET}"
        --fail-on HIGH
        --format sarif
        --output apiguard-results.sarif
        --modules a1_bola,a2_auth,a3_mass_assignment,a4_rate_limiting,a5_function_auth,a7_ssrf,a8_misconfig,a9_inventory
        --auth-token "${API_AUTH_TOKEN}"
  artifacts:
    paths:
      - apiguard-results.sarif
    reports:
      sast: apiguard-results.sarif
    when: always
    expire_in: 30 days
  allow_failure:
    exit_codes:
      - 1
  rules:
    - if: '$CI_PIPELINE_SOURCE == "merge_request_event"'
    - if: '$CI_COMMIT_BRANCH == "main"'
```

### Notes

- The `reports: sast:` key uploads the SARIF file to GitLab's Security Dashboard.
- `allow_failure: exit_codes: [1]` lets the pipeline continue when findings are present but still marks the job as a warning. Remove this to hard-fail.
- Exit codes `2` (configuration/target/schema error) and `3` (internal error) always fail the job.

---

## Jenkins

Declarative pipeline using the CLI binary downloaded from GitHub Releases.

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        API_TARGET_URL = credentials('api-target-url')
        API_AUTH_TOKEN = credentials('api-auth-token')
        APIGUARD_VERSION = 'latest'
    }

    stages {
        stage('Install APIGuard') {
            steps {
                sh '''
                    curl -fsSL https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-amd64 \
                        -o /usr/local/bin/apiguard
                    chmod +x /usr/local/bin/apiguard
                    apiguard version
                '''
            }
        }

        stage('API Security Scan') {
            steps {
                sh '''
                    apiguard scan \
                        --spec ./api/openapi.yaml \
                        --target "${API_TARGET_URL}" \
                        --fail-on HIGH \
                        --format sarif \
                        --output apiguard-results.sarif \
                        --modules a1_bola,a2_auth,a3_mass_assignment,a4_rate_limiting,a5_function_auth,a7_ssrf,a8_misconfig,a9_inventory \
                        --auth-token "${API_AUTH_TOKEN}"
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'apiguard-results.sarif', allowEmptyArchive: true

            recordIssues(
                tools: [sarif(pattern: 'apiguard-results.sarif')],
                qualityGates: [
                    [threshold: 1, type: 'TOTAL_HIGH', criticality: 'FAILURE'],
                    [threshold: 1, type: 'TOTAL_ERROR', criticality: 'FAILURE']
                ]
            )
        }
    }
}
```

### Requirements

- The [Warnings Next Generation](https://plugins.jenkins.io/warnings-ng/) plugin is required for `recordIssues` with SARIF support.
- For Docker-based Jenkins agents, use the `ghcr.io/opensecstack/apiguard` image directly instead of downloading the binary.

---

## Generic CI

For any CI system that supports shell commands, download the binary and run it directly.

### Linux (amd64)

```bash
#!/usr/bin/env bash
set -euo pipefail

# Download the latest release
curl -fsSL \
    https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-amd64 \
    -o ./apiguard
chmod +x ./apiguard

# Run the scan
./apiguard scan \
    --spec ./api/openapi.yaml \
    --target "${API_TARGET_URL}" \
    --fail-on HIGH \
    --format sarif \
    --output apiguard-results.sarif \
    --auth-token "${API_AUTH_TOKEN}"

# Exit code determines pipeline result:
#   0 = pass (no findings above threshold)
#   1 = findings above threshold
#   2 = configuration error, unreachable target, or invalid schema
#   3 = internal error
```

### Linux (arm64)

```bash
curl -fsSL \
    https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-arm64 \
    -o ./apiguard
chmod +x ./apiguard
```

### macOS (amd64)

```bash
curl -fsSL \
    https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-darwin-amd64 \
    -o ./apiguard
chmod +x ./apiguard
```

### Specific Version

Pin to a specific version to avoid unexpected changes:

```bash
APIGUARD_VERSION="0.5.2"
curl -fsSL \
    "https://github.com/opensecstack/apiguard/releases/download/v${APIGUARD_VERSION}/apiguard-linux-amd64" \
    -o ./apiguard
chmod +x ./apiguard
```

---

## Configuration Reference

### Fail-on Threshold

The `--fail-on` flag controls which severity level causes a non-zero exit code.

| Value | Behaviour |
|-------|-----------|
| `CRITICAL` | Fail only on CRITICAL findings (CVSS 9.0+). |
| `HIGH` | Fail on HIGH or CRITICAL findings (CVSS 7.0+). Default. |
| `MEDIUM` | Fail on MEDIUM, HIGH, or CRITICAL findings (CVSS 4.0+). |
| `LOW` | Fail on any finding with a severity of LOW or above (CVSS 0.1+). |
| `NONE` | Never fail due to findings. The scan still exits `2` or `3` on errors. |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed. No findings at or above the `--fail-on` threshold. |
| `1` | Scan completed. One or more findings at or above the `--fail-on` threshold. |
| `2` | Scan failed. Configuration error, unreachable target, or invalid schema. |
| `3` | Scan failed. Internal error. |

### Baseline Comparison

Use `--baseline` to compare the current scan against a previous scan result. Only **new** findings (not present in the baseline) are evaluated against the `--fail-on` threshold. This is useful for adopting APIGuard incrementally without requiring all pre-existing findings to be fixed immediately.

```bash
apiguard scan \
    --spec ./api/openapi.yaml \
    --target https://api.example.com \
    --fail-on HIGH \
    --baseline ./previous-scan.sarif \
    --format sarif \
    --output apiguard-results.sarif
```

Findings are matched by a composite key of endpoint, method, module, and finding fingerprint. A finding present in the baseline but absent in the current scan is reported as resolved in the output but does not affect the exit code.

### Module Selection

Each OWASP module can be individually enabled or disabled via `--modules`. This is particularly relevant in CI where execution time matters.

| Module | Default | Typical Duration | CI Recommendation |
|--------|---------|-----------------|-------------------|
| `a1_bola` | Enabled | ~30s per endpoint | Include. Core security check. |
| `a2_auth` | Enabled | ~10s per endpoint | Include. Fast and high-value. |
| `a3_mass_assignment` | Enabled | ~15s per endpoint | Include. |
| `a4_rate_limiting` | Enabled | ~60s total | Include. Single pass. |
| `a5_function_auth` | Enabled | ~20s per endpoint | Include when schema tags admin endpoints. |
| `a6_business_flow` | Disabled | ~120s+ per endpoint | Skip in CI. Requires manual config. Slow. |
| `a7_ssrf` | Enabled | ~15s per endpoint | Include if OAST configured. |
| `a8_misconfig` | Enabled | ~5s total | Include. Fast. |
| `a9_inventory` | Enabled | ~10s total | Include. Fast. |
| `a10_unsafe_consumption` | Disabled | ~120s+ per endpoint | Skip in CI. Requires OAST setup. Slow. |

To run only the fast, high-confidence modules:

```bash
apiguard scan \
    --spec ./api/openapi.yaml \
    --target https://api.example.com \
    --modules a1_bola,a2_auth,a3_mass_assignment,a4_rate_limiting,a8_misconfig,a9_inventory
```

---

## SARIF Output

APIGuard produces [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) output when `--format sarif` is specified.

### Contents

The SARIF file includes:

- **Tool metadata** -- APIGuard version, module versions, scan configuration.
- **Rules** -- One rule per unique finding type, mapped to OWASP API Top 10 IDs and CWE IDs.
- **Results** -- One result per finding instance, including:
  - Endpoint (method + path) as the location.
  - Severity level mapped to SARIF `level` (`error`, `warning`, `note`).
  - CVSS 3.1 score in the `properties` bag.
  - Evidence (request/response snippets) in the message.
  - Remediation guidance in `help.text` and `help.markdown`.
- **Invocation** -- Execution metadata including exit code, duration, and any tool-level errors.

### Severity Mapping

| APIGuard Severity | SARIF Level |
|-------------------|-------------|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `note` |

### Upload to GitHub

```yaml
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: apiguard-results.sarif
    category: apiguard
```

The `category` field ensures APIGuard results appear as a distinct tool in the GitHub Security tab and do not overwrite results from other SARIF-producing tools (e.g., CodeQL).

### Upload to GitLab

GitLab natively consumes SARIF via the `reports:sast` artifact keyword:

```yaml
artifacts:
  reports:
    sast: apiguard-results.sarif
```

Results appear in the GitLab Security Dashboard and in merge request security widgets.

### Upload to Azure DevOps

Use the `PublishBuildArtifacts` task to store the SARIF file, then the SARIF SAST Scans Tab extension to render it:

```yaml
# azure-pipelines.yml
steps:
  - script: |
      curl -fsSL https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-amd64 -o apiguard
      chmod +x apiguard
      ./apiguard scan \
          --spec ./api/openapi.yaml \
          --target $(API_TARGET_URL) \
          --fail-on HIGH \
          --format sarif \
          --output $(Build.ArtifactStagingDirectory)/apiguard-results.sarif \
          --auth-token $(API_AUTH_TOKEN)
    displayName: Run APIGuard scan
    continueOnError: true

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)/apiguard-results.sarif
      artifactName: CodeAnalysisLogs
    condition: always()
    displayName: Publish SARIF results
```

---

## Docker Usage

The official Docker image is published to `ghcr.io/opensecstack/apiguard`.

### Basic Scan

```bash
docker run --rm \
    -v "$(pwd)":/workspace \
    ghcr.io/opensecstack/apiguard:latest \
    scan \
        --spec /workspace/api/openapi.yaml \
        --target https://api.example.com \
        --fail-on HIGH \
        --format sarif \
        --output /workspace/apiguard-results.sarif
```

### With Authentication

```bash
docker run --rm \
    -v "$(pwd)":/workspace \
    -e APIGUARD_AUTH_TOKEN="${API_AUTH_TOKEN}" \
    ghcr.io/opensecstack/apiguard:latest \
    scan \
        --spec /workspace/api/openapi.yaml \
        --target https://api.example.com \
        --auth-token "${APIGUARD_AUTH_TOKEN}" \
        --format sarif \
        --output /workspace/apiguard-results.sarif
```

### Pinned Version

```bash
docker run --rm \
    -v "$(pwd)":/workspace \
    ghcr.io/opensecstack/apiguard:0.5.2 \
    scan \
        --spec /workspace/api/openapi.yaml \
        --target https://api.example.com \
        --format sarif \
        --output /workspace/apiguard-results.sarif
```

### Docker Compose (for local development and testing)

```yaml
# docker-compose.ci.yml
services:
  apiguard-scan:
    image: ghcr.io/opensecstack/apiguard:latest
    volumes:
      - .:/workspace
    command: >
      scan
        --spec /workspace/api/openapi.yaml
        --target http://api:8080
        --fail-on HIGH
        --format sarif
        --output /workspace/apiguard-results.sarif
    depends_on:
      - api

  api:
    build: .
    ports:
      - "8080:8080"
```

---

## Best Practices

### Run on Every Pull Request

Run APIGuard on every PR to catch regressions before they reach the main branch. Use `--fail-on HIGH` to block PRs that introduce high-severity findings without being overly noisy about medium/low issues.

### Use Baseline Comparison on Main

Commit or store the latest scan result from the main branch as a baseline. On PRs, pass `--baseline` to compare against it. This ensures only **new** findings introduced by the PR are evaluated, which avoids forcing teams to fix all pre-existing issues before adopting APIGuard.

### Fail on HIGH and Above

The default `--fail-on HIGH` threshold is recommended for most teams. CRITICAL and HIGH findings represent direct exploitation risk (auth bypass, BOLA, SSRF, data exposure). Failing on MEDIUM tends to produce too much noise from informational headers and rate limiting gaps that may be intentionally deferred.

### Always Upload SARIF

Upload SARIF results regardless of the scan outcome (`if: always()` in GitHub Actions, `when: always` in GitLab). This ensures:

- Security teams have visibility into all findings, not just failures.
- Trends are tracked over time in the GitHub Security tab or GitLab Security Dashboard.
- Resolved findings are recorded when using baseline comparison.

### Skip Slow Modules in CI

Modules `a6_business_flow` and `a10_unsafe_consumption` are disabled by default because they require manual configuration and are significantly slower. Do not enable them in CI unless you have explicitly configured them and accepted the additional execution time.

### Pin the APIGuard Version

Use a specific version tag (`opensecstack/apiguard-action@v1.2.3`, `ghcr.io/opensecstack/apiguard:0.5.2`) rather than `latest` in production CI pipelines. This prevents unexpected changes in scan behaviour when a new version is released.

### Secure the Auth Token

Never hardcode API authentication tokens in pipeline configuration. Use your CI platform's secrets management:

- **GitHub Actions**: `${{ secrets.API_AUTH_TOKEN }}`
- **GitLab CI**: CI/CD Variables (masked, protected)
- **Jenkins**: `credentials()` binding
- **Generic**: Environment variables injected by the CI platform's secrets store
