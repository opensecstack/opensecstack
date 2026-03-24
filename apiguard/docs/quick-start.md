# APIGuard Quick Start

From zero to your first API security scan in 5 minutes.

## Prerequisites

- [Docker](https://docker.com) 24+ (or Go 1.22+ and Rust 1.76+ for local install)

## Option 1: Docker (Fastest)

```bash
# Scan an API directly
docker run --rm ghcr.io/opensecstack/apiguard:latest scan \
  --spec https://petstore3.swagger.io/api/v3/openapi.json \
  --target https://petstore3.swagger.io \
  --format json
```

## Option 2: Binary

```bash
# Download (Linux amd64)
curl -fsSL https://github.com/opensecstack/apiguard/releases/latest/download/apiguard-linux-amd64.tar.gz | tar xz
sudo mv apiguard /usr/local/bin/

# Scan
apiguard scan --spec ./api/openapi.yaml --target http://localhost:8080 --format html --output report.html
```

## Option 3: Local Development Stack

```bash
git clone https://github.com/opensecstack/apiguard
cd apiguard
cp .env.example .env
make dev

# Verify
curl http://localhost:8080/api/v1/health
# → {"status":"ok","version":"0.1.0"}
```

## Run Against a Vulnerable Test Target

APIGuard ships with VAmPI (a deliberately vulnerable API) for testing:

```bash
cd apiguard

# Start the test target
docker compose -f docker-compose.test.yml up -d

# Run a scan against it
apiguard scan \
  --spec ./tests/integration/vampi-openapi.yaml \
  --target http://localhost:5000 \
  --format html \
  --output report.html

# Or use the make shortcut
make scan-example
```

## Understanding Results

Each finding includes:

| Field | Description |
|-------|-------------|
| **OWASP ID** | Which OWASP API Top 10 category (A1-A10) |
| **Severity** | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| **CVSS Score** | Numeric score (0.0-10.0) per CVSS 3.1 |
| **Endpoint** | The affected API endpoint |
| **Evidence** | Request/response pair proving the vulnerability |
| **Remediation** | How to fix the issue |

## CI/CD Integration

Add APIGuard to your pipeline in one step:

```yaml
# .github/workflows/api-security.yml
- uses: opensecstack/apiguard-action@v1
  with:
    spec: ./api/openapi.yaml
    target: ${{ secrets.API_TARGET_URL }}
    fail-on: HIGH
    format: sarif
    output: apiguard-results.sarif
```

See [CI/CD Integration Guide](cicd-integration.md) for GitHub Actions, GitLab CI, and Jenkins examples.

## Next Steps

- [Configuration Reference](configuration.md) — all options and settings
- [CLI Reference](cli-reference.md) — all commands and flags
- [OWASP Coverage Map](owasp-coverage.md) — what APIGuard tests and how
- [Custom Rules](custom-rules.md) — write your own security rules
- [Report Formats](report-formats.md) — JSON, SARIF, HTML, PDF output
- [Architecture Overview](architecture.md) — how APIGuard works internally
