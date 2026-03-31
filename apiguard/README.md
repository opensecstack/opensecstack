# APIGuard

> Point APIGuard at any OpenAPI spec. Get a complete OWASP API Top 10 security report automatically.

Open Source API Security Testing Framework | OWASP API Top 10 | Go + Rust + React + PostgreSQL

## What It Does

- **Parses** OpenAPI/Swagger schemas into a normalised internal representation (GraphQL planned)
- **Runs** OWASP API Top 10 security tests against your live API endpoints
- **Outputs** HTML/PDF/JSON/SARIF reports with CVSS 3.1 scoring and remediation guidance

## OWASP API Top 10 Coverage

| ID  | Vulnerability                              | Status |
|-----|--------------------------------------------|--------|
| A1  | Broken Object Level Authorization (BOLA)   | ✅ Implemented |
| A2  | Broken Authentication                      | ✅ Implemented |
| A3  | Broken Object Property Level Authorization | ✅ Implemented |
| A4  | Unrestricted Resource Consumption          | ✅ Implemented |
| A5  | Broken Function Level Authorization        | ✅ Implemented |
| A6  | Unrestricted Access to Sensitive Flows     | ✅ Implemented |
| A7  | Server Side Request Forgery (SSRF)         | ✅ Implemented |
| A8  | Security Misconfiguration                  | ✅ Implemented |
| A9  | Improper Inventory Management              | ✅ Implemented |
| A10 | Unsafe Consumption of APIs                 | ✅ Implemented |

## Quick Start

```bash
# Clone
git clone https://github.com/opensecstack/apiguard
cd apiguard

# Copy environment config
cp .env.example .env

# Start the full local stack
make dev

# Run a scan
apiguard scan --spec ./api/openapi.yaml --target http://localhost:8080 --format html
```

## CI/CD Integration

```yaml
# .github/workflows/api-security.yml
name: API Security Scan
on: [push, pull_request]

jobs:
  apiguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run APIGuard
        uses: opensecstack/apiguard-action@v1
        with:
          spec: ./api/openapi.yaml
          target: ${{ secrets.API_TARGET_URL }}
          fail-on: HIGH
          format: sarif
          output: apiguard-results.sarif
      - name: Upload to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: apiguard-results.sarif
```

## Documentation

See the [docs/](docs/) directory for full documentation including:

- [Quick Start](docs/quick-start.md)
- [Architecture Overview](docs/architecture.md)
- [OWASP Coverage Map](docs/owasp-coverage.md)
- [CLI Reference](docs/cli-reference.md)
- [Configuration Reference](docs/configuration.md)
- [API Reference](docs/api.md)
- [Parser Specification](docs/parser-spec.md)
- [Report Formats](docs/report-formats.md)
- [CI/CD Integration](docs/cicd-integration.md)
- [Custom Rule Writing](docs/custom-rules.md)
- [Testing Guide](docs/testing.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Development Setup](docs/dev/setup.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started. Look for issues labelled `good first issue`.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
