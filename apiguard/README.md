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

See the [docs/](docs/) directory for full documentation.

### Getting Started

| Document | Description |
|----------|-------------|
| [Quick Start](docs/quick-start.md) | From zero to your first API security scan in 5 minutes |
| [User Guide](docs/user-guide.md) | Full workflow: running scans, reading results, managing findings, and using the dashboard |

### Architecture & Internals

| Document | Description |
|----------|-------------|
| [Architecture Overview](docs/architecture.md) | Layered pipeline design, component responsibilities, and input/output contracts |
| [Data Model](docs/data-model.md) | APIGuard IR (Intermediate Representation) that normalises all supported schema formats |
| [Parser Specification](docs/parser-spec.md) | Supported input formats (OpenAPI 3.x, Swagger 2.x, GraphQL) and parsing behaviour |

### API & CLI

| Document | Description |
|----------|-------------|
| [REST API Reference](docs/api.md) | Full REST API reference for the APIGuard server (JWT-authenticated, JSON responses) |
| [CLI Reference](docs/cli-reference.md) | Single Go binary covering the scan pipeline, report generation, and rule management |
| [Configuration Reference](docs/configuration.md) | Every configurable setting across CLI flags, environment variables, and config files |

### Authentication

APIGuard authenticates users via sinauth SSO using OpenID Connect (authorization_code + PKCE).
ID and access tokens are RS256-signed and validated against the sinauth JWKS endpoint.
The web dashboard uses `sinauth.ts` for popup-based login and an `AuthCallback` page.
Auth events are forwarded to the CITADEL WORM audit chain, and a `POST /api/v1/auth/logout` endpoint maintains an access-token denylist.
See the [sinauth integration guide](../sinauth/docs/integration/apiguard.md) for setup details.

### Security & Compliance

| Document | Description |
|----------|-------------|
| [OWASP Coverage Map](docs/owasp-coverage.md) | What APIGuard tests, detection methods, confidence levels, and known false positives |
| [Security Reference](docs/security.md) | APIGuard's own security model -- how it protects itself, its users, and scanned systems |
| [NIS2 Directive Mapping](docs/nis2-mapping.md) | Mapping APIGuard findings to NIS2 Article 21 security measures for compliance evidence |
| [Custom Rules Guide](docs/custom-rules.md) | Writing, loading, and managing custom security-check rules for organisation-specific checks |

### Reports & Integrations

| Document | Description |
|----------|-------------|
| [Report Formats](docs/report-formats.md) | Output formats (HTML, PDF, JSON, SARIF) and their generation pipeline |
| [CI/CD Integration](docs/cicd-integration.md) | Integrating APIGuard into CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, etc.) |
| [Integration Guide](docs/integration.md) | Outbound webhook events for integrating with other opensecstack platforms |
| [Forge Integration](docs/forge-integration.md) | Source code forge integration (GitHub, GitLab, Bitbucket, Azure DevOps) for PR scanning |

### Operations

| Document | Description |
|----------|-------------|
| [Operator Handbook](docs/operator-handbook.md) | Production deployment, operations, and maintenance reference |
| [Performance Reference](docs/performance.md) | Scan duration benchmarks, memory usage, and tuning guidance |
| [Testing Guide](docs/testing.md) | Test organisation, how to run tests, and how to write new tests |
| [Troubleshooting](docs/troubleshooting.md) | Common issues with installation, configuration, and scanning (problem-cause-solution format) |
| [FAQ](docs/faq.md) | Frequently asked questions about APIGuard behaviour, safety, and capabilities |

### Development

| Document | Description |
|----------|-------------|
| [Development Setup](docs/dev/setup.md) | Building, running, and testing APIGuard locally with all prerequisites |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to get started. Look for issues labelled `good first issue`.

## Licence

Apache 2.0 — see [LICENSE](LICENSE).
