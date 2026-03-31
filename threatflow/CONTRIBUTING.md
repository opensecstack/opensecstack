# Contributing to ThreatFlow

Thank you for your interest in contributing to ThreatFlow. This document covers the platform-specific guidelines. For ecosystem-wide contribution rules, see the root [CONTRIBUTING.md](../CONTRIBUTING.md).

## Prerequisites

- Go 1.22+
- PostgreSQL 16+ (for integration tests)
- Docker 24+ (for full-stack testing)
- golangci-lint (for linting)

## Getting Started

```bash
cd threatflow
cp .env.example .env        # configure local settings
make test                    # run tests
make lint                    # run linter
make run                     # start server in dev mode
```

## Code Structure

| Directory | Purpose |
|-----------|---------|
| `cmd/threatflow/` | CLI entrypoint (Cobra) |
| `internal/api/` | HTTP handlers and routing (chi) |
| `internal/config/` | Viper configuration |
| `internal/version/` | Build-time version info |
| `internal/feed/` | *(planned)* Feed polling |
| `internal/stix/` | *(planned)* STIX 2.1 parser |
| `internal/correlate/` | *(planned)* Correlation engine |
| `internal/db/` | *(planned)* PostgreSQL layer |

## Commit Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(feed): add TAXII 2.1 polling client
fix(stix): handle missing indicator pattern field
test(ioc): add deduplication edge case tests
docs(api): document PATCH /iocs/{id} endpoint
```

## Pull Request Checklist

- [ ] Tests pass: `make test`
- [ ] Linter passes: `make lint`
- [ ] New endpoints documented in `docs/api-reference.md`
- [ ] CHANGELOG.md updated if user-facing
- [ ] No secrets committed (check `.env` is in `.gitignore`)

## Security

Report vulnerabilities via [SECURITY.md](SECURITY.md), never in public issues.
