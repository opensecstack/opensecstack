# opensecstack Ecosystem Changelog

All notable ecosystem-level changes are documented here.
Platform-specific changelogs: [APIGuard](apiguard/CHANGELOG.md) | [NIS2 Compass](nis2compass/CHANGELOG.md)

## [Unreleased]

### Ecosystem
- Root-level CI/CD orchestration workflow
- Cross-platform integration test suite
- Ecosystem-wide SAST and dependency auditing
- CITADEL governance engine — live MARSHAL decision engine (in development)

### Added
- `.github/CODEOWNERS` — code ownership for all platforms
- `.github/dependabot.yml` — automated dependency updates for all package ecosystems
- `.github/pull_request_template.md` — standardised PR checklist
- `.github/ISSUE_TEMPLATE/` — bug, feature, and security issue templates
- `GOVERNANCE.md` — maintainer structure, RFC process, release policy
- `pyproject.toml` (NIS2 Compass) — black, isort, mypy, pytest configuration
- `.golangci.yml` (APIGuard) — extended Go linter configuration with gosec, errcheck

---

## [0.1.0] - 2025-Q1

### Platforms launched
- **APIGuard v0.1.0** — API security testing with full OWASP API Top 10 coverage, CVSS 3.1, SARIF output
- **NIS2 Compass MVP** — NIS2 Article 21(2) compliance assessment (all 10 measures A–J), PDF reports, CITADEL webhook integration

### SDK
- **opensecstack Go SDK** — typed clients for APIGuard and NIS2 Compass, zero external HTTP dependencies
- **opensecstack Python SDK** — typed clients with thread-safe token caching and proactive refresh

### Infrastructure
- Docker Compose for development, testing, and production stacks
- Kubernetes manifests (`deploy/k8s/`) for production deployment
- Multi-stage Docker builds for both platforms (~50MB APIGuard, minimal NIS2 Compass)
- GitHub Actions CI for APIGuard (Go + Rust + React) and NIS2 Compass (Python + React)

### Governance
- Architecture Decision Records: ADR-001 (Rust for parsing), ADR-002 (Go for HTTP/orchestration)
- RFCs: Template and submission process established
- SECURITY.md: Responsible disclosure policy
- CONTRIBUTING.md: Language-specific contribution standards
- CODE_OF_CONDUCT.md: Community standards
- CLA.md: Contributor License Agreement
