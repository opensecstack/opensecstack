# opensecstack Roadmap

> Public roadmap for the opensecstack ecosystem.

## Current Status (as of Q1 2025)

### Completed
- **APIGuard v0.1.0** — Full OWASP API Top 10 (A1–A10), CVSS 3.1, SARIF, HTML/PDF/JSON reports, React dashboard, Go + Python SDK, Kubernetes manifests
- **NIS2 Compass MVP** — All 10 NIS2 Article 21(2) measures, PDF reports, CITADEL webhook integration, artifact evidence management
- **opensecstack SDK** — Go and Python typed clients for APIGuard and NIS2 Compass
- **CITADEL integration** — Webhook-based audit event forwarding from both platforms (HMAC-SHA256 signed)

### In Progress
- CITADEL governance engine — standalone MARSHAL decision engine deployment
- Ecosystem CI/CD — root-level orchestration and cross-platform integration tests
- Test coverage expansion — unit tests for db, middleware, handlers packages

## Phase 1 — Foundation (Current)

| Deliverable | Status |
|-------------|--------|
| APIGuard v0.1.0 — OpenAPI parser, A1-A3 modules, CLI, reports | Done |
| CITADEL governance engine — MARSHAL, BEACON, PATROL, WORM log, chain anchors | In Development |
| opensecstack/sdk — initial Go client, event schemas | Done |
| Ecosystem documentation and architecture | Done |

## Phase 2 — Full OWASP + CI/CD

| Deliverable | Status |
|-------------|--------|
| APIGuard v0.2.0 — A4-A10 modules, CVSS 3.1, SARIF output | Done |
| APIGuard v0.3.0 — GitLab CI, Jenkins, GraphQL support, baseline comparison | Planned |
| opensecstack/sdk — Python client, OpenAPI contracts | Done |

## Phase 3 — Dashboard + Multi-tenant

| Deliverable | Status |
|-------------|--------|
| APIGuard v0.4.0 — React dashboard, scan history, finding management, API inventory, regression detection | Done |
| APIGuard v0.5.0 — Teams, RBAC, API keys, multi-project | Done |
| NIS2 Compass — initial release | Done |

## Phase 4 — Governance Integration

| Deliverable | Status |
|-------------|--------|
| APIGuard v0.6.0 — CITADEL integration, MARSHAL scan governance, WORM audit trail | Planned |
| IRFlow — initial release | Planned |
| ThreatFlow — initial release | Planned |

## Phase 5 — Production + Ecosystem

| Deliverable | Status |
|-------------|--------|
| APIGuard v1.0.0 — security audit, performance benchmarks, HA deployment | Planned |
| OpenScrub — initial release | Planned |
| CyberPath — initial release | Planned |
| SecureLab — initial release | Planned |
| OpenCSIRT — initial release | Planned |

## Platform-Specific Roadmaps

- [APIGuard Roadmap](apiguard/ROADMAP.md)

## How We Plan

- Roadmap is updated quarterly
- Community input via [GitHub Discussions](https://github.com/opensecstack/opensecstack/discussions)
- Significant changes require an [RFC](rfcs/)
- Architecture decisions are recorded in [ADRs](adrs/)
