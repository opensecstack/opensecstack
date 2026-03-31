# opensecstack

> Open-source cybersecurity ecosystem for Europe and beyond.

**8 integrated security platforms + 1 governance layer.**
Built for NIS2 compliance, API security, incident response, threat intelligence, and security operations — all connected through a typed SDK and governed by an immutable audit trail.

---

## Table of Contents

- [Why opensecstack](#why-opensecstack)
- [The Ecosystem](#the-ecosystem)
- [Architecture](#architecture)
- [Active Platforms](#active-platforms)
  - [APIGuard](#apiguard)
  - [NIS2 Compass](#nis2-compass)
  - [CITADEL](#citadel)
- [Planned Platforms](#planned-platforms)
- [SDK](#sdk)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Security](#security)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Community](#community)
- [Licence](#licence)

---

## Why opensecstack

European organisations face a growing regulatory and threat landscape:

- **NIS2 Directive** mandates incident response, supply chain security, and regular risk assessments for essential and important entities.
- **API-first architectures** expose new attack surfaces not covered by traditional WAFs.
- **Fragmented tooling** means security teams operate across disconnected products with no unified audit trail.

opensecstack provides a **cohesive, open-source alternative**: every platform shares the same SDK contracts, every action flows into the same governance layer, and every deployment can be self-hosted with zero vendor lock-in.

---

## The Ecosystem

| Platform | What It Does | Stack | Licence | Status |
|----------|-------------|-------|---------|--------|
| [**APIGuard**](apiguard/) | API security testing — OWASP API Top 10 (A1–A10), CVSS 3.1 scoring, SARIF/HTML/PDF/JSON reports | Go + Rust + React | Apache 2.0 | Active |
| [**NIS2 Compass**](nis2compass/) | NIS2 Article 21(2) compliance assessment, evidence management, PDF reporting | Python + Go + React | AGPL-3.0 | Active |
| **ThreatFlow** | Threat intelligence aggregation, IOC correlation, STIX 2.1 bundles | Rust + Go | Apache 2.0 | Planned |
| **IRFlow** | Incident response orchestration with NIS2 72-hour notification support | Go + Python | AGPL-3.0 | Planned |
| **OpenScrub** | DDoS mitigation at kernel level via XDP/eBPF | Rust + C | Apache 2.0 | Planned |
| **CyberPath** | Security awareness training and certification | Go + React | Apache 2.0 | Planned |
| **SecureLab** | Attack simulation and detection rule validation | Python + Rust | Apache 2.0 | Planned |
| **OpenCSIRT** | National/sector CSIRT operations and advisory management | Go + Python | AGPL-3.0 | Planned |

**Governance:** [**CITADEL**](.citadel/) — immutable audit trail, SHA-256 chain anchors, MARSHAL authorisation engine, BEACON risk scoring, PATROL anomaly detection, separation of duties enforcement. Built by Security Intelligence Group (SIG).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        opensecstack ecosystem                        │
│                                                                      │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │
│  │ APIGuard │  │NIS2Compass│  │ ThreatFlow │  │    IRFlow      │  │
│  │ (API sec)│  │(compliance│  │ (threat    │  │ (incident resp)│  │
│  │          │  │  mgmt)    │  │  intel)    │  │                │  │
│  └────┬─────┘  └─────┬─────┘  └─────┬──────┘  └───────┬────────┘  │
│       │              │              │                  │            │
│       └──────────────┴──────────────┴──────────────────┘            │
│                              │                                       │
│                    opensecstack/sdk                                  │
│               (typed contracts, event schemas)                       │
│                              │                                       │
│       ┌───────────────────────────────────────────────┐             │
│       │                   CITADEL                     │             │
│       │  MARSHAL (authz) · BEACON (risk) · PATROL    │             │
│       │  WORM log · SHA-256 chain · SoD enforcement  │             │
│       └───────────────────────────────────────────────┘             │
└─────────────────────────────────────────────────────────────────────┘
```

All platforms communicate through the [opensecstack SDK](sdk/) using **typed JSON contracts**. Supported event schemas:

| Contract | Format | Producers → Consumers |
|----------|--------|-----------------------|
| Scan Result | JSON v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass |
| IOC Bundle | STIX 2.1 v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT |
| Incident Record | JSON v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL |
| Compliance Evidence | JSON v1 | NIS2 Compass → CITADEL |
| CITADEL Event | JSON v2.0 | Any platform → CITADEL |
| Training Record | JSON v1 | CyberPath → NIS2 Compass, CITADEL |
| Advisory | CSAF 2.0 v1 | OpenCSIRT → ThreatFlow |
| Simulation Result | JSON v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow |

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full architecture diagram and data-flow map.

---

## Active Platforms

### APIGuard

**Automated API security testing against the OWASP API Security Top 10.**

- Parses OpenAPI 3.x and Swagger 2.0 schemas (Rust-powered parser; GraphQL planned)
- Tests A1 (Broken Object Level Authorisation) through A10 (Unsafe Consumption of APIs)
- CVSS 3.1 scoring for every finding
- Reports in JSON, SARIF, HTML, and PDF
- CI/CD integration (GitHub Actions, GitLab CI, Jenkins)
- Custom rule support with YAML/TOML definitions
- JWT/API-key authentication support for testing protected endpoints
- Fully self-hosted — no data leaves your infrastructure

```bash
cd apiguard && make dev
# API on :8080, web UI on :3000
```

**Stack:** Go 1.22 · Rust 1.76+ · React + TypeScript + Vite · PostgreSQL 16 · Redis 7

See [apiguard/README.md](apiguard/README.md) and [apiguard/docs/](apiguard/docs/) for the full reference.

---

### NIS2 Compass

**NIS2 Article 21(2) compliance management — from gap assessment to PDF evidence.**

- Maps controls to all 10 NIS2 Article 21(2) measures (risk management, incident handling, supply chain, cryptography, access control, etc.)
- Manages assessments across multiple organisations
- Tracks control status: `not_started` → `in_progress` → `compliant` / `non_compliant`
- Uploads and links evidence artifacts to controls (policy documents, screenshots, certificates)
- Generates signed PDF compliance reports via ReportLab
- Immutable audit log with SHA-256 CITADEL chain anchors
- JWT authentication with scoped API keys (`read` / `read_write`)
- Rate limiting, trusted proxy support, per-endpoint pagination caps

```bash
cd nis2compass && docker compose -f docker-compose.dev.yml up
# API on :8090, web UI on :3001
```

**Stack:** Python 3.12 · Flask 3.0 · SQLAlchemy 2.0 · PostgreSQL 16 · Redis 7 · ReportLab 4.2 · Alembic · Gunicorn

See [nis2compass/README.md](nis2compass/README.md) for the full reference.

**NIS2 Article 21(2) coverage:**

| Measure | Description |
|---------|-------------|
| A | Risk analysis and information system security policies |
| B | Incident handling |
| C | Business continuity, backup management, disaster recovery |
| D | Supply chain security |
| E | Security in network and information systems acquisition/development/maintenance |
| F | Policies and procedures to assess effectiveness of cybersecurity risk-management measures |
| G | Basic cyber hygiene practices and cybersecurity training |
| H | Policies and procedures regarding the use of cryptography |
| I | Human resources security, access control and asset management |
| J | Use of multi-factor authentication or continuous authentication solutions |

---

### CITADEL

**Governance layer for the opensecstack ecosystem.**

CITADEL is built and maintained by Security Intelligence Group (SIG). It provides:

- **MARSHAL** — authorisation engine with policy-based access control
- **BEACON** — real-time risk scoring engine
- **PATROL** — anomaly detection and behavioural baselining
- **WORM audit log** — append-only audit entries with PostgreSQL advisory locks
- **SHA-256 chain anchors** — tamper-evident hash chain linking every audit event
- **Separation of duties** — enforced at the governance layer, not just the application layer
- **Evidence vault** — cryptographically verified compliance evidence storage

CITADEL runs as a standalone service and receives events from all platforms via webhook.

See [.citadel/README.md](.citadel/README.md) for architecture and integration details.

---

## Planned Platforms

| Platform | Target | Key Capabilities |
|----------|--------|-----------------|
| **ThreatFlow** | Phase 4 | STIX 2.1 IOC ingestion, threat feeds, correlation engine |
| **IRFlow** | Phase 4 | Incident playbooks, NIS2 72h notification drafting, SOAR connectors |
| **OpenScrub** | Phase 5 | XDP/eBPF DDoS mitigation, rate limiting at kernel level |
| **CyberPath** | Phase 5 | Awareness training, phishing simulations, certification tracking |
| **SecureLab** | Phase 5 | Attack simulation, detection rule testing, purple-team support |
| **OpenCSIRT** | Phase 5 | CSIRT case management, CSAF advisory publishing, sector coordination |

See [ROADMAP.md](ROADMAP.md) for phase timelines and deliverables.

---

## SDK

The [opensecstack SDK](sdk/) provides typed clients in **Go, Python, TypeScript, and Rust** — the same clients used internally between platforms.

### Go SDK

Zero external dependencies. Requires Go 1.21+.

```go
import "github.com/opensecstack/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewAPIGuardClient("https://apiguard.example.com", "your-api-key")
scan, err := client.CreateScan(ctx, "https://api.example.com/openapi.json")
findings, err := client.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
    PerPage: 100,
    Severity: "critical",
})
```

### Python SDK

Requires Python 3.10+ and `requests >= 2.31`.

```python
from opensecstack import APIGuardClient

client = APIGuardClient("https://apiguard.example.com", api_key="your-api-key")
scan = client.create_scan(spec_url="https://api.example.com/openapi.json")
findings = client.get_findings(scan["id"])
```

### TypeScript SDK

Zero external dependencies. Requires Node.js 18+. Published as `@opensecstack/sdk` on npm.

```typescript
import { APIGuardClient } from "@opensecstack/sdk";

const client = new APIGuardClient({
  baseURL: "https://apiguard.example.com",
  apiKey: "your-api-key",
});
const scan = await client.createScan("https://api.example.com/openapi.json");
const findings = await client.getFindings(scan.id);
```

### Rust SDK

Async-first with tokio + reqwest. Requires Rust 1.75+.

```rust
use opensecstack::APIGuardClient;

let client = APIGuardClient::new("https://apiguard.example.com", "your-api-key");
let scan = client.create_scan("https://api.example.com/openapi.json").await?;
let findings = client.get_findings(&scan.id, Default::default()).await?;
```

All clients handle JWT acquisition and refresh automatically, retry on 5xx with exponential backoff, and emit structured warning logs on persistent auth failures.

See [sdk/README.md](sdk/README.md) · [sdk/go/](sdk/go/) · [sdk/python/](sdk/python/) · [sdk/typescript/](sdk/typescript/) · [sdk/rust/](sdk/rust/).

---

## Quick Start

### Full Ecosystem (Docker Compose)

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Copy and fill in secrets
cp deploy/.env.example deploy/.env
# Required: POSTGRES_PASSWORD, NIS2_DB_PASSWORD, REDIS_PASSWORD,
#           APIGUARD_JWT_SECRET, NIS2_SECRET_KEY, NIS2_JWT_SECRET

docker compose -f deploy/docker-compose.yml up -d
```

| Service | URL |
|---------|-----|
| APIGuard API | http://localhost:8080 |
| APIGuard UI | http://localhost:3000 |
| NIS2 Compass API | http://localhost:8090 |
| NIS2 Compass UI | http://localhost:3001 |

### Single Platform

```bash
# APIGuard only
cd apiguard
make dev            # hot-reload dev stack (API + Rust parser + UI)
make test           # full test suite (Go + Rust + integration)
make scan-example   # scan VAmPI as a quick demonstration

# NIS2 Compass only
cd nis2compass
docker compose -f docker-compose.dev.yml up
```

### Kubernetes

Production-ready Kubernetes manifests are in [deploy/k8s/](deploy/k8s/).

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/secrets.yaml        # fill in before applying
kubectl apply -f deploy/k8s/configmap.yaml
kubectl apply -f deploy/k8s/postgres/
kubectl apply -f deploy/k8s/redis/
kubectl apply -f deploy/k8s/apiguard/
kubectl apply -f deploy/k8s/nis2compass/
```

---

## Deployment

### Environment Variables

The full stack requires the following environment variables (see [deploy/.env.example](deploy/.env.example)):

| Variable | Required By | Description |
|----------|-------------|-------------|
| `POSTGRES_PASSWORD` | All | PostgreSQL superuser password |
| `NIS2_DB_PASSWORD` | NIS2 Compass | NIS2 database password |
| `REDIS_PASSWORD` | NIS2 Compass | Redis password |
| `APIGUARD_JWT_SECRET` | APIGuard | JWT signing secret (min 32 bytes) |
| `NIS2_JWT_SECRET` | NIS2 Compass | JWT signing secret (min 32 bytes) |
| `NIS2_SECRET_KEY` | NIS2 Compass | Flask session secret |
| `NIS2_WEBHOOK_SECRET` | NIS2 Compass | HMAC secret for CITADEL webhooks (required when `NIS2_WEBHOOK_URL` is set) |
| `CITADEL_API_KEY` | All (optional) | CITADEL governance forwarding key |

### Make Targets (root)

| Target | Description |
|--------|-------------|
| `make dev` | Start full ecosystem with hot reload |
| `make up` | Start production stack detached |
| `make test` | Run all platform test suites |
| `make build` | Build all Docker images |
| `make lint` | Run all linters (golangci-lint, clippy, eslint) |
| `make fmt` | Format all code (gofmt, rustfmt, prettier) |
| `make migrate` | Run database migrations |
| `make clean` | Remove all containers, volumes, and build artifacts |

---

## Security

We take security seriously across every platform:

- **No default secrets** — all sensitive values must be explicitly configured; the app refuses to start if credentials are absent
- **JWT authentication** with configurable TTL and scoped API keys (`read` / `read_write`)
- **Immutable audit trail** on every write operation, with SHA-256 CITADEL chain anchors
- **Rate limiting** on all endpoints with trusted-proxy support
- **Input validation** at every API boundary — pagination caps, MIME-type checks, path traversal prevention
- **Constant-time comparisons** for API key validation to prevent timing attacks
- **CORS** configured per-environment with explicit origin allowlisting

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

## Documentation

### Ecosystem

| Document | Description |
|----------|-------------|
| [ECOSYSTEM.md](ECOSYSTEM.md) | Full architecture diagram, data-flow map, integration contracts, licensing rationale |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, component interactions, deployment topology |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance model, decision-making process |
| [ROADMAP.md](ROADMAP.md) | Phase-by-phase delivery plan |
| [CHANGELOG.md](CHANGELOG.md) | Project-wide changelog |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guide — code, docs, security research |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [docs/security-architecture.md](docs/security-architecture.md) | Security architecture — five-layer defence model |
| [docs/tds-integration.md](docs/tds-integration.md) | TDS integration guide for new platform components |
| [adrs/](adrs/) | Architecture Decision Records |
| [rfcs/](rfcs/) | Request for Comments |

### Platform Documentation

| Platform | Reference |
|----------|-----------|
| APIGuard | [apiguard/README.md](apiguard/README.md) · [apiguard/docs/](apiguard/docs/) (22 guides) |
| NIS2 Compass | [nis2compass/README.md](nis2compass/README.md) · [nis2compass/docs/](nis2compass/docs/) (16 guides) |
| CITADEL | [.citadel/README.md](.citadel/README.md) · [.citadel/docs/](.citadel/docs/) (26 guides) |
| IRFlow | [irflow/README.md](irflow/README.md) · [irflow/docs/](irflow/docs/) |
| ThreatFlow | [threatflow/README.md](threatflow/README.md) · [threatflow/docs/](threatflow/docs/) (21 guides) |
| Go SDK | [sdk/go/README.md](sdk/go/README.md) · [sdk/go/RELEASING.md](sdk/go/RELEASING.md) |
| Python SDK | [sdk/python/README.md](sdk/python/README.md) |
| TypeScript SDK | [sdk/typescript/README.md](sdk/typescript/README.md) · [sdk/typescript/RELEASING.md](sdk/typescript/RELEASING.md) |
| Rust SDK | [sdk/rust/README.md](sdk/rust/README.md) |
| SDK Docs | [sdk/docs/](sdk/docs/) (8 guides) |
| Kubernetes | [deploy/k8s/README.md](deploy/k8s/README.md) |
| Website | [website/README.md](website/README.md) |

### Architecture Decision Records

| ADR | Decision |
|-----|----------|
| [ADR-001](adrs/ADR-001-rust-for-parsing.md) | Rust for the OpenAPI/GraphQL parsing and analysis layer |
| [ADR-002](adrs/ADR-002-go-for-http-and-orchestration.md) | Go for HTTP servers and orchestration |
| [ADR-009](adrs/ADR-009-time-dimension-segmentation.md) | Time Dimension Segmentation (TDS) |

---

## Roadmap

| Phase | Theme | Key Deliverables |
|-------|-------|-----------------|
| **Phase 1** (current) | Foundation | APIGuard A1–A3, CITADEL governance engine, Go SDK |
| **Phase 2** | Full OWASP + CI/CD | APIGuard A4–A10, CVSS 3.1, SARIF, Python SDK, GitLab/Jenkins |
| **Phase 3** | Dashboard + Multi-tenant | React dashboard, RBAC, API key management, NIS2 Compass release |
| **Phase 4** | Governance Integration | CITADEL integration, IRFlow release, ThreatFlow release |
| **Phase 5** | Production + Ecosystem | APIGuard v1.0, OpenScrub, CyberPath, SecureLab, OpenCSIRT |

See [ROADMAP.md](ROADMAP.md) for full details and per-platform sub-roadmaps.

---

## Contributing

We welcome contributions to every platform — code, tests, documentation, translations, and security research.

**Getting started:**

1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Look for `good first issue` labels across the platform issues
3. Join the conversation in GitHub Discussions or Discord

**Development setup** for each platform is documented in its own `README.md`. The root `Makefile` orchestrates the full stack.

**All contributors** are bound by the [Contributor License Agreement](CLA.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

---

## Community

- **GitHub Discussions** — questions, ideas, show & tell
- **Discord** — real-time chat (`#general`, `#contributors`, per-platform channels)
- **Monthly community calls** — open to all, schedule in [community/MEETINGS.md](community/MEETINGS.md)

| Resource | Description |
|----------|-------------|
| [community/README.md](community/README.md) | Community hub and programme overview |
| [community/GOOD-FIRST-ISSUES.md](community/GOOD-FIRST-ISSUES.md) | Curated starter issues for new contributors |
| [community/AMBASSADORS.md](community/AMBASSADORS.md) | EU regional ambassador profiles |
| [community/HALL-OF-FAME.md](community/HALL-OF-FAME.md) | Outstanding contributor recognition |
| [community/MEETINGS.md](community/MEETINGS.md) | Meeting schedule and host rotation |
| [community/MENTORSHIP.md](community/MENTORSHIP.md) | Mentorship programme and mentor profiles |

---

## Licence

| Category | Licence | Platforms |
|----------|---------|-----------|
| Tool platforms | [Apache 2.0](LICENSE) | APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab |
| Governance platforms | AGPL-3.0 | IRFlow, NIS2 Compass, OpenCSIRT, CITADEL |
| SDK | Apache 2.0 | opensecstack/sdk |

**Why two licences?** Tool platforms are permissive so they can be embedded in CI/CD pipelines and commercial workflows. Governance platforms are copyleft so any modifications to the audit trail, compliance reporting, or CSIRT operations must remain open source. See [ECOSYSTEM.md](ECOSYSTEM.md) for the full rationale.
