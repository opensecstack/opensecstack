# opensecstack (SIN — Security Intelligence Network)

> Open-source cybersecurity ecosystem for Europe and beyond.

**11 integrated security platforms + 1 identity layer + 1 governance layer + 4-language SDK.**
Built for NIS2 compliance, API security, incident response, threat
intelligence, AI-attack defence, and security operations — all
connected through typed SDK contracts, fronted by a single sign-on
identity provider (sinauth), and governed by an immutable audit trail.

> **Status (Q2 2026):** All 11 platforms + SDK at v1.0.0 production.
> See [ROADMAP.md](ROADMAP.md) for the long-term roadmap.

---

## Table of Contents

- [Why opensecstack](#why-opensecstack)
- [The Ecosystem](#the-ecosystem)
- [Architecture](#architecture)
- [Production Platforms](#production-platforms)
  - [APIGuard](#apiguard)
  - [NIS2 Compass](#nis2-compass)
  - [IRFlow](#irflow)
  - [ThreatFlow](#threatflow)
  - [CITADEL](#citadel)
- [All Platforms](#the-ecosystem)
- [SDK](#sdk)
- [Quick Start](#quick-start)
- [Security & Maturity](#security--maturity)
- [Post-Quantum Strategy](#post-quantum-strategy)
- [Documentation](#documentation)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [Community](#community)
- [Licence](#licence)

---

## Why opensecstack

European organisations face a growing regulatory and threat landscape:

- **NIS2 Directive** mandates incident response, supply chain security,
  and regular risk assessments for essential and important entities.
- **EU AI Act** and projected **NIS3** will require AI-attack defence
  as a formal obligation by 2030-2032.
- **API-first architectures** expose attack surfaces not covered by
  traditional WAFs.
- **Fragmented tooling** leaves security teams operating across
  disconnected products with no unified audit trail.

opensecstack provides a **cohesive, open-source alternative**: every
platform shares the same SDK contracts, every action flows into the
same governance layer, and every deployment can be self-hosted with
zero vendor lock-in.

---

## The Ecosystem

| Platform | What it does | Stack | Licence | Status |
|----------|-------------|-------|---------|--------|
| [**APIGuard**](apiguard/) | API security testing — OWASP API Top 10 (A1–A10), CVSS 3.1, SARIF/HTML/PDF/JSON reports | Go + Rust + Python + React | Apache 2.0 | ✅ **v1.0.0** |
| [**NIS2 Compass**](nis2compass/) | NIS2 Article 21(2) compliance assessment, evidence management, Article 23 notification | Python + Go + React | AGPL-3.0 | ✅ **v1.0.0** |
| [**CITADEL**](citadel/) | Cryptographic governance engine — MARSHAL, WORM, NDS, AUGUR, chain anchors | Go | AGPL-3.0 | ✅ **v1.0.0** |
| [**IRFlow**](irflow/) | Incident response orchestration — playbooks, governed actions, NIS2 72-hour notification | Go + Python | AGPL-3.0 | ✅ **v1.0.0** |
| [**ThreatFlow**](threatflow/) | Threat intelligence aggregation — IOC ingestion, STIX 2.1, MITRE ATT&CK | Rust + Go | Apache 2.0 | ✅ **v1.0.0** |
| [**VertGuard**](vertguard/) | AI-attack defence — deepfake, prompt injection, AI threat intel, MITRE ATLAS | Go + Rust + Python | AGPL-3.0 | ✅ **v1.0.0** |
| [**OpenScrub**](openscrub/) | DDoS mitigation at kernel level (XDP/eBPF, GoBGP) | Rust + C + Go | Apache 2.0 | ✅ **v1.0.0** |
| [**CyberPath**](cyberpath/) | Security training — Docker/Wasm labs, NIS2 Art. 21(2)(g) evidence | Go + React + Python | Apache 2.0 | ✅ **v1.0.0** |
| [**SecureLab**](securelab/) | Attack simulation — MITRE ATT&CK coverage, detection validation | Python + Rust + Go | Apache 2.0 | ✅ **v1.0.0** |
| [**OpenCSIRT**](opencsirt/) | National/sector CSIRT operations — TAXII 2.1, STIX 2.1, CSAF 2.0 | Go + Python | AGPL-3.0 | ✅ **v1.0.0** |
| [**SIN Community**](community/) | Developer knowledge hub — posts, tags, full-text search, notifications, TOTP, API keys, spaces | Go + React + TypeScript | Apache 2.0 | ✅ **v1.0.0** |

**Identity layer:** [**sinauth**](sinauth/) — dedicated OAuth 2.0 /
OpenID Connect authorization server. One account grants access to every
SIN platform via single sign-on: RS256-signed ID/access tokens, JWKS
endpoint, authorization-code + PKCE (S256) flow, social login (Google,
GitHub), and TOTP MFA. What Auth0 is globally, sinauth is for SIN.
Apache 2.0, runs on `:8100`, issuer `https://auth.sin.to`. Per-platform
integration guides in [sinauth/docs/integration/](sinauth/docs/integration/).

**Governance layer:** CITADEL (above) — MARSHAL 5-gate decision
engine, WORM audit chain with TripleHash (SHA-256 + SHA-512 + BLAKE3)
+ Ed25519 anchors, NDS separation of duties, AUGUR behavioural
heuristics. VIGIL ecosystem health monitor is design-stage (v2.0).

**SDK:** [opensecstack/sdk](sdk/) — typed clients in Go, Python,
TypeScript, Rust. Shared Argon2id + pepper password hashing module
(byte-compatible across languages).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                     opensecstack (SIN) ecosystem                     │
│                                                                      │
│  ┌──────────┐  ┌───────────┐  ┌────────────┐  ┌────────────────┐  │
│  │ APIGuard │  │NIS2Compass│  │ ThreatFlow │  │    IRFlow      │  │
│  │ v1.0.0   │  │  v1.0.0   │  │  v1.0.0    │  │   v1.0.0       │  │
│  └────┬─────┘  └─────┬─────┘  └─────┬──────┘  └───────┬────────┘  │
│       │              │              │                  │            │
│  ┌────┴──────────────┴──────────────┴──────────────────┴───────┐   │
│  │              opensecstack/sdk (v1.0.0)                      │   │
│  │        Go · Python · TypeScript · Rust contracts            │   │
│  └─────────────────────────────┬───────────────────────────────┘   │
│                                │                                     │
│       ┌───────────────────────────────────────────────┐             │
│       │            CITADEL (v1.0.0, AGPL-3.0)         │             │
│       │  MARSHAL (5 gates) · WORM (TripleHash chain)  │             │
│       │  NDS (SoD) · AUGUR (behavioural heuristics)   │             │
│       │  Ed25519 anchors · VIGIL (planned v2.0)       │             │
│       └───────────────────────────────────────────────┘             │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │  VertGuard   │  │  OpenScrub   │  │  OpenCSIRT   │              │
│  │  v1.0.0 ✅   │  │  v1.0.0 ✅   │  │  v1.0.0 ✅   │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────────┐  │
│  │  CyberPath   │  │  SecureLab   │  │     SIN Community        │  │
│  │  v1.0.0 ✅   │  │  v1.0.0 ✅   │  │  v1.0.0 ✅               │  │
│  └──────────────┘  └──────────────┘  └──────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

All platforms communicate through the [opensecstack/sdk](sdk/) using
**typed JSON contracts**. Supported event schemas:

| Contract | Format | Producers → Consumers |
|----------|--------|-----------------------|
| Scan Result | JSON v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass |
| IOC Bundle | STIX 2.1 v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT |
| Incident Record | JSON v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL |
| Compliance Evidence | JSON v1 | NIS2 Compass → CITADEL |
| CITADEL Kerkese | JSON v2.0 | Any platform → CITADEL (MARSHAL input) |
| Training Record | JSON v1 | CyberPath → NIS2 Compass, CITADEL |
| Advisory | CSAF 2.0 v1 | OpenCSIRT → ThreatFlow |
| Simulation Result | JSON v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow, VertGuard |
| AI-Attack Detection | JSON v1 | VertGuard → CITADEL, IRFlow, ThreatFlow |
| Content Provenance | C2PA + JSON v1.3 | VertGuard Module 1 evidence envelope |

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full architecture diagram
and data-flow map.

---

## Production Platforms

### APIGuard

**Automated API security testing against the OWASP API Security Top 10.**

- Parses OpenAPI 3.x and Swagger 2.0 schemas (Rust-powered parser)
- Tests A1 (Broken Object Level Authorisation) through A10
- CVSS 3.1 scoring, reports in JSON, SARIF, HTML, PDF
- CI/CD integration (GitHub Actions, GitLab CI, Jenkins)
- Custom rules via YAML/TOML
- JWT/API-key authentication for protected endpoints
- Self-hosted — no data leaves your infrastructure

**Stack:** Go 1.24 · Rust 1.76+ · Python 3.12 · React · PostgreSQL 16

See [apiguard/README.md](apiguard/README.md) and
[apiguard/docs/](apiguard/docs/) for the full reference.

### NIS2 Compass

**NIS2 Article 21(2) compliance management — from gap assessment to
PDF evidence.**

- All 10 NIS2 Article 21(2) measures mapped to NIST CSF categories
- Evidence vault with artifact-to-control linking
- Article 23 72-hour notification delivery
- Signed PDF compliance reports
- Immutable audit log anchored in CITADEL WORM chain
- Multi-org support

**Stack:** Python 3.12 · Flask · SQLAlchemy 2.0 · ReportLab · Alembic

See [nis2compass/README.md](nis2compass/README.md).

### IRFlow

**Incident response orchestration with NIS2 Article 23 support.**

- Graph-based playbook executor with branching + per-step timeouts
- HMAC-signed webhook ingestion from APIGuard / CITADEL / ThreatFlow
- JWT + RBAC (5 roles: admin, operator, verifier, viewer, service)
- CITADEL MARSHAL evaluation on every governed action
- NIS2 Article 23 async notification with 72-hour tracking
- Prometheus metrics + structured audit logging

**Stack:** Go 1.24 · chi · zap · pgx · PostgreSQL 16

See [irflow/README.md](irflow/README.md) and
[irflow/docs/](irflow/docs/).

### ThreatFlow

**Threat intelligence aggregation and correlation.**

- IOC ingestion from MISP, AlienVault OTX, VirusTotal, custom feeds
- STIX 2.1 bundles, TAXII server/client
- MITRE ATT&CK technique mapping (19 techniques + 16 auto-rules)
- Cross-feed correlation and confidence scoring
- Integration with OpenScrub (auto-block) and IRFlow (enrichment)

**Stack:** Go 1.24 · Rust 1.76+ · PostgreSQL 16

See [threatflow/README.md](threatflow/README.md).

### CITADEL

**Cryptographic governance engine for the opensecstack ecosystem.**

CITADEL provides the audit and authorisation layer every other
platform depends on.

- **MARSHAL** — 5-gate decision engine (AuthN → AuthZ → NDS → AUGUR → WORM)
- **WORM chain** — append-only audit log with SHA-256 + SHA-512 + BLAKE3
  (TripleHash) per entry; Ed25519 chain anchors every 100 entries
- **NDS** — Separation of Duties enforced cryptographically at Gate 3
- **AUGUR** — behavioural heuristics (off-hours, high-frequency,
  DATA_EXPORT without incident)
- **Evidence custody** — chain-of-custody manifest for auditor export
- **VIGIL** — ecosystem health monitor (GREEN / AMBER / RED),
  design-stage for v2.0

**Benchmarks** (Go 1.24.4, Intel i7-7600U):

- TripleHash: 1.52 µs / 100-byte payload
- WORM chain step: 427 ns, 0 allocations
- WORM append (PostgreSQL 16, sync): 4.22 ms
- MARSHAL 5-gate evaluation: 7.55 µs (in-memory mock)
- Chain verification (1,000 entries): 10.19 ms

See [citadel/README.md](citadel/README.md) and
[citadel/docs/](citadel/docs/) (25 guides).

---

## Scaffolded & Planned

### VertGuard (scaffolded — Phase 4.1)

**AI-attack defence platform. 24 docs + Go/Rust skeleton + docker-compose
in place. Phase 4.1 accepting contributors.**

Five modules across three phases:

| # | Module | Phase | Status |
|:-:|---|:-:|---|
| 1 | Media Authenticity (C2PA + deepfake detection) | 4.1 (C2PA) + 4.2 (ML) | 🔨 scaffold |
| 2 | AI Phishing Detection | 4.2 | 📋 planned |
| 3 | **Prompt Injection Defence** (OWASP LLM Top 10) | **4.1** | 🔨 scaffold |
| 4 | **AI Threat Intelligence Feed** (MITRE ATLAS) | **4.1** | 🔨 scaffold |
| 5 | Synthetic Identity Detection | 4.3 | 📋 planned |

Port: 8091 (API) · 3009 (Dashboard) · 50051 (gRPC ML side-car,
Phase 4.2+)

See [vertguard/README.md](vertguard/README.md),
[RFC-0004](rfcs/RFC-0004-vertguard-platform.md), and
[vertguard/.github/GOOD_FIRST_ISSUES.md](vertguard/.github/GOOD_FIRST_ISSUES.md)
for how to contribute.

### OpenScrub (planned — Phase 2)

DDoS mitigation at kernel level. XDP/eBPF programs, GoBGP blackhole
announcements, FastNetMon detection integration.

### CyberPath (planned — Phase 2)

Security training with Docker and Wasm labs. Content authored as
YAML + Markdown. NIS2 Article 21(2)(g) evidence records anchored in
CITADEL.

### SecureLab (planned — Phase 3)

Attack simulation and detection validation. Scenario library maps to
MITRE ATT&CK. Validates OpenScrub rules, APIGuard detection, and
VertGuard AI-attack patterns.

### OpenCSIRT (planned — Phase 3)

National and sector CSIRT operations. TAXII 2.1 server + client, STIX
2.1 object model, CSAF 2.0 advisory generation, NIS2 Article 23
aggregate reporting. EU peer CSIRT federation.

---

## SDK

The [opensecstack/sdk](sdk/) provides typed clients in **Go, Python,
TypeScript, and Rust** — the same clients used internally between
platforms.

### Go SDK

Zero external dependencies. Go 1.21+.

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewAPIGuardClient("https://apiguard.example.com", "your-api-key")
scan, _ := client.CreateScan(ctx, "https://api.example.com/openapi.json")
findings, _ := client.GetFindings(ctx, scan.ID, opensecstack.GetFindingsOptions{
    Severity: "critical",
})
```

### Python SDK

Python 3.10+. `pip install opensecstack-sdk`.

```python
from opensecstack import APIGuardClient

client = APIGuardClient("https://apiguard.example.com", api_key="your-api-key")
scan = client.create_scan(spec_url="https://api.example.com/openapi.json")
findings = client.get_findings(scan["id"])
```

### TypeScript SDK

Node.js 18+ and browser. Zero external runtime dependencies.

```typescript
import { APIGuardClient } from "@opensecstack/sdk";

const client = new APIGuardClient({
  baseURL: "https://apiguard.example.com",
  apiKey: "your-api-key",
});
const scan = await client.createScan({ specUrl: "https://api.example.com/openapi.json" });
```

### Rust SDK

Async-first with tokio + reqwest. Rust 1.75+.

```rust
use opensecstack::APIGuardClient;

let client = APIGuardClient::new("https://apiguard.example.com", "your-api-key");
let scan = client.create_scan("https://api.example.com/openapi.json").await?;
```

**Shared module:** [Argon2id + pepper password hashing](sdk/go/password/)
with byte-compatible PHC encoding across Go
([sdk/go/password](sdk/go/password)) and Python
([sdk/python-password](sdk/python-password)).

See [sdk/README.md](sdk/README.md) and [sdk/docs/](sdk/docs/) (8
guides).

---

## Quick Start

### Full ecosystem (Docker Compose)

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack

# Fill in secrets
cp deploy/.env.example deploy/.env

docker compose -f deploy/docker-compose.yml up -d
```

| Service | URL |
|---------|-----|
| APIGuard API / UI | http://localhost:8080 / :3000 |
| NIS2 Compass API / UI | http://localhost:8090 / :3001 |
| CITADEL API | http://localhost:8099 |
| IRFlow API | http://localhost:8083 |
| ThreatFlow API | http://localhost:8084 |
| VertGuard API / UI (scaffold) | http://localhost:8091 / :3009 |
| sinauth (identity provider) | http://localhost:8100 |

### Single platform

```bash
cd apiguard && make dev            # APIGuard with hot reload
cd nis2compass && docker compose -f docker-compose.dev.yml up
cd citadel && make docker-up
cd irflow && make compose-test-up && make run
cd threatflow && docker compose up -d
cd vertguard && docker compose up -d   # scaffold — returns 501 for Phase 4.1 endpoints
cd sinauth && make keys-generate && docker compose -f docker-compose.dev.yml up   # identity provider on :8100
```

### Kubernetes

Production-ready manifests in [deploy/k8s/](deploy/k8s/). See
[deploy/k8s/README.md](deploy/k8s/README.md) for detail.

---

## Security & Maturity

v1.0.0 fits different deployments differently. Be honest about your
tier:

| Profile | v1.0.0 verdict |
|---|---|
| **Standard** — single region, trusted operator, NGOs / public admin / SaaS | **Production-ready** |
| **Elevated** — multi-region, multi-tenant, zero-trust | **Production-ready** with Vault + service mesh + OpenTelemetry |
| **High assurance** — banking Tier 1, national CSIRTs, NIS2 essential entities | **Not yet** — wait for v1.1 (JWKS, mTLS, third-party audit) |

Full tier matrix: [docs/security-maturity.md](docs/security-maturity.md).

**Reporting vulnerabilities:** see [SECURITY.md](SECURITY.md). Every
platform also ships its own SECURITY.md with scope and SLA.

---

## Post-Quantum Strategy

NIST PQC standards finalised 2024. NIS3 (projected 2030-2032) will
likely mandate migration. We're moving **before** it's mandatory:

| Version | Year | Action |
|---|---|---|
| v1.0.0 | 2026 (now) | Ed25519 anchors + TripleHash. Baseline. |
| v1.1 | 2026-2027 | Algorithm-identifier schema fields. No breaking change. |
| v2.0 | 2028 | Hybrid Ed25519 + ML-DSA signatures. |
| v2.5 | 2029 | QuintHash (TripleHash + 2 PQ-resistant primitives). |
| v3.0 | 2030 | ML-DSA default. Aligned with expected NIS3 transposition. |
| v4.0 | 2033 | Ed25519 signing retired; historical verification retained. |

See [docs/post-quantum-roadmap.md](docs/post-quantum-roadmap.md) and
[ADR-011](adrs/ADR-011-post-quantum-agility.md).

---

## Documentation

### Ecosystem

| Document | Description |
|----------|-------------|
| [ECOSYSTEM.md](ECOSYSTEM.md) | Full architecture, data-flow map, integration contracts, licensing |
| [ARCHITECTURE.md](ARCHITECTURE.md) | System architecture, component interactions |
| [GOVERNANCE.md](GOVERNANCE.md) | Project governance, decision-making process |
| [ROADMAP.md](ROADMAP.md) | Phase-by-phase delivery plan (5 phases to 2036) |
| [CHANGELOG.md](CHANGELOG.md) | Ecosystem-wide changelog |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guide |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure, PQ strategy |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community standards |
| [docs/security-architecture.md](docs/security-architecture.md) | Five-layer defence model |
| [docs/security-maturity.md](docs/security-maturity.md) | 3-tier deployment profile |
| [docs/deployment-topology.md](docs/deployment-topology.md) | Ports, network segments, secret distribution |
| [docs/release-process.md](docs/release-process.md) | Per-platform + ecosystem releases |
| [docs/compatibility-matrix.md](docs/compatibility-matrix.md) | Version pairing, PQC status |
| [docs/deprecation-policy.md](docs/deprecation-policy.md) | Feature retirement |
| [docs/post-quantum-roadmap.md](docs/post-quantum-roadmap.md) | PQ migration timeline |
| [docs/migrations/](docs/migrations/) | Version-to-version migration guides |
| [docs/tds-integration.md](docs/tds-integration.md) | TDS integration for new components |
| [adrs/](adrs/) | Architecture Decision Records |
| [rfcs/](rfcs/) | Request for Comments |

### Platform documentation

| Platform | Reference |
|----------|-----------|
| APIGuard | [apiguard/README.md](apiguard/README.md) · [apiguard/docs/](apiguard/docs/) (25 guides) |
| NIS2 Compass | [nis2compass/README.md](nis2compass/README.md) · [nis2compass/docs/](nis2compass/docs/) (17 guides) |
| CITADEL | [citadel/README.md](citadel/README.md) · [citadel/docs/](citadel/docs/) (25 guides) |
| IRFlow | [irflow/README.md](irflow/README.md) · [irflow/docs/](irflow/docs/) (12 guides) |
| ThreatFlow | [threatflow/README.md](threatflow/README.md) · [threatflow/docs/](threatflow/docs/) (21 guides) |
| VertGuard | [vertguard/README.md](vertguard/README.md) · [vertguard/docs/](vertguard/docs/) (18 guides) |
| sinauth (identity) | [sinauth/README.md](sinauth/README.md) · [sinauth/docs/](sinauth/docs/) · [integration guides](sinauth/docs/integration/) |
| Go SDK | [sdk/go/README.md](sdk/go/README.md) |
| Python SDK | [sdk/python/README.md](sdk/python/README.md) |
| TypeScript SDK | [sdk/typescript/README.md](sdk/typescript/README.md) |
| Rust SDK | [sdk/rust/README.md](sdk/rust/README.md) |

### Architecture Decision Records

| ADR | Decision |
|-----|----------|
| [ADR-001](adrs/ADR-001-rust-for-parsing.md) | Rust for OpenAPI/GraphQL parsing and analysis |
| [ADR-002](adrs/ADR-002-go-for-http-and-orchestration.md) | Go for HTTP servers and orchestration |
| [ADR-009](adrs/ADR-009-time-dimension-segmentation.md) | Time Dimension Segmentation (TDS) |
| [ADR-010](adrs/ADR-010-vertguard-platform-strategy.md) | VertGuard platform strategy (AI-attack defence) |
| [ADR-011](adrs/ADR-011-post-quantum-agility.md) | Post-quantum cryptographic agility |

### RFCs

| RFC | Topic |
|-----|-------|
| [RFC-0001](rfcs/RFC-0001.md) | (see file) |
| [RFC-0002](rfcs/RFC-0002.md) | (see file) |
| [RFC-0003](rfcs/RFC-0003.md) | (see file) |
| [RFC-0004](rfcs/RFC-0004-vertguard-platform.md) | VertGuard — AI-Attack Defence Platform (comment period 2026-05-20) |

---

## Roadmap

| Phase | Theme | Timeline | Status |
|-------|-------|----------|--------|
| **Phase 1** | Foundation — 5 platforms + SDK at v1.0.0 | 2026 Q1-Q2 | ✅ Complete |
| **Phase 2** | Network defence & training — OpenScrub, CyberPath | 2026 Q3 – 2027 Q2 | 📋 Planned |
| **Phase 3** | Simulation & CSIRT — SecureLab, OpenCSIRT, ecosystem v1.0 | 2027 Q3 – 2028 Q2 | 📋 Planned |
| **Phase 4** | AI-attack defence — VertGuard (3 sub-phases) | 2026 Q3 – 2028 Q4 | 🔨 Scaffolded |
| **Phase 5** | Long-term sovereignty stack (tiered aspirational) | 2028 – 2036 | 🔮 Aspirational |

See [ROADMAP.md](ROADMAP.md) for quarterly milestones and honest
caveats.

---

## Contributing

We welcome contributions to every platform — code, tests,
documentation, translations, and security research.

**Getting started:**

1. Read [CONTRIBUTING.md](CONTRIBUTING.md)
2. Look for `good-first-issue` labels across the platforms
3. For VertGuard Phase 4.1: see
   [vertguard/.github/GOOD_FIRST_ISSUES.md](vertguard/.github/GOOD_FIRST_ISSUES.md)
   (15 issues drafted and ready)
4. Comment on open RFCs, especially
   [RFC-0004](rfcs/RFC-0004-vertguard-platform.md)
5. Join GitHub Discussions

**Development setup** for each platform is documented in its own
`README.md`. The root `Makefile` orchestrates the full stack.

All contributors are bound by the [CLA](CLA.md) and
[Code of Conduct](CODE_OF_CONDUCT.md). Review ownership per path is
enforced by [CODEOWNERS](.github/CODEOWNERS).

---

## Community

- **GitHub Discussions** — questions, ideas, show & tell
- **Monthly community calls** — schedule in
  [community/MEETINGS.md](community/MEETINGS.md)

| Resource | Description |
|----------|-------------|
| [community/README.md](community/README.md) | Community hub overview |
| [community/GOOD-FIRST-ISSUES.md](community/GOOD-FIRST-ISSUES.md) | Curated starter issues |
| [community/AMBASSADORS.md](community/AMBASSADORS.md) | EU regional ambassador profiles |
| [community/MEETINGS.md](community/MEETINGS.md) | Meeting schedule |
| [community/MENTORSHIP.md](community/MENTORSHIP.md) | Mentorship programme |

---

## Licence

| Category | Licence | Platforms |
|----------|---------|-----------|
| Tool platforms | [Apache 2.0](LICENSE) | APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab |
| Governance platforms | AGPL-3.0 | IRFlow, NIS2 Compass, OpenCSIRT, CITADEL, **VertGuard** |
| Community platforms | Apache 2.0 | **SIN Community** |
| Identity layer | Apache 2.0 | **sinauth** |
| SDK | Apache 2.0 | opensecstack/sdk |

**Why two licences?** Tool platforms are permissive so they can be
embedded in CI/CD pipelines and commercial workflows. Governance
platforms (including VertGuard, whose AI-attack detections become
evidence in the CITADEL audit chain) are copyleft so any
modifications to the audit trail, compliance reporting, or CSIRT
operations must remain open source.

See [ECOSYSTEM.md](ECOSYSTEM.md) for the full rationale.
