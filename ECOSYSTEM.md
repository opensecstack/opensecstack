# opensecstack Ecosystem Architecture

> 11 platforms. 1 governance layer. 1 SDK. All open source. All integrated.
>
> Current state (2026-05-23, ecosystem v1.2.0): all 11 platforms, sinauth, and the SDK have shipped v1.0.0. VertGuard is partial (Phase 4.1: 3 of 5 modules scaffolded, 2 endpoints return `501`). OpenScrub (GoBGP not yet implemented) and CyberPath (Wasm sandbox labs not yet wired) each carry one specific, self-documented gap against their original scope — see README.md's [Known Gaps](README.md#known-gaps) section. Long-term sovereignty stack (Phase 5) is aspirational — see [ROADMAP.md](ROADMAP.md).

## Platform Overview

| Platform | Purpose | Language | Licence | Version | Status |
|----------|---------|----------|---------|---------|--------|
| **APIGuard** | API security testing (OWASP API Top 10) | Go + Rust | Apache 2.0 | **v1.0.0** | ✅ Production |
| **NIS2 Compass** | NIS2 Article 21 compliance assessment | Python + Go | AGPL-3.0 | **v1.0.0** | ✅ Production |
| **IRFlow** | Incident response orchestration | Go + Python | AGPL-3.0 | **v1.0.0** | ✅ Production |
| **ThreatFlow** | Threat intelligence aggregation & correlation | Go | Apache 2.0 | **v1.0.0** | ✅ Production |
| **OpenScrub** | DDoS mitigation (XDP/eBPF; GoBGP not yet implemented) | Rust + C + Go | Apache 2.0 | **v1.0.0** | ✅ Production |
| **CyberPath** | Security training & certification (Wasm sandbox labs not yet wired) | Go + React + Rust | Apache 2.0 | **v1.0.0** | ✅ Production |
| **SecureLab** | Attack simulation & detection validation | Python + Rust | Apache 2.0 | **v1.0.0** | ✅ Production |
| **OpenCSIRT** | National/sector CSIRT operations | Go + Python | AGPL-3.0 | **v1.0.0** | ✅ Production |
| **VertGuard** | AI-attack defence — prompt injection defence (OWASP LLM Top 10) and AI threat feed (MITRE ATLAS) live, 2 endpoints pending Rust pattern-engine integration; C2PA media authenticity, deepfake video/voice detection, Python ML (HuggingFace), Zoom/Teams/WebEx plugins, and real-time WebSocket video stream planned | Go + Rust + Python | AGPL-3.0 | **Phase 4.1** | 🔨 Partial |
| **SIN Community** | Developer knowledge hub — posts, comments, tags, full-text search, notifications, TOTP 2FA, API keys, series, spaces | Go + React + TypeScript + PostgreSQL + Meilisearch | Apache 2.0 | **v1.0.0** | ✅ Production |

**Identity Layer:**
| Component | Purpose | Language | Version | Status |
|-----------|---------|----------|---------|--------|
| **sinauth** | OAuth 2.0 / OpenID Connect authorization server — single sign-on for all platforms, RS256 + JWKS, authorization-code + PKCE, social login (Google, GitHub), TOTP MFA | Go + PostgreSQL | **v1.0.0** | ✅ Production |

**Governance Layer:**
| Component | Purpose | Language | Version | Status |
|-----------|---------|----------|---------|--------|
| **CITADEL** | Governance engine (MARSHAL 5-gate, WORM chain, NDS, AUGUR, chain anchors) | Go | **v1.0.0** | ✅ Production |

**SDK:**
| Component | Purpose | Languages | Version | Status |
|-----------|---------|-----------|---------|--------|
| **opensecstack/sdk** | Typed clients, event schemas, OpenAPI contracts, Argon2id+pepper module | Go · Python · TypeScript · Rust | **v1.0.0** | ✅ Production |

## Architecture Diagram

```
                         ┌─────────────────────────────────────────────┐
                         │            opensecstack/sdk                 │
                         │  Go · Python · TypeScript · Rust clients    │
                         │     Event schemas · OpenAPI contracts       │
                         └──────────────────┬──────────────────────────┘
                                            │
          ┌─────────────────────────────────┼─────────────────────────────────┐
          │                                 │                                 │
          │              ┌──────────────────┴──────────────────┐              │
          │              │              CITADEL                │              │
          │              │  ┌───────────┐   ┌───────────────┐  │              │
          │              │  │  MARSHAL  │   │  WORM Log     │  │              │
          │              │  │  5-gate   │   │  TripleHash   │  │              │
          │              │  │  engine   │   │  append-only  │  │              │
          │              │  └───────────┘   └───────────────┘  │              │
          │              │  ┌───────────┐   ┌───────────────┐  │              │
          │              │  │   AUGUR   │   │ Chain Anchors │  │              │
          │              │  │behavioral │   │ Ed25519-signed│  │              │
          │              │  └───────────┘   └───────────────┘  │              │
          │              │  ┌───────────┐   ┌───────────────┐  │              │
          │              │  │    NDS    │   │     VIGIL     │  │              │
          │              │  │ (SoD)     │   │ (planned v2)  │  │              │
          │              │  └───────────┘   └───────────────┘  │              │
          │              └──────────────────┬──────────────────┘              │
          │                                 │                                 │
          │         EXECUTE / REFUSE / HARD_STOP                              │
          │                                 │                                 │
  ┌───────┴──────────────┬──────────────────┼───────────────┬────────────────┐│
  │                      │                  │               │                ││
  ▼                      ▼                  ▼               ▼                ▼▼
┌──────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐  ┌──────────────┐
│ APIGuard │  │ NIS2 Compass │  │  ThreatFlow  │  │   IRFlow   │  │  OpenScrub   │
│          │  │              │  │              │  │            │  │              │
│ API sec  │  │ NIS2 Art.21  │  │ Threat intel │  │ Incident   │  │ DDoS         │
│ testing  │  │ assessment   │  │ aggregation  │  │ response   │  │ mitigation   │
│          │  │              │  │              │  │            │  │              │
│ Go+Rust  │  │ Python+Go    │  │ Go           │  │ Go+Python  │  │ Rust+C+Go    │
│ v1.0.0 ✅│  │ v1.0.0 ✅    │  │ v1.0.0 ✅    │  │ v1.0.0 ✅  │  │ v1.0.0 ✅    │
└────┬─────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  └──────┬───────┘
     │               │                 │                │                │
     └───────────────┼─────────────────┼────────────────┼────────────────┘
                     │                 │                │
         ┌───────────┼─────────────────┼────────────────┼────────────┐
         │           │                 │                │            │
  ┌──────┴───────┐  │  ┌──────────────┐│┌─────────────┐│ ┌──────────┴───┐
  │  CyberPath   │  │  │  SecureLab   │││  OpenCSIRT  ││ │  VertGuard   │
  │  (v1.0.0)    │  │  │  (v1.0.0)    │││  (v1.0.0)   ││ │  (partial)   │
  │              │  │  │              │││             ││ │              │
  │ Security     │  │  │ Attack sim   │││ CSIRT       ││ │ AI-attack    │
  │ training     │  │  │ & detection  │││ operations  ││ │ defence      │
  │              │  │  │ validation   │││             ││ │              │
  │ Go+React+Rs  │  │  │ Python+Rust  │││ Go+Python   ││ │ Go+Rust+Py   │
  └──────────────┘  │  └──────────────┘│└─────────────┘│ └──────────────┘
                    │                  │               │
                    └──────────────────┴───────────────┘
```

## Data Flow Between Platforms

> This diagram shows the intended/target architecture. Not every arrow is
> wired yet — see [docs/v1.0.0-readiness-roadmap.md](docs/v1.0.0-readiness-roadmap.md)
> for verified status. Two arrows confirmed to have zero backing code as
> of the last audit were removed below rather than left to imply they're
> live: `APIGuard → VertGuard` (no VertGuard reference exists anywhere in
> apiguard/) and `VertGuard → OpenCSIRT` cross-border coordination (design-stage
> only — referenced in roadmap/ADR docs, no integration client exists).

```
APIGuard scan findings ──────────► IRFlow (auto-create incident on CRITICAL)
                       ──────────► ThreatFlow (IOC extraction from scan targets)
                       ──────────► NIS2 Compass (Art.21 Measure 8 evidence)
                       ──────────► CITADEL (citadel.evidence + citadel.log)

ThreatFlow IOCs ─────────────────► OpenScrub (auto-block malicious IPs)
                ─────────────────► IRFlow (enrich incidents with threat context)
                ─────────────────► OpenCSIRT (advisory generation)
                ─────────────────► VertGuard (enrich AI threat feed)

IRFlow incidents ────────────────► NIS2 Compass (Art.23 notification trigger)
                 ────────────────► OpenCSIRT (CSIRT coordination)
                 ────────────────► CITADEL (citadel.incident + chain anchor)

NIS2 Compass assessments ────────► CITADEL (compliance evidence)
                         ────────► CyberPath (training gap identification)

SecureLab simulations ───────────► IRFlow (validate playbooks)
                      ───────────► OpenScrub (validate DDoS rules)
                      ───────────► ThreatFlow (validate detection rules)
                      ───────────► VertGuard (validate AI-attack detection)

CyberPath completions ───────────► NIS2 Compass (Art.21 Measure G evidence)
                      ───────────► CITADEL (training evidence for audit)

OpenCSIRT advisories ────────────► ThreatFlow (advisory → IOC pipeline)
                     ────────────► NIS2 Compass (incident notification tracking)
                     ────────────► VertGuard (cross-CSIRT AI threat sharing)

VertGuard AI-threat detection ───► IRFlow (auto-incident on HIGH-confidence detection)
                               ───► ThreatFlow (AI-specific IOC feed)
                               ───► CITADEL (evidence for AI-initiated actions)
```

## Integration Contracts

All inter-platform communication uses the `opensecstack/sdk`. End-user
and operator authentication is delegated to **sinauth** over OpenID
Connect — platforms validate sinauth-issued RS256 tokens against the
JWKS endpoint (`https://auth.sin.to/.well-known/jwks.json`) rather than
minting their own user credentials. See
[sinauth/docs/integration/](sinauth/docs/integration/) for the
per-platform OIDC client setup.

| Contract | Format | Version | Description | Status |
|----------|--------|---------|-------------|--------|
| CITADEL Kerkese | JSON | v1 | Any platform → CITADEL MARSHAL | ✅ Implemented, wired live by 6+ platforms |
| Identity (SSO) | OpenID Connect 1.0 | RS256 | sinauth → every platform (ID/access tokens, JWKS) | ✅ Implemented |
| Scan Result | JSON | v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass | 📋 Target design, not yet wired — see [CLAUDE.md](CLAUDE.md#sdk-contracts-the-only-sanctioned-integration-path) |
| IOC Bundle | STIX 2.1 | v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT | 📋 Target design — the real IOC pipeline exchanges STIX 2.1 directly, bypassing this SDK contract entirely |
| Incident Record | JSON | v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL | 📋 Target design, not yet wired |
| Compliance Evidence | JSON | v1 | NIS2 Compass → CITADEL | 📋 Target design — evidence generation exists but is pull-only, no push/ingestion |
| Advisory | CSAF 2.0 | v1 | OpenCSIRT → ThreatFlow | 📋 Target design, not yet wired |
| Simulation Result | JSON | v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow | 📋 Target design, not yet wired |
| AI-Attack Detection | JSON | v1 | VertGuard → IRFlow, ThreatFlow, OpenCSIRT | 📋 Target design, not yet wired |
| Content Provenance | C2PA | 2.0 | VertGuard → CITADEL (as WORM evidence) | 📋 Target design, not yet wired |

There is no separate "Training Record" contract — CyberPath's WORM audit
events already flow through CITADEL Kerkese above (see CLAUDE.md for why
an earlier version of this table's `Training Record` row was removed
rather than implemented).

All cross-platform webhooks are HMAC-SHA256 signed with a ±5-minute replay window and per-source secrets. See [IRFlow webhook spec](irflow/docs/webhook-spec.md) for the canonical wire format.

## Language-Per-Layer Strategy

| Concern | Language | Rationale |
|---------|----------|-----------|
| HTTP services, orchestration, CLI | **Go** | Goroutines for concurrency, single binary deployment, mature ecosystem |
| Parsing untrusted input, crypto, regex-heavy analysis | **Rust** | Memory safety for security-critical code, performance for high-throughput paths |
| ML inference, data science, report templates | **Python** | HuggingFace ecosystem, pandas, Jinja2, scikit-learn |
| Dashboards and UIs | **React + TypeScript** | Component ecosystem, type safety, developer familiarity |
| Kernel-level packet processing | **C + Rust/Aya** | XDP/eBPF requires C or Rust/Aya for kernel programs |
| Data persistence | **PostgreSQL 16+** | JSONB for flexible storage, row-level security, WORM tables for CITADEL |
| ERP layer (future CITADEL companion) | **Odoo-inspired, not Odoo-based** | Custom ERP for governance workflows, to be built Phase 5 Tier A |

## Licensing Model

| Category | Licence | Components | Rationale |
|----------|---------|------------|-----------|
| Security tools (embeddable in CI/CD) | Apache 2.0 | APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab | Permissive — embeddable in proprietary pipelines |
| Governance platforms | AGPL-3.0 | CITADEL, IRFlow, NIS2 Compass, OpenCSIRT, VertGuard | Copyleft — governance modifications must remain open |
| Community platforms | Apache 2.0 | SIN Community | Permissive — open knowledge hub |
| SDK | Apache 2.0 | opensecstack/sdk | Permissive — anyone can build integrations |
| Crypto library (planned Phase 5 Tier A) | Apache 2.0 | vantage-hash (TripleHash extracted) | Library — maximum adoption |

## Cross-Platform Security Guarantees

Every opensecstack deployment provides these guarantees:

| Guarantee | Enforced by |
|---|---|
| **Every privileged action is cryptographically evaluated** | CITADEL MARSHAL 5-gate engine |
| **Every decision is WORM-logged with TripleHash integrity** | CITADEL WORM chain (SHA-256 + SHA-512 + BLAKE3) |
| **Tamper-resistance via Ed25519 anchors** | CITADEL chain anchors (every 100 entries) |
| **Separation of Duties enforced at protocol level** | CITADEL Gate 3 (NDS) — operator ≠ verifier, cross-role-group |
| **All inter-platform webhooks HMAC-signed, replay-protected** | IRFlow webhook spec (±5 min window) |
| **Single sign-on with central MFA across all platforms** | sinauth OIDC (RS256 + JWKS, PKCE, TOTP) |
| **All API clients JWT-authenticated with RBAC** | IRFlow auth middleware, 5 canonical roles |
| **Password hashing Argon2id + server-side pepper** | sdk/go/password + sdk/python-password |
| **NIS2 Article 21(2) + Article 23 compliance by design** | NIS2 Compass measure tracking + IRFlow notification |

## Repository Structure

```
opensecstack/                       ← monorepo (current, 2026)
├── apiguard/           ← API security testing
├── nis2compass/        ← NIS2 compliance assessment
├── threatflow/         ← Threat intelligence
├── irflow/             ← Incident response
├── openscrub/          ← DDoS mitigation
├── cyberpath/          ← Security training
├── securelab/          ← Attack simulation & detection
├── opencsirt/          ← CSIRT operations
├── vertguard/          ← AI-attack defence (partial, Phase 4.1)
├── community/          ← SIN developer knowledge hub (v1.0.0) + community resources
├── sinauth/            ← SIN identity provider (OAuth2 / OIDC SSO, v1.0.0)
├── citadel/            ← CITADEL governance layer
├── sdk/                ← Go + Python + TypeScript + Rust SDK
├── deploy/             ← Docker Compose, K8s manifests
├── docs/               ← Ecosystem-level documentation
├── website/            ← opensecstack.org source
├── rfcs/               ← Request for Comments
└── adrs/               ← Architecture Decision Records
```

**Future repositories** (Phase 5, 2028-2036): `vantage-hash`, `pyramid-registry`, `pyramid-mvno`, `pyramid-os`, `symphy-os` — extracted from the monorepo when their independent lifecycle justifies the split. See [docs/release-process.md](docs/release-process.md) for the split criteria.

## Deployment Topology

For port assignments, network segmentation, and tier-specific
deployment profiles, see [docs/deployment-topology.md](docs/deployment-topology.md)
and [docs/security-maturity.md](docs/security-maturity.md).

## Related

- [ROADMAP.md](ROADMAP.md) — 10-year phased plan
- [ARCHITECTURE.md](ARCHITECTURE.md) — technical deep-dive
- [docs/release-process.md](docs/release-process.md) — how releases coordinate
- [docs/compatibility-matrix.md](docs/compatibility-matrix.md) — version pairing
- [docs/deprecation-policy.md](docs/deprecation-policy.md) — feature retirement
