# opensecstack Ecosystem Architecture

> 8 platforms. 1 governance layer. 1 SDK. All open source. All integrated.

## Platform Overview

| Platform | Purpose | Language | Licence | Status |
|----------|---------|----------|---------|--------|
| **APIGuard** | API security testing (OWASP API Top 10) | Go + Rust | Apache 2.0 | In Development |
| **NIS2 Compass** | NIS2 Article 21 compliance assessment | Python + Go | AGPL-3.0 | Planned |
| **ThreatFlow** | Threat intelligence aggregation & correlation | Rust + Go | Apache 2.0 | Planned |
| **IRFlow** | Incident response orchestration | Go + Python | AGPL-3.0 | Planned |
| **OpenScrub** | DDoS mitigation (XDP/eBPF) | Rust + C | Apache 2.0 | Planned |
| **CyberPath** | Security training & certification | Go + React | Apache 2.0 | Planned |
| **SecureLab** | Attack simulation & detection validation | Python + Rust | Apache 2.0 | Planned |
| **OpenCSIRT** | National/sector CSIRT operations | Go + Python | AGPL-3.0 | Planned |

**Governance Layer:**
| Component | Purpose | Language |
|-----------|---------|----------|
| **CITADEL** | Governance, audit trail, evidence chain, separation of duties | Go + Rust (Odoo 18/19) |

## Architecture Diagram

```
                         ┌─────────────────────────────────────────────┐
                         │            opensecstack/sdk                 │
                         │     Go + Python clients · Event schemas     │
                         │       Integration contracts (OpenAPI)       │
                         └──────────────────┬──────────────────────────┘
                                            │
          ┌─────────────────────────────────┼─────────────────────────────────┐
          │                                 │                                 │
          │              ┌──────────────────┴──────────────────┐              │
          │              │           CITADEL                 │              │
          │              │  ┌───────────┐  ┌───────────────┐   │              │
          │              │  │ MARSHAL  │  │  WORM Log     │   │              │
          │              │  │ (5 gates) │  │  (append-only)│   │              │
          │              │  └───────────┘  └───────────────┘   │              │
          │              │  ┌───────────┐  ┌───────────────┐   │              │
          │              │  │  BEACON   │  │  PATROL       │   │              │
          │              │  │ (intel)   │  │  (audit)      │   │              │
          │              │  └───────────┘  └───────────────┘   │              │
          │              │  ┌──────────────────────────────┐   │              │
          │              │  │  Chain Anchors (SHA-256)     │   │              │
          │              │  │  Evidence Vault · SoD Engine │   │              │
          │              │  └──────────────────────────────┘   │              │
          │              └──────────────────┬──────────────────┘              │
          │                                 │                                 │
          │         EXECUTE / REFUSE / HARD STOP                              │
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
│ Go+Rust  │  │ Python+Go    │  │ Rust+Go      │  │ Go+Python  │  │ Rust+C       │
└────┬─────┘  └──────┬───────┘  └──────┬───────┘  └─────┬──────┘  └──────┬───────┘
     │               │                 │                 │                │
     └───────────────┼─────────────────┼─────────────────┼────────────────┘
                     │                 │                 │
              ┌──────┴───────┐  ┌──────┴───────┐  ┌─────┴────────┐
              │  CyberPath   │  │  SecureLab   │  │  OpenCSIRT   │
              │              │  │              │  │              │
              │ Security     │  │ Attack sim   │  │ CSIRT        │
              │ training     │  │ & detection  │  │ operations   │
              │              │  │ validation   │  │              │
              │ Go+React     │  │ Python+Rust  │  │ Go+Python    │
              └──────────────┘  └──────────────┘  └──────────────┘
```

## Data Flow Between Platforms

```
APIGuard scan findings ──────────► IRFlow (auto-create incident on CRITICAL)
                       ──────────► ThreatFlow (IOC extraction from scan targets)
                       ──────────► NIS2 Compass (Art.21 Measure 8 evidence)
                       ──────────► CITADEL (citadel.evidence + citadel.log)

ThreatFlow IOCs ─────────────────► OpenScrub (auto-block malicious IPs)
                ─────────────────► IRFlow (enrich incidents with threat context)
                ─────────────────► OpenCSIRT (advisory generation)

IRFlow incidents ────────────────► NIS2 Compass (Art.23 notification trigger)
                 ────────────────► OpenCSIRT (CSIRT coordination)
                 ────────────────► CITADEL (citadel.incident + chain anchor)

NIS2 Compass assessments ────────► CITADEL (compliance evidence)
                         ────────► CyberPath (training gap identification)

SecureLab simulations ───────────► IRFlow (validate playbooks)
                      ───────────► OpenScrub (validate DDoS rules)
                      ───────────► ThreatFlow (validate detection rules)

CyberPath completions ───────────► NIS2 Compass (Art.21 Measure G evidence)
                      ───────────► CITADEL (training evidence for audit)

OpenCSIRT advisories ────────────► ThreatFlow (advisory → IOC pipeline)
                     ────────────► NIS2 Compass (incident notification tracking)
```

## Integration Contracts

All inter-platform communication uses the `opensecstack/sdk`:

| Contract | Format | Version | Description |
|----------|--------|---------|-------------|
| Scan Result | JSON | v1 | APIGuard → IRFlow, ThreatFlow, NIS2 Compass |
| IOC Bundle | STIX 2.1 | v1 | ThreatFlow → OpenScrub, IRFlow, OpenCSIRT |
| Incident Record | JSON | v1 | IRFlow → NIS2 Compass, OpenCSIRT, CITADEL |
| Compliance Evidence | JSON | v1 | NIS2 Compass → CITADEL |
| CITADEL Event | JSON | v2.0 | Any platform → CITADEL (MARSHAL input) |
| Training Record | JSON | v1 | CyberPath → NIS2 Compass, CITADEL |
| Advisory | CSAF 2.0 | v1 | OpenCSIRT → ThreatFlow |
| Simulation Result | JSON | v1 | SecureLab → IRFlow, OpenScrub, ThreatFlow |

## Language-Per-Layer Strategy

| Concern | Language | Rationale |
|---------|----------|-----------|
| HTTP services, orchestration, CLI | **Go** | Goroutines for concurrency, single binary deployment, mature ecosystem |
| Parsing untrusted input, crypto, regex-heavy analysis | **Rust** | Memory safety for security-critical code, performance for high-throughput paths |
| Data science, ML, report templates | **Python** | Ecosystem (pandas, Jinja2, scikit-learn), rapid prototyping |
| Dashboards and UIs | **React** | Component ecosystem, TypeScript safety, developer familiarity |
| Kernel-level packet processing | **C + Rust/Aya** | XDP/eBPF requires C or Rust/Aya for kernel programs |
| Data persistence | **PostgreSQL 16+** | JSONB for flexible storage, row-level security, WORM tables for CITADEL |
| ERP governance layer | **Odoo 18/19** | CITADEL runs inside Odoo — institutional governance, multi-ERP topology |

## Licensing Model

| Category | Licence | Platforms | Rationale |
|----------|---------|-----------|-----------|
| Security tools (used in CI/CD) | Apache 2.0 | APIGuard, ThreatFlow, OpenScrub, CyberPath, SecureLab | Permissive — embeddable in proprietary pipelines |
| Governance platforms | AGPL-3.0 | IRFlow, NIS2 Compass, OpenCSIRT | Copyleft — governance modifications must remain open |
| SDK | Apache 2.0 | opensecstack/sdk | Permissive — anyone can build integrations |
| CITADEL | AGPL-3.0 | .citadel | Copyleft — audit trail integrity requires transparency |

## Repository Structure

```
opensecstack/
├── apiguard/           ← API security testing
├── nis2compass/        ← NIS2 compliance assessment
├── threatflow/         ← Threat intelligence
├── irflow/             ← Incident response
├── openscrub/          ← DDoS mitigation
├── cyberpath/          ← Security training
├── securelab/          ← Attack simulation
├── opencsirt/          ← CSIRT operations
├── .citadel/             ← CITADEL governance layer
├── sdk/                ← Go + Python SDK
├── deploy/             ← Docker Compose, Helm, deployment docs
├── docs/               ← Ecosystem-level documentation
├── community/          ← Community resources
├── website/            ← opensecstack.org source
├── rfcs/               ← Request for Comments
└── adrs/               ← Architecture Decision Records
```
