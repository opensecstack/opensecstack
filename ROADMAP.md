# opensecstack Roadmap

> Public roadmap for the opensecstack ecosystem.
>
> Updated: Q2 2026. Next review: Q4 2026.

## Current Status (as of Q2 2026)

### ✅ Production (v1.0.0)

| Platform | Highlights |
|---|---|
| **CITADEL** | MARSHAL 5-gate engine (AuthN → AuthZ → NDS → AUGUR → WORM), TripleHash (SHA-256 + SHA-512 + BLAKE3), Ed25519 chain anchors, 25 tests, benchmarks (7.55 µs MARSHAL, 4.22 ms WORM append, 1.52 µs TripleHash) |
| **APIGuard** | OWASP API Top 10 (A1–A10), CVSS 3.1, SARIF/HTML/PDF/JSON reports, React dashboard, CI/CD integration, HA deployment, security audit complete |
| **NIS2 Compass** | All 10 Article 21(2) measures, PDF reports, CITADEL webhook integration, artifact evidence management, NIS2 → NIST CSF mapping |
| **IRFlow** | Graph-based playbook executor, HMAC-signed webhooks (APIGuard/CITADEL/ThreatFlow), JWT + RBAC with 5 roles, CITADEL MARSHAL + WORM integration, NIS2 Article 23 async notification, Prometheus metrics, real-DB integration tests |
| **ThreatFlow** | IOC aggregation (MISP, AlienVault OTX, VirusTotal), MITRE ATT&CK mapping (19 techniques + 16 auto-rules), TAXII feed, STIX integration, CITADEL + IRFlow webhooks |
| **opensecstack/sdk** | Go + Python + TypeScript + Rust typed clients, event schemas, OpenAPI contracts, Argon2id + pepper password hashing module |
| **OpenScrub** | XDP/eBPF DDoS mitigation (XDP blocklist, rate-limiting, SYN-cookie mitigation, ThreatFlow IOC auto-block, CITADEL evidence emitter), Rust + Aya + Go, v1.0.0 — GoBGP blackhole routing not yet implemented, see Phase 2 below |
| **CyberPath** | Security training platform, Docker/Wasm labs, NIS2 Art.21(2)(g) completion records to CITADEL WORM, Go + React + Rust, v1.0.0 |
| **OpenCSIRT** | CSIRT operations — constituency lifecycle, CSAF 2.0 advisory authoring, incident coordination with IRFlow, CITADEL WORM emission, peer-CSIRT federation, Go + Python, v1.0.0 |
| **VertGuard** | AI-attack defence — prompt injection (OWASP LLM Top 10), C2PA media authenticity (Rust c2pa-rs), AI threat feed (MITRE ATLAS), Zoom/Teams/WebEx meeting integrations, 28 API endpoints, NIS3-ready security audit, Go + Rust + Python, v1.0.0 — deepfake video/voice detection is a heuristic sub-check today, not a real detector; real-time video call analysis is not implemented |
| **SecureLab** | Attack simulation, MITRE ATT&CK coverage mapping, detection validation against APIGuard/OpenScrub/ThreatFlow/VertGuard, Python + Rust + Go, v1.0.0 |
| **SIN Community** | Developer knowledge hub — posts, comments, tags, full-text search (Meilisearch, with a PostgreSQL tsvector fallback), notifications, API keys, series, spaces, Go + React + TypeScript + PostgreSQL, v1.0.0 — TOTP 2FA has a DB schema but no implementation yet |

---

## Phase 1 — Foundation ✅ Complete

Shipped Q1-Q2 2026.

| Deliverable | Version | Status |
|---|---|---|
| CITADEL — MARSHAL, WORM, NDS, AUGUR, chain anchors | v1.0.0 | ✅ Done |
| APIGuard — OpenAPI parser, A1-A10 modules, CLI, reports, HA | v1.0.0 | ✅ Done |
| NIS2 Compass — All Article 21(2), PDF reports, CITADEL integration | v1.0.0 | ✅ Done |
| IRFlow — Playbook executor, webhooks, MARSHAL+WORM, NIS2 Art. 23 | v1.0.0 | ✅ Done |
| ThreatFlow — IOC aggregation, MITRE ATT&CK, STIX/TAXII | v1.0.0 | ✅ Done |
| opensecstack/sdk — 4-language clients, password hashing module | v1.0.0 | ✅ Done |
| Ecosystem documentation — 136 docs covering 5 platforms + meta | — | ✅ Done |
| Release discipline — CODEOWNERS, release-process, deprecation-policy, compatibility-matrix, migration template | — | ✅ Done |
| Security maturity framework — 3-tier deployment profile (standard/elevated/high-assurance) | — | ✅ Done |

## Phase 2 — Network Defence & Training (2026 Q3 – 2027 Q2)

Expand coverage to network-layer attacks and human factor (NIS2 Art. 21(2)(g)).

| Deliverable | Target | Status |
|---|---|---|
| OpenScrub v0.1.0 — XDP/eBPF kernel module, FastNetMon adapter | 2026 Q4 | ✅ Done |
| OpenScrub — GoBGP blackhole-route integration | — | 📋 Not yet implemented (see [ADR-002](openscrub/adrs/002-gobgp-integration.md)) |
| OpenScrub v1.0.0 — HA, kernel 5.15+, CITADEL integration, ThreatFlow IOC auto-block | 2027 Q2 | ✅ Done |
| CyberPath v0.1.0 — Learning path engine, Docker labs, browser terminal | 2027 Q1 | ✅ Done |
| CyberPath v1.0.0 — NIS2 Art. 21(2)(g) completion records to CITADEL WORM | 2027 Q2 | ✅ Done |
| CyberPath — Wasm sandbox lab runtime (OCI pull, cosign verify, wasmtime instantiate) | — | 📋 Not yet wired (Docker-based labs unaffected) |

## Phase 3 — Simulation & CSIRT Operations (2027 Q3 – 2028 Q2)

Close the loop — validate defences against offensive scenarios, coordinate across CSIRTs.

| Deliverable | Target | Status |
|---|---|---|
| SecureLab v0.1.0 — Scenario engine, attack library, MITRE ATT&CK coverage map | 2027 Q4 | ✅ Done |
| SecureLab v1.0.0 — OpenScrub + APIGuard + ThreatFlow detection validation, payload fuzzing | 2028 Q1 | ✅ Done |
| OpenCSIRT v0.1.0 — TAXII 2.1 server/client, STIX 2.1 builder, constituency management | 2026 Q2 | ✅ Done |
| OpenCSIRT v1.0.0 — CSAF 2.0, CITADEL WORM emission, IRFlow incident bridge, peer-CSIRT federation, HMAC replay protection | 2026 Q2 | ✅ Done |
| **Ecosystem v1.0.0 — 11-platform stack** | 2026 Q2 | ✅ Done |

## Phase 4 — AI-Attack Defence (2026 Q3 – 2028 Q4)

**Staggered phased launch** to deliver immediate value without requiring ML expertise up front.

### Phase 4.1 — VertGuard v0.1 (no ML, Q3 2026)

Go + Rust only. Leverages existing engineering team.

| Deliverable | Tech | Justification |
|---|---|---|
| **Module 3: Prompt Injection Defense** | Rust pattern engine + Go scanner | OWASP LLM Top 10 coverage, LLM firewall integration (NeMo Guardrails) |
| **Module 4: AI Threat Intelligence Feed** | Go + ThreatFlow SDK | Feed collector, MITRE ATLAS mapping, AI-specific IOC types |
| API server, dashboard, CITADEL integration | Go + React | Consistent with 11-platform pattern |

Product-market fit: every organisation deploying LLM-using apps today.

### Phase 4.2 — SIN Community v1.0.0 ✅ Done

| Deliverable | Status |
|---|---|
| SIN Community v1.0.0 — posts, comments, tags, Meilisearch FTS, notifications, TOTP, API keys, series, spaces, Docker deployment | ✅ Done |

### Phase 4.4 — VertGuard v0.5 (Python ML layer, Q1-Q3 2027)

ML expertise required. Funded by Phase 1 revenue + EU grants.

| Deliverable | Tech | Justification |
|---|---|---|
| **Module 1: Media Authenticity** | Rust C2PA + Python ML | C2PA provenance (no ML) + deepfake detection (ML) |
| **Module 2: AI Phishing Detection** | Python ML wrappers | LLM-generated email/chat classification |
| gRPC ML service, model registry with SHA-256 checksums | Python + Go | Supply chain security for ML |
| Dataset registry, adversarial robustness testing | Python | Dataset hygiene |

### Phase 4.5 — VertGuard v1.0 (Q3 2028)

| Deliverable | Tech | Justification |
|---|---|---|
| **Module 5: Synthetic Identity Detection** | Python ML | GAN-generated profile detection |
| Real-time video call analysis | Python + WebRTC | Live deepfake detection mid-call |
| v1.0.0 stable — NIS3-ready, security audit checklist 100% complete | — | 🔨 Partial — Modules 3-4 live, Module 1 ML path and Modules 2/5 still pending; see [README Known Gaps](README.md#known-gaps) |

**Ecosystem v1.1.0 — 11-platform stack — ✅ shipped 2026-05-10**

---

## Phase 5 — Long-term Sovereignty Stack (2028 – 2036)

**Aspirational, requires foundation backing + EU funding.** Tiered by realistic feasibility.

### Tier A — High feasibility (2028-2030)

| Deliverable | Dependency | Feasibility |
|---|---|---|
| vantage-hash — Standalone Rust crate (TripleHash extracted) | Community demand signal | ✓ High |
| pyramid-registry v0.1 — DAG + W3C DID + FROST threshold signatures | Research partnerships | ✓ High |
| Post-quantum migration — Hash/signature agility across ecosystem (Ed25519 → ML-DSA, SHA-256 → quintHash) | NIST PQC finalisation | ✓ High (must happen) |
| AI governance integration — MARSHAL gate for AI-initiated actions | VertGuard + CITADEL integration | ✓ High |

### Tier B — Medium feasibility (2030-2033)

| Deliverable | Dependency | Feasibility |
|---|---|---|
| pyramid-registry v1.0 — Cross-organisational federation, production-ready | Tier A maturity | ~ Medium |
| Runix alpha — Rust microkernel, Wasm layer 1-3 | 50+ full-time engineers, foundation backing | ~ Medium (25% probability) |
| Ecosystem release v2.0 — NIS3-ready bundle | NIS3 adoption (2030-2032) | ✓ High if NIS3 on schedule |

### Tier C — Aspirational (2033-2036)

| Deliverable | Dependency | Feasibility |
|---|---|---|
| Runix v1.0 — Full desktop OS (layers 1-6) | Sustained €10M+/year funding | ⚠️ Low (15% probability) |
| Runix Mobile alpha — Mobile OS with ARM64 + TrustZone + EM defence | Mil-grade expertise, classification handling | ⚠️ Low (15% probability) |
| pyramid-mvno pilot — Sovereign 5G core + dSIM | Spectrum licensing, regulatory clearance in 1+ EU state | ⚠️ Low (20% probability) |
| Runix Mobile v1.0 — Production mobile OS | Runix + pyramid-mvno matured | ⚠️ Very low (8% probability) |

**Tier C is only achievable with Linux Foundation / EU consortium backing.** Without that, ecosystem stabilises at Tier A + B (~12-14 active components) by 2036 — still a remarkable outcome.

---

## Version Summary

| Platform | Current (Q2 2026) | Target v1.0.0 |
|---|---|---|
| CITADEL | ✅ v1.0.0 | — |
| APIGuard | ✅ v1.0.0 | — |
| NIS2 Compass | ✅ v1.0.0 | — |
| IRFlow | ✅ v1.0.0 | — |
| ThreatFlow | ✅ v1.0.0 | — |
| opensecstack/sdk | ✅ v1.0.0 | — |
| OpenScrub | ✅ v1.0.0 | — |
| CyberPath | ✅ v1.0.0 | — |
| SecureLab | ✅ v1.0.0 | — |
| OpenCSIRT | ✅ v1.0.0 | — |
| VertGuard | 🔨 Partial | 2 Phase 4.1 endpoints pending |
| SIN Community | ✅ v1.0.0 | — |
| vantage-hash | 📋 — | Phase 5 Tier A (2029) |
| pyramid-registry | 📋 — | Phase 5 Tier A/B (2030+) |
| Runix | 📋 — | Phase 5 Tier C (2033+) |
| Runix Mobile | 📋 — | Phase 5 Tier C (2034+) |
| pyramid-mvno | 📋 — | Phase 5 Tier C (2033+) |

## Ecosystem release milestones

| Release | Scope | Target |
|---|---|---|
| **ecosystem/v1.0.0-2026-Q2** | 5-platform foundation (CITADEL, APIGuard, NIS2 Compass, IRFlow, ThreatFlow) + SDK | ✅ Shipped 2026 Q2 |
| **ecosystem/v1.1.0** | +OpenScrub v1.0 + CyberPath v1.0 + OpenCSIRT v1.0 + VertGuard v1.0 + SecureLab v1.0 + SIN Community v1.0 — 11-platform stack | ✅ Shipped 2026-05-10 |
| **ecosystem/v2.0.0** | 11-platform stack + PQC migration (Ed25519 → ML-DSA hybrid) | 2028 Q4 |
| **ecosystem/v2.5.0** | +vantage-hash + pyramid-registry v1.0 | 2030 |
| **ecosystem/v3.0.0** | NIS3-ready bundle | 2032 |
| **ecosystem/v4.0.0** | +Runix (if Tier C funded) | 2034-2036 |

## Platform-specific roadmaps

- [APIGuard Roadmap](apiguard/ROADMAP.md)
- [NIS2 Compass Roadmap](nis2compass/ROADMAP.md)
- [CITADEL Roadmap](citadel/ROADMAP.md)
- [IRFlow Roadmap](irflow/ROADMAP.md)
- [ThreatFlow Roadmap](threatflow/ROADMAP.md)

## How we plan

- Roadmap is reviewed **quarterly**. Next review: **Q4 2026**.
- Phase ordering is not contractual — a later phase may start early if
  contributor capacity allows, but quality gates (see
  [docs/release-process.md](docs/release-process.md)) must hold.
- Community input via [GitHub Discussions](https://github.com/opensecstack/opensecstack/discussions).
- Significant changes require an [RFC](rfcs/).
- Architecture decisions are recorded in [ADRs](adrs/).
- Compatibility guarantees are codified in [docs/compatibility-matrix.md](docs/compatibility-matrix.md).
- Deprecation follows [docs/deprecation-policy.md](docs/deprecation-policy.md).

## How to influence the roadmap

1. **Open a GitHub Discussion** with label `roadmap` for early-stage ideas.
2. **File an RFC** under [rfcs/](rfcs/) for proposals that change the
   ecosystem's direction (new platform, cross-platform contract change,
   licensing change).
3. **Contribute to the ecosystem** — all 11 platforms are at v1.0.0. Contributions that improve integration depth, expand test coverage, or accelerate Phase 5 Tier A components are welcome.
4. **Sponsor development** — Tier C feasibility depends on funding. Get
   in touch via `contact@opensecstack.org` if your organisation wants to
   accelerate a specific component.

## Honest caveats

- **Phase 5 Tier C is aspirational.** If funding and foundation backing
  do not materialise by 2028, the Runix / Runix Mobile / pyramid-mvno
  components remain designs, not code. The core 11-platform security
  stack continues without them.
- **VertGuard ML model weights** are not bundled — operators must supply trained weights for the video/voice/identity models or run with the stub backend. The model training pipeline and configs are included.
- **Post-quantum migration is not optional** — NIST PQC standards
  (2024) plus expected NIS3 requirements (2030-2032) make this a
  must-have for ecosystem survival beyond 2030.
- **We will not ship a platform before its own v1.0.0 readiness gate
  passes**, even if the roadmap slips. Quality over calendar.
