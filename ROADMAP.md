# opensecstack Roadmap

> Public roadmap for the opensecstack ecosystem.
>
> Updated: 2026-09-19. Next review: Q4 2026.

## Current Status (as of 2026-09-19)

### ✅ Released (ecosystem/v1.0.0, published 2026-09-19)

The first real release of this ecosystem. Only the following are actually
live — tagged, built, and published to a registry a deployer could install
from (see [CHANGELOG.md](CHANGELOG.md) `[ecosystem/v1.0.0]` entry for the
full accounting):

| Platform | Highlights |
|---|---|
| **CITADEL** | MARSHAL 5-gate engine (AuthN → AuthZ → NDS → AUGUR → WORM), TripleHash (SHA-256 + SHA-512 + BLAKE3), Ed25519 chain anchors, 25 tests, benchmarks (7.55 µs MARSHAL, 4.22 ms WORM append, 1.52 µs TripleHash) |
| **APIGuard** | OWASP API Top 10 (A1–A10), CVSS 3.1, SARIF/HTML/PDF/JSON reports, React dashboard, CI/CD integration, HA deployment, security audit complete |
| **NIS2 Compass** | All 10 Article 21(2) measures, PDF reports, CITADEL webhook integration, artifact evidence management, NIS2 → NIST CSF mapping |
| **IRFlow** | Graph-based playbook executor, HMAC-signed webhooks (APIGuard/CITADEL/ThreatFlow), JWT + RBAC with 5 roles, CITADEL MARSHAL + WORM integration, NIS2 Article 23 async notification, Prometheus metrics, real-DB integration tests |
| **opensecstack/sdk** | Go + Python + TypeScript + Rust typed clients, event schemas, OpenAPI contracts, Argon2id + pepper password hashing module |

### 🔨 Feature-complete in-repo, never released (no tag, no package, no image)

These platforms have substantial implementation and tests in this repo, but
have never been through a real release pipeline — nothing has ever been
published for them to crates.io, npm, PyPI, or GHCR.

| Platform | Highlights |
|---|---|
| **ThreatFlow** | IOC aggregation (MISP, AlienVault OTX, VirusTotal), MITRE ATT&CK mapping (19 techniques + 16 auto-rules), TAXII feed, STIX integration, CITADEL + IRFlow webhooks |
| **OpenScrub** | XDP/eBPF DDoS mitigation (XDP blocklist, rate-limiting, SYN-cookie mitigation, ThreatFlow IOC auto-block, CITADEL evidence emitter), Rust + Aya + Go — GoBGP blackhole routing not yet implemented, see Phase 2 below |
| **CyberPath** | Security training platform, Docker/Wasm labs, NIS2 Art.21(2)(g) completion records to CITADEL WORM, Go + React + Rust |
| **OpenCSIRT** | CSIRT operations — constituency lifecycle, CSAF 2.0 advisory authoring, incident coordination with IRFlow, CITADEL WORM emission, peer-CSIRT federation, Go + Python |
| **VertGuard** | AI-attack defence — prompt injection (OWASP LLM Top 10), C2PA media authenticity (Rust c2pa-rs), AI threat feed (MITRE ATLAS), Zoom/Teams/WebEx meeting integrations, 28 API endpoints, NIS3-ready security audit, Go + Rust + Python — deepfake video/voice detection is a heuristic sub-check today, not a real detector; real-time video call analysis is not implemented |
| **SecureLab** | Attack simulation, MITRE ATT&CK coverage mapping, detection validation against APIGuard/OpenScrub/ThreatFlow/VertGuard, Python + Rust + Go |
| **SIN Community** | Developer knowledge hub — posts, comments, tags, full-text search (Meilisearch, with a PostgreSQL tsvector fallback), notifications, API keys, series, spaces, Go + React + TypeScript + PostgreSQL — TOTP 2FA has a DB schema but no implementation yet |

---

## Phase 1 — Foundation ✅ Complete

Feature-complete Q1-Q2 2026; actually released as `ecosystem/v1.0.0` on
2026-09-19 (ThreatFlow excepted — see below).

| Deliverable | Version | Status |
|---|---|---|
| CITADEL — MARSHAL, WORM, NDS, AUGUR, chain anchors | v1.0.0 | ✅ Done — released |
| APIGuard — OpenAPI parser, A1-A10 modules, CLI, reports, HA | v1.0.0 | ✅ Done — released |
| NIS2 Compass — All Article 21(2), PDF reports, CITADEL integration | v1.0.0 | ✅ Done — released |
| IRFlow — Playbook executor, webhooks, MARSHAL+WORM, NIS2 Art. 23 | v1.0.0 | ✅ Done — released |
| ThreatFlow — IOC aggregation, MITRE ATT&CK, STIX/TAXII | v1.0.0 | 🔨 Feature-complete — never released (not part of `ecosystem/v1.0.0`) |
| opensecstack/sdk — 4-language clients, password hashing module | v1.0.0 | ✅ Done — released |
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
| **Ecosystem v1.0.0 — 11-platform stack** | 2026 Q2 | 📋 Not shipped — see [Ecosystem release milestones](#ecosystem-release-milestones) below; the real `ecosystem/v1.0.0` (published 2026-09-19) covers a 5-platform + SDK scope, not the full 11-platform stack |

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

### Phase 4.2 — SIN Community v1.0.0 🔨 Feature-complete, not released

| Deliverable | Status |
|---|---|
| SIN Community v1.0.0 — posts, comments, tags, Meilisearch FTS, notifications, TOTP, API keys, series, spaces, Docker deployment | 🔨 Implemented in-repo — never published (no Docker image ever pushed, no `ecosystem/*` release has included it); TOTP 2FA also has a DB schema but no implementation yet |

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

**Ecosystem v1.1.0 — 11-platform stack — 📋 planned, not yet shipped** (no `ecosystem/v1.1.0` tag exists; see [Ecosystem release milestones](#ecosystem-release-milestones) below)

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
| Runix alpha — Rust microkernel, Wasm layer 1-3 | Kernel bring-up (boot, GDT/IDT, paging + heap, PIC/PIT interrupts, cooperative scheduler, syscall ABI, ring 0 → ring 3 transition, QEMU-native test harness) already implemented and CI-tested in [opensecstack/runix](https://github.com/opensecstack/runix); capability manager (Ed25519 tokens) and a real Wasm engine (`wasmi`) are also live. Full alpha scope (Wasm hosted in ring 3, network stack) still needs sustained engineering capacity. | 🔨 In progress — ahead of this table's original 2030-2033 timeline |
| Ecosystem release v2.0 — NIS3-ready bundle | NIS3 adoption (2030-2032) | ✓ High if NIS3 on schedule |

### Tier C — Aspirational (2033-2036)

| Deliverable | Dependency | Feasibility |
|---|---|---|
| Runix v1.0 — Full desktop OS (layers 1-6) | Sustained €10M+/year funding | ⚠️ Low (15% probability) |
| Runix Mobile alpha — Mobile OS with ARM64 + TrustZone + EM defence | Mil-grade expertise, classification handling | ⚠️ Low (15% probability) |
| runix-mvno pilot — Sovereign 5G core + dSIM | Spectrum licensing, regulatory clearance in 1+ EU state | ⚠️ Low (20% probability) |
| Runix Mobile v1.0 — Production mobile OS | Runix + runix-mvno matured | ⚠️ Very low (8% probability) |

**Tier C is only achievable with Linux Foundation / EU consortium backing.** Without that, ecosystem stabilises at Tier A + B (~12-14 active components) by 2036 — still a remarkable outcome.

---

## Version Summary

| Platform | Current (2026-09-19) | Target v1.0.0 |
|---|---|---|
| CITADEL | ✅ Released — ecosystem/v1.0.0 | — |
| APIGuard | ✅ Released — ecosystem/v1.0.0 | — |
| NIS2 Compass | ✅ Released — ecosystem/v1.0.0 | — |
| IRFlow | ✅ Released — ecosystem/v1.0.0 | — |
| ThreatFlow | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| opensecstack/sdk | ✅ Released — ecosystem/v1.0.0 | — |
| OpenScrub | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| CyberPath | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| SecureLab | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| OpenCSIRT | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| VertGuard | 🔨 Partial, never released | 2 Phase 4.1 endpoints pending; no published Docker image or tag yet |
| SIN Community | 🔨 Feature-complete, never released | No published Docker image or tag yet |
| vantage-hash | 📋 — | Phase 5 Tier A (2029) |
| pyramid-registry | 📋 — | Phase 5 Tier A/B (2030+) |
| Runix | 🔨 Alpha in progress | Kernel bring-up done; full desktop OS (layers 1-6) is Phase 5 Tier C (2033+) |
| Runix Mobile | 📋 — | Phase 5 Tier C (2034+) |
| runix-mvno | 📋 — | Phase 5 Tier C (2033+) |

## Ecosystem release milestones

| Release | Scope | Target |
|---|---|---|
| **ecosystem/v1.0.0** | 5-platform foundation (CITADEL, APIGuard, NIS2 Compass, IRFlow) + SDK (Go/Python/TypeScript/Rust, incl. `vantage-hash`) | ✅ Shipped 2026-09-19 — the real, first-ever ecosystem release; see [CHANGELOG.md](CHANGELOG.md) |
| **ecosystem/v1.1.0** (planned) | +OpenScrub v1.0 + CyberPath v1.0 + OpenCSIRT v1.0 + ThreatFlow v1.0 + VertGuard v1.0 + SecureLab v1.0 + SIN Community v1.0 — 11-platform stack | 📋 Planned — not yet shipped, no tag exists |
| **ecosystem/v2.0.0** | 11-platform stack + PQC migration (Ed25519 → ML-DSA hybrid) | 2028 Q4 |
| **ecosystem/v2.5.0** | +vantage-hash + pyramid-registry v1.0 | 2030 |
| **ecosystem/v3.0.0** | NIS3-ready bundle | 2032 |
| **ecosystem/v4.0.0** | +Runix (if Tier C funded) | 2034-2036 |

> Note: `ecosystem/v1.0.0-2026-Q2` and `ecosystem/v1.1.0` were previously
> drafted names for planned milestones that were never actually tagged or
> published. The real first release is `ecosystem/v1.0.0` (2026-09-19,
> renumbered down from what had been planned as a later version, for the
> same reason described in [CHANGELOG.md](CHANGELOG.md)).

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
3. **Contribute to the ecosystem** — 5 platforms plus the SDK are released as `ecosystem/v1.0.0`; the remaining 6 are feature-complete in-repo but not yet released. Contributions that improve integration depth, expand test coverage, help get the remaining platforms through the release pipeline, or accelerate Phase 5 Tier A components are welcome.
4. **Sponsor development** — Tier C feasibility depends on funding. Get
   in touch via `contact@opensecstack.org` if your organisation wants to
   accelerate a specific component.

## Honest caveats

- **Phase 5 Tier C is aspirational** for the *desktop/mobile OS product*
  goal — a shipped, production Runix v1.0 (layers 1-6) and Runix Mobile
  still depend on the funding/staffing this section describes. That said,
  **this is no longer a "no code exists" caveat for Runix itself**: Alpha
  kernel bring-up (boot through a real ring 0 → ring 3 transition,
  capability manager, syscall-gated IPC, a real Wasm engine) is
  implemented and CI-tested today in [opensecstack/runix](https://github.com/opensecstack/runix),
  independent of Tier C funding materialising. Runix Mobile and
  runix-mvno remain designs, not code, pending the funding/backing
  described above. The core 11-platform security stack continues
  regardless of any of this.
- **VertGuard ML model weights** are not bundled — operators must supply trained weights for the video/voice/identity models or run with the stub backend. The model training pipeline and configs are included.
- **Post-quantum migration is not optional** — NIST PQC standards
  (2024) plus expected NIS3 requirements (2030-2032) make this a
  must-have for ecosystem survival beyond 2030.
- **We will not ship a platform before its own v1.0.0 readiness gate
  passes**, even if the roadmap slips. Quality over calendar.
