# ADR-010: VertGuard Platform Strategy

**Status:** Accepted
**Date:** 2026-04-20
**Deciders:** core-maintainers, vertguard-platform-team
**Supersedes:** —
**Related:** [ADR-011 Post-Quantum Agility](./ADR-011-post-quantum-agility.md), [ROADMAP.md § Phase 4](../ROADMAP.md#phase-4--ai-attack-defence-2026-q3--2028-q4)

---

**Implemented** — VertGuard shipped v1.0.0 (production) on 2026-05-10.
See [vertguard/CHANGELOG.md](../vertguard/CHANGELOG.md) `[1.0.0]`,
[ECOSYSTEM.md](../ECOSYSTEM.md), and [CLAUDE.md](../CLAUDE.md) for
current status. The design and phased scope below are retained as a
historical record of the decision; they still describe the platform's
architecture accurately.

## Context

The opensecstack ecosystem's 9 platforms (5 active + 4 planned) cover
classic cybersecurity threat categories: API vulnerabilities, NIS2
compliance gaps, threat intelligence, incident response, DDoS, training,
attack simulation, and CSIRT operations. **None of them address
AI-generative threats** — deepfakes, AI-generated phishing, prompt
injection, synthetic identity fraud, AI-agent misbehaviour.

This is a meaningful gap because:

1. **Market reality (2026):** AI-generated phishing has grown ~400% in
   2024-2026. Voice-clone CEO fraud has caused €25M+ confirmed losses.
   Prompt injection is the OWASP LLM Top 10 #1 issue.
2. **Regulatory trajectory:** EU AI Act (in force since 2024) addresses
   AI *producers*; NIS3 (expected 2030-2032) is projected to address
   AI-attack *defences* for essential entities.
3. **OSS landscape gap:** No production-grade OSS alternative exists.
   Commercial options (Reality Defender, Lakera, Protect AI) are SaaS,
   non-EU-sovereign, and cost €30k-€300k/year per deployment.

Without an AI-defence platform, the ecosystem's positioning as "the
EU's sovereign alternative for NIS-scope organisations" is incomplete
by 2028-2030 as AI threats dominate the landscape.

## Decision

**Add VertGuard as the 10th opensecstack platform**, delivered in three
phases. Adopt a staggered build approach where the Go/Rust modules ship
first (without requiring ML expertise), followed by the Python ML layer
as funding and talent allow.

### Name

- Working internal name: **VertGuard**
- Albanian-first alternative: **Vërtet** (means "truly / authentically"
  — semantically aligned with "content authenticity / AI truth
  verification")
- Final name to be confirmed before v0.1.0 tag. This ADR uses
  VertGuard for clarity.

### Scope — 5 modules

| Module | Purpose | Language | Phase |
|---|---|---|---|
| **1. Media Authenticity** | C2PA provenance + deepfake detection (image/video/audio) | Rust (C2PA) + Python (ML) | 4.2 |
| **2. AI Phishing Detection** | LLM-generated email/chat classification | Python ML | 4.2 |
| **3. Prompt Injection Defence** | OWASP LLM Top 10 scanner + LLM firewall integration | Rust pattern engine + Go | **4.1** |
| **4. AI Threat Intelligence Feed** | AI-specific IOCs, MITRE ATLAS mapping, ThreatFlow integration | Go | **4.1** |
| **5. Synthetic Identity Detection** | GAN-generated profile + real-time video call analysis | Python ML | 4.3 |

### Phased timeline

| Phase | Target | Scope | Requires |
|---|---|---|---|
| **4.1 v0.1** | 2026 Q4 | Modules 3 + 4 (Go/Rust only) | Existing engineering team |
| **4.2 v0.5** | 2027 Q3 | Modules 1 + 2 (Python ML layer) | ML expertise hire + EU funding |
| **4.3 v1.0** | 2028 Q3 | Module 5 + real-time analysis | Matured ML pipelines + GPU budget |

### Architecture

- **Go**: HTTP API, orchestration, CITADEL + ThreatFlow integration,
  pattern engine coordination. Same pattern as the other 9 platforms.
- **Rust**: C2PA library bindings (via `c2pa-rs`), prompt injection
  pattern matching, audio fingerprinting. Performance-critical paths
  where memory safety matters (parsing untrusted inputs).
- **Python**: ML inference service via gRPC side-car. HuggingFace
  model zoo adapters. Runs in separate process from Go for fault
  isolation.
- **gRPC boundary** between Go and Python — chosen over CGO (fragile),
  REST (latency), shared memory (complexity).
- **Model registry** (`models.yaml`) with SHA-256 checksums.
  Pre-trained models are downloaded on first run from verified URLs,
  never committed to git.
- **Dataset registry** (`datasets.yaml`) — same pattern for test data
  (licensing + repo-size + privacy hygiene).

### Licence

**AGPL-3.0** — consistent with governance-adjacent platforms (CITADEL,
IRFlow, NIS2 Compass, OpenCSIRT). VertGuard produces evidence that
enters the audit chain and participates in compliance decisions;
copyleft prevents closed-source forks of a trust component.

### Ports

- API: **8091** (next after NIS2 Compass's 8090)
- Dashboard: **3009**
- gRPC ML side-car: **50051** (internal-only, Phase 4.2+)

See [docs/deployment-topology.md](../docs/deployment-topology.md).

## Alternatives considered

### Alternative A: Platform right now (Option A in discussion)

Build all 5 modules simultaneously before Phase 1 ecosystem maturity.

- **Rejected** because: ML expertise is not in the current team; the
  9 existing platforms still need to reach stable v1.0.0; revenue to
  fund ML hires doesn't exist yet.

### Alternative B: Defer entirely until 2028-2029

Wait for NIS3 draft publication before starting any implementation.

- **Rejected** because: first-mover advantage in OSS AI-defence is
  significant; prompt-injection market demand exists today; Modules 3
  and 4 require zero ML expertise and can ship in 2026 with existing
  capabilities.

### Alternative C: Distribute into existing platforms (Option C in discussion)

Extend ThreatFlow with AI-IOC feeds, APIGuard with deepfake endpoints,
CyberPath with AI-threat modules, SecureLab with AI-attack scenarios.

- **Rejected** because: AI-attack defence is a distinct discipline
  requiring specialised detection models, a unified detector pipeline,
  a coherent dashboard, and dedicated threat intelligence. Fragmenting
  across platforms makes each underpowered and loses the marketing
  narrative ("where do I go for AI defence?" has no answer).

### Chosen: Staggered platform (hybrid of Options A + B)

Modules 3 + 4 ship in Phase 4.1 as a standalone platform (v0.1.0) —
this is Option A's "ship now" benefit for the modules that don't need
ML. Modules 1, 2, 5 defer to Phase 4.2 and 4.3 as Option B suggests
for the ML-heavy modules.

## Consequences

### Positive

- **Closes the AI-attack coverage gap** that no other OSS ecosystem
  addresses for NIS-scope entities.
- **NIS3-ready by 2030-2032** — v1.0.0 lands at the start of the NIS3
  transposition window.
- **First-mover positioning** in OSS prompt-injection defence (Module
  3), a market with active commercial demand.
- **Revenue path** — Phase 4.1 modules are commercially deployable
  without ML; early adopters fund Phase 4.2's ML team.
- **Coherent story** for the ecosystem — 10 platforms covering both
  classic and AI-generative threat landscapes.
- **MITRE ATLAS adoption** — Module 4 aligns the ecosystem with the
  emerging MITRE ATLAS framework (ATT&CK for AI systems).

### Negative

- **Scope expansion** — 10th platform adds coordination overhead.
  Mitigated by monorepo structure (no repo split needed in 2026-2028).
- **ML expertise dependency** — Phase 4.2 stalls without ML hires.
  Mitigated by Phase 4.1's independence from ML.
- **Model refresh cycles** — deepfake / AI-generation models evolve
  every 3-6 months. Platform must be model-zoo-adapter-friendly, not
  hard-coded to specific models. Addressed by `models.yaml` registry.
- **Adversarial arms race** — attackers will adapt to evade detectors.
  Requires ongoing research engagement (university partnerships).
- **False-positive sensitivity** — a legitimate image flagged as
  deepfake erodes trust. Configurable confidence thresholds per
  deployment; extensive false-positive test suite in `tests/fp/`.
- **Privacy concerns** — content scanning requires access. Addressed
  by on-device inference support for private content; `docs/privacy-ml-inference.md`
  covers the deployment options.

### Neutral

- **Ecosystem total grows from 9 → 10 platforms.**
- **Doc count grows from 358 → 391** (+33 VertGuard docs).
- **Ecosystem release numbering**: `v1.1.0` adds VertGuard v0.1
  (Phase 4.1); `v2.0.0` includes VertGuard v1.0 (Phase 4.3 complete).

## Open questions (defer to Phase 4.1 start)

1. Final name: VertGuard (English-global) or Vërtet (Albanian-first)?
2. Does ML service run as side-car (per VertGuard pod) or shared
   service (one per cluster)? Side-car simpler, shared more efficient
   for GPU utilisation.
3. Which LLM firewall integration to ship by default in v0.1 — NeMo
   Guardrails (NVIDIA), Llama Guard (Meta), or both?
4. Commercial-support offering in 2027 — separate company or through
   existing OpenSecStack Foundation?

## Implementation checklist (Phase 4.1 kickoff)

- [ ] This ADR approved by core-maintainers.
- [ ] VertGuard lead identified (internal or new hire).
- [ ] `opensecstack/vertguard/` directory created with 12 standard docs
      + SBOM.json + initial docker-compose.
- [ ] Module 3 Rust crate (`vertguard/rust/prompt-patterns/`) scoped.
- [ ] Module 4 Go package (`vertguard/internal/threatfeed/`) scoped.
- [ ] ThreatFlow integration contract reviewed and approved.
- [ ] CITADEL Kerkese schema extended with `vertguard.detection`
      event type.
- [ ] Updated: [ECOSYSTEM.md](../ECOSYSTEM.md), [ROADMAP.md](../ROADMAP.md),
      [docs/deployment-topology.md](../docs/deployment-topology.md),
      [docs/compatibility-matrix.md](../docs/compatibility-matrix.md).
- [ ] `good-first-issues` label applied to 5 initial Module 3+4 tasks.
- [ ] Public announcement (blog post + HN + LinkedIn) when v0.1.0-rc1 ships.

## Review

Quarterly review by core-maintainers. Next review: 2026 Q4 (before
Phase 4.1 kickoff).
