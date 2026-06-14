# ADR-012: CyberPath Platform Strategy

**Status:** Proposed
**Date:** 2026-04-26
**Deciders:** core-maintainers, cyberpath-lead (TBD)
**Supersedes:** —
**Related:** [ADR-010 VertGuard Platform Strategy](./ADR-010-vertguard-platform-strategy.md), [ADR-011 Post-Quantum Agility](./ADR-011-post-quantum-agility.md), [ROADMAP.md § Phase 2](../ROADMAP.md)

---

## Context

NIS2 Article 21(2)(g) requires essential and important entities to
provide cybersecurity training to staff with documented evidence of
completion. Auditors increasingly ask not "did you train?" but
"show me the immutable record of who completed what training, when,
against which lesson revision."

The opensecstack ecosystem already covers the surrounding compliance
surface — NIS2 Compass identifies gaps, CITADEL stores immutable
audit evidence, IRFlow handles incident response. **The training
platform that produces audit-grade completion evidence is missing.**

This is a real gap because:

1. **Existing LMSes are not audit-grade.** Moodle, TalentLMS, and the
   commercial cyber-training SaaS landscape (KnowBe4, Hoxhunt,
   Curricula) treat completion as a database row. Records are
   mutable, content is mutable, and there is no cryptographic chain
   to an external audit ledger. An auditor cannot independently
   verify a completion record without trusting the LMS operator.
2. **Hands-on cyber labs in browsers are still hard.** Slide-deck
   training fails the spirit of Article 21(2)(g). Phishing
   recognition needs to be practised against real samples; secure
   coding needs an editor and a real CVE corpus. Browser-VM patterns
   work but are heavy; container-in-browser is reasonable but
   spinup is slow.
3. **The ecosystem already has the pieces.** CITADEL provides the
   WORM ledger. NIS2 Compass provides gap analytics. IRFlow
   provides the incident-derived "what training would have
   prevented this?" signal. Without a training platform that
   integrates with all three, the ecosystem leaves the Article 21(2)(g)
   evidence chain to third-party LMSes that don't speak the
   ecosystem's contracts.
4. **Phase 2 timing aligns with NIS2 audit cycles.** First-cycle NIS2
   audits begin landing in 2027–2028 across EU member states. A
   training platform that ships v1.0.0 in 2027 Q2 is on the right
   side of that cycle.

Without CyberPath, opensecstack's positioning as "the EU's sovereign
NIS2 compliance stack" is incomplete: the audit chain has a hole
where training evidence should be.

## Decision

**Add CyberPath as the security training and certification platform
in opensecstack**, delivered in two releases across Phase 2.

### Scope — 8 modules across 2 releases

| Module | Purpose | Language | Release |
|---|---|---|---|
| **1. Learning Path Engine** | Track / module / lesson sequencing, prerequisites, progress | Go | **v0.1.0** |
| **2. Quiz & Assessment Engine** | Knowledge-check assessments with question banks | Go | **v0.1.0** |
| **3. Docker-Based Labs** | Hands-on lab environments via per-session Docker + xterm.js | Go + React | **v0.1.0** |
| **4. Wasm Sandbox Labs** | Lower-overhead, faster-spinup labs on a wasmtime host | Rust + Go | **v1.0.0** |
| **5. Certification Issuance** | Per-track signed completion certificates | Go | **v1.0.0** |
| **6. CITADEL Evidence Emitter** | Async `cyberpath.completion` event emission | Go | **v1.0.0** |
| **7. NIS2 Compass Coverage API** | Article 21 measure coverage queries | Go | **v1.0.0** |
| **8. Content Versioning** | Immutable lesson revisions | Go | **v1.0.0** |

### Phased timeline

| Release | Target | Scope | Requires |
|---|---|---|---|
| **v0.0.1** (scaffold + skeleton) | 2026 Q4 | Repo skeleton; `make build`; `/api/v1/health` | Existing engineering team |
| **v0.1.0** (alpha) | 2027 Q1 | Modules 1, 2, 3 — Learning paths, quizzes, Docker labs | Existing engineering team |
| **v1.0.0** (stable) | 2027 Q2 | Modules 4, 5, 6, 7, 8 — Wasm labs, certification, CITADEL evidence | Rust + Wasm engineering capacity |

### Architecture

- **Go**: HTTP API (chi), persistence (pgx), logging (zerolog),
  config (viper), metrics (prometheus). Same stack as VertGuard /
  APIGuard for ecosystem consistency and shared operator handbook
  coverage.
- **React + TypeScript + Vite**: learner UI, dashboard, lesson
  runner, quiz UI, browser terminal (xterm.js + WebSocket). Bilingual
  (shqip + anglisht) from day one.
- **Rust + wasmtime** (v1.0.0+): sandbox host. Pre-built lab images
  registered in `labs/labs.yaml` with SHA-256 checksums.
  Per-session isolation, no host filesystem access by default.
- **PostgreSQL** schema spans: `users`, `paths`, `modules`,
  `lessons`, `quizzes`, `progress`, `completions`, `certifications`,
  `lab_sessions`, `content_versions`. One DB instance per platform
  (ecosystem standard).
- **Integrations**:
  - CITADEL — `cyberpath.completion` evidence events (HMAC-SHA256
    signed, async drain queue, circuit breaker — same pattern as
    VertGuard's CITADEL emitter).
  - NIS2 Compass — `GET /api/v1/cyberpath/coverage/{user_id}` and
    `GET /api/v1/cyberpath/recommend?gap=<measure>`.
  - IRFlow — incident-derived training plays (incident type → track
    recommendation).
  - opensecstack/sdk — auth + Argon2id password hashing (shared
    primitives).

### Licence

**Apache 2.0** — consistent with the ecosystem's tool-platform tier
(APIGuard, ThreatFlow, OpenScrub, SecureLab). CyberPath is intended
to be embeddable in proprietary corporate LMS deployments and
training pipelines; copyleft would block that integration. The
audit-grade evidence chain is enforced by integration with CITADEL
(which is governance-adjacent and AGPL-licensed), not by the
training platform's own licence.

### Ports

- API: **8086** (already reserved in
  [docs/deployment-topology.md](../docs/deployment-topology.md))
- Dashboard: **3006** (already reserved)

## Alternatives considered

### Alternative A: Extend an existing LMS (Moodle plug-in)

Build CyberPath as a Moodle plug-in that adds CITADEL evidence
emission and NIS2 Compass integration, leaving the rest of the LMS
to Moodle.

- **Rejected** because: Moodle's content model and completion
  semantics are designed for academic course management, not
  cryptographically anchored audit evidence. Retrofitting an
  immutable content-version chain on top of Moodle's mutable
  resource model is harder than starting from a model that's
  audit-first. Sandbox labs in Moodle are not first-class. Moodle's
  PHP stack also doesn't fit the ecosystem's Go-platform homogeneity
  benefit.

### Alternative B: Browser-VM-only labs (no Wasm sandbox)

Skip the v1.0.0 Wasm sandbox; ship Docker-based labs as the
permanent solution.

- **Rejected** because: Docker spinup p95 is 30s+ even on a warm
  host, and per-learner container resource cost limits scale.
  wasmtime spinup is sub-second for the same lab classes. Docker
  labs remain in scope (Module 3) for exercises that genuinely need
  a Linux userspace; Wasm labs are the right answer for the
  majority of cyber training content.

### Alternative C: Hosted SaaS (commercial product)

Operate CyberPath as a commercial multi-tenant SaaS, not as an OSS
self-hostable platform.

- **Rejected** because: NIS2-scope organisations across the EU
  increasingly require self-hostable, EU-sovereign training
  platforms. SaaS alternatives exist already (KnowBe4, Hoxhunt) and
  the OSS ecosystem gap is precisely a self-hostable, audit-grade,
  EU-sovereign training stack. Hosted-SaaS is incompatible with
  CITADEL deployment patterns where the WORM ledger lives inside the
  customer's perimeter.

### Alternative D: Defer entirely until 2028

Wait for first-cycle NIS2 audit feedback before starting.

- **Rejected** because: training-evidence audit gaps are visible to
  deployers today; first-cycle audits land in 2027 Q3 onwards;
  shipping v1.0.0 in 2027 Q2 puts CyberPath on the right side of
  the audit cycle for early-adopter NIS2 entities.

### Chosen: Phase-2 staggered platform (Apache 2.0)

Build CyberPath as a standalone platform in Phase 2. Modules 1–3
ship in v0.1.0 with no Rust dependency (Go + React + Docker labs);
Modules 4–8 ship in v1.0.0 with the Wasm sandbox and the audit-
grade evidence chain to CITADEL.

## Consequences

### Positive

- **Closes the Article 21(2)(g) audit-evidence gap** that no
  existing OSS LMS addresses for NIS2 entities.
- **Audit-grade by design** — completions reference an immutable
  content version and seal into CITADEL WORM. An auditor can rerun
  the same lesson the learner saw.
- **First-mover positioning** in OSS audit-grade cyber training.
- **Coherent ecosystem story** — gap (NIS2 Compass) → training
  (CyberPath) → evidence (CITADEL) → response (IRFlow) is a
  closed loop.
- **Hands-on first** — Docker labs in v0.1.0, Wasm labs in v1.0.0.
  Both browser-delivered.
- **Embeddable** — Apache 2.0 lets enterprises integrate CyberPath
  into existing corporate LMS portals without licence friction.

### Negative

- **Content authoring is the long pole.** Software is shippable in
  2 quarters; eight bilingual tracks with quiz banks and lab
  exercises are not. Mitigated by phasing: 3 tracks ship in v0.1.0,
  remaining 5 in v1.0.0.
- **Wasm sandbox depends on wasmtime upstream.** Sandbox-escape
  CVEs in wasmtime become CyberPath's problem. Mitigated by
  pinning + patch SLA documented in SECURITY.md.
- **Bilingual content doubles authoring cost.** Albanian +
  English from day one is a deliberate cost; mitigated by treating
  shqip as the source language for opensecstack-internal content
  and English as the translated target.
- **Certification signing key management.** v1.0.0 introduces a
  long-lived Ed25519 signing key; key rotation procedures must be
  documented before v1.0.0 ships.
- **NIS2 Compass coupling.** The coverage API depends on NIS2
  Compass's measure taxonomy; Compass schema changes ripple into
  CyberPath. Mitigated by treating `docs/nis2-integration.md` as a
  bilateral contract.

### Neutral

- **Ecosystem total grows by one Phase-2 platform.** Already
  reflected in [ECOSYSTEM.md](../ECOSYSTEM.md) and
  [ROADMAP.md](../ROADMAP.md); no schema changes elsewhere.
- **Doc count grows** as v1.0.0 paperwork lands (initial scaffold:
  ~12 docs; full v1.0.0 audit-readiness package: ~25 docs).

## Open questions (defer to Phase 2 kickoff)

1. Wasm runtime selection: wasmtime (Bytecode Alliance) vs
   wasmer. Default working assumption is wasmtime; revisit at v0.5.0.
2. Lab-image distribution: ship images via OCI registry alongside
   Docker images, or separate registry? Default working assumption
   is OCI registry.
3. Certification format: human-readable PDF + JSON-LD signed
   credential, or JSON-LD only? Default working assumption is
   both, with PDF as a rendered view.
4. Multi-tenant deployment posture for v1.0.0: per-tenant DB
   schema, per-tenant DB instance, or row-level isolation? Default
   working assumption matches CITADEL's multi-tenant pattern;
   revisit when CITADEL formalises it.

## Implementation checklist (Phase 2 kickoff)

- [ ] This ADR approved by core-maintainers.
- [ ] CyberPath lead identified.
- [ ] `opensecstack/cyberpath/` directory created with scaffold
      paperwork (this commit).
- [ ] Updated: [ECOSYSTEM.md](../ECOSYSTEM.md),
      [ROADMAP.md](../ROADMAP.md),
      [docs/deployment-topology.md](../docs/deployment-topology.md),
      [docs/compatibility-matrix.md](../docs/compatibility-matrix.md).
- [ ] CITADEL Kerkese schema extended with `cyberpath.completion`
      event type — joint with the CITADEL team.
- [ ] NIS2 Compass coverage / recommend contract reviewed and
      approved — joint with the NIS2 Compass team.
- [ ] `good-first-issue` label applied to the first 5 v0.1.0
      tasks (PostgreSQL schema, learning-path orchestrator, quiz
      engine skeleton, browser terminal proof of concept, NIS2
      Article 21 awareness track outline).

## References

- NIS2 Directive (EU) 2022/2555, Article 21(2)(g) —
  cybersecurity training requirement
- OWASP Top 10 (2021) — secure coding track source
- MITRE ATT&CK — IR basics + threat-intel basics track sources
- C2PA (referenced indirectly via VertGuard cross-platform tracks)
- Bytecode Alliance wasmtime — Wasm sandbox runtime
- Moodle, TalentLMS — LMS comparison points (not adopted)
- KnowBe4, Hoxhunt, Curricula — commercial cyber-training comparison
  points (not adopted)

## Review

Quarterly review by core-maintainers. Next review: 2026 Q4 (before
Phase 2 kickoff).
