# CyberPath Roadmap

> Public roadmap for CyberPath — the security training and
> certification platform in the opensecstack (SIN) ecosystem. Phase 2
> (Modules 1–8) shipped as v1.0.0 on 2026-05-09, well ahead of the
> original 2027 Q1–Q2 targets recorded below for historical context.
>
> This roadmap complements the ecosystem-wide
> [ROADMAP.md § Phase 2](../ROADMAP.md) and the strategic decision
> recorded in
> [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md).

## Guiding principles

1. **Completions are evidence.** Every track completion produces a
   CITADEL WORM entry signed against an immutable content version.
   A completion that cannot be sealed into the audit chain is not a
   completion.
2. **Hands-on first.** Slide-deck training fails the spirit of NIS2
   Article 21(2)(g). Every track that can have a lab, has a lab.
3. **Sandbox over VM.** Lab spinup must be seconds, not minutes.
   v1.0.0 ships Docker-based labs because they exist today; v1.0.0
   ships Wasm-based labs because they're the right answer for
   browser-delivered cyber training.
4. **Bilingual from day one.** Albanian (shqip) and English in the
   learner UI. Track content is authored bilingually, not
   machine-translated post-hoc.

## Phase 2 — Learning Path + Docker Labs

Go + React foundation: learning path engine, quiz engine, Docker-based
labs. Originally targeted for a 2027 Q1 release; shipped far ahead of
that target as part of the single v1.0.0 release on 2026-05-09 (see
[CHANGELOG.md](CHANGELOG.md) — Modules 1–3 shipped together with
Modules 4–8, not as a separate earlier release).

### v1.0.0 — shipped 2026-05-09 (Modules 1–3)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Scaffold + docs + LICENSE + paperwork | — | Done |
| PostgreSQL schema (users, paths, modules, lessons, quizzes, progress, completions, content_versions) | 1 | Done |
| Go orchestrator for learning paths | 1 | Done |
| API: `GET /api/v1/tracks`, `GET /api/v1/tracks/{id}`, `POST /api/v1/enrollments`, `POST /api/v1/lessons/{id}/complete` | 1 | Done |
| Quiz engine + question banks + randomisation | 2 | Done |
| API: `POST /api/v1/quizzes/{id}/submit` | 2 | Done |
| Docker-based lab provisioner | 3 | Done |
| WebSocket relay + browser terminal (xterm.js) | 3 | Done |
| API: `POST /api/v1/labs/{id}/start` | 3 | Done |
| React frontend: learner UI, dashboard, lesson runner | — | Done |
| i18n (shqip + anglisht) | — | Done |
| Initial 3 tracks: NIS2 Article 21 awareness, Phishing recognition, Secure coding | — | Done |
| Integration tests against live Postgres | — | Done |

### Success metrics for v1.0.0

- **Lab spinup p95:** ≤ 30s (Docker) — met at ship
- **Quiz scoring accuracy:** 100% (deterministic for v1.0.0 banks)
- **Track completion rate (pilot):** ≥ 70% on the NIS2 Article 21
  awareness track
- **First pilot deployment:** delivered with v1.0.0, 2026-05-09

## Phase 2 — Wasm Sandbox + Certification + Audit Evidence

Adds the Rust + wasmtime sandbox, certification issuance, and the
CITADEL evidence chain. Originally targeted for a 2027 Q2 release;
shipped as part of the same v1.0.0 release, 2026-05-09.

### v1.0.0 — shipped 2026-05-09

| Deliverable | Module | Status |
|---|:-:|:-:|
| wasmtime host integration | 4 | Done |
| Pre-built lab image build pipeline | 4 | Done |
| Lab-image registry with SHA-256 + cosign keyless signatures | 4 | Done |
| Per-session isolation policy + escape-attempt tests (41 cases) | 4 | Done |
| Certification issuance (per-track) | 5 | Done |
| Signed completion certificates (Ed25519) | 5 | Done |
| `cyberpath.completion` event emission to CITADEL (HMAC-SHA256) | 6 | Done |
| CITADEL Kerkese schema extension | 6 | Done |
| `GET /api/v1/cyberpath/coverage/{user_id}` (NIS2 Compass) | 7 | Done |
| `GET /api/v1/cyberpath/recommend?gap=<measure>` (NIS2 Compass) | 7 | Done |
| Content versioning (immutable lesson revisions, `content_version_id` on every completion) | 8 | Done |
| IRFlow integration: incident → recommended track | — | Done |
| Remaining 5 tracks: IR basics, API security, threat intel basics, Linux hardening, network forensics | — | Done |
| v1.0.0 third-party security review (sandbox escape focus) | — | Pending (auditor scheduling) |
| Full documentation at v1.0 standard | — | Done |

### Success metrics for v1.0.0

- **v1.0.0 ship:** delivered 2026-05-09 (well ahead of the original
  2027 Q2 target)
- **Wasm lab spinup p95:** ≤ 5s
- **CITADEL evidence emission success rate:** ≥ 99.9%
- **Sandbox escape findings during third-party review:** 0
  unmitigated highs/criticals at release
- **NIS2 Article 21(2)(g) coverage:** 100% — every Article 21 measure
  with a training requirement maps to at least one CyberPath track

## Post-v1.0 direction (2027 Q3+)

### v1.x (2027 Q3 – 2028)

- New tracks added in response to NIS2 amendments (anticipated
  2027–2028 review cycle)
- Additional EU language coverage in the learner UI
- Hardware-isolated lab runtime evaluation (Firecracker, gVisor) for
  exercises the Wasm sandbox can't host (e.g. kernel-level forensics)
- VertGuard cross-platform tracks (deepfake recognition, prompt
  injection awareness for non-engineers) once VertGuard v0.5+ ships
- Threat-intel-driven track auto-recommendation (ThreatFlow IOC
  surfacing → track suggestion)

### v2.0 (post-NIS2 amendment cycle)

- Federated certification trust (cross-CSIRT certification
  recognition via OpenCSIRT)
- Adaptive learning paths driven by NIS2 Compass gap analytics
- Post-quantum signing of certifications (aligned with
  [ADR-011](../adrs/ADR-011-post-quantum-agility.md))

## Non-goals

- **Not a general-purpose LMS.** CyberPath is cyber-training-
  specific. Generic L&D content (HR onboarding, sales training, etc.)
  belongs in Moodle or TalentLMS.
- **Not a CTF platform.** Lab content is curriculum-anchored, not
  capture-the-flag scoring. SecureLab is the ecosystem's CTF /
  attack-simulation platform.
- **Not a content marketplace.** Tracks are authored within the
  ecosystem. Third-party content can be imported with attribution but
  is not a primary delivery channel.
- **Not a real-time proctoring platform.** Certifications are
  evidence of completion against a content version, not proctored
  exam outcomes.

## Call for contributions

CyberPath is v1.0.0 and feature-complete for its initial 8 modules —
the data model, lab runtime, and certification format are settled.
Open areas for contribution now are extensions to the shipped
platform, not scaffold work:

- **Track content authoring** — new tracks beyond the 8 initial ones
  (NIS2 Article 21 awareness, phishing recognition, secure coding, IR
  basics, API security, threat-intel basics, Linux hardening, network
  forensics)
- **Additional Wasm lab images** on the existing build pipeline
  (Rust + wasmtime)
- **Additional EU language coverage** in the learner UI, beyond the
  shipped shqip + anglisht i18n
- **Per-schema tenant isolation** (see [docs/tenancy.md](docs/tenancy.md)
  — today only a bare `tenant_id` column ships)
- **Hardware-isolated lab runtime evaluation** (Firecracker, gVisor)
  for exercises the Wasm sandbox can't host

Open an issue with label `claim-module` or `good-first-issue`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related

- [../ROADMAP.md § Phase 2](../ROADMAP.md) — ecosystem-wide roadmap
- [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md) — strategic decision
- [docs/architecture.md](docs/architecture.md) — detailed architecture
- [docs/module-list.md](docs/module-list.md) — initial 8 tracks
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [docs/nis2-integration.md](docs/nis2-integration.md)
