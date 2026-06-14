# CyberPath Roadmap

> Public roadmap for CyberPath — the security training and
> certification platform in the opensecstack (SIN) ecosystem. Phase 2
> delivery across 2027 Q1–Q2.
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

## Phase 2 — Learning Path + Docker Labs (2027 Q1)

Go + React only. No Wasm runtime yet. Ships v1.0.0 by 2027 Q1.

### v1.0.0 (2027 Q1 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Scaffold + docs + LICENSE + paperwork | — | In progress |
| PostgreSQL schema (users, paths, modules, lessons, quizzes, progress, completions, content_versions) | 1 | Planned |
| Go orchestrator for learning paths | 1 | Planned |
| API: `GET /api/v1/tracks`, `GET /api/v1/tracks/{id}`, `POST /api/v1/enrollments`, `POST /api/v1/lessons/{id}/complete` | 1 | Planned |
| Quiz engine + question banks + randomisation | 2 | Planned |
| API: `POST /api/v1/quizzes/{id}/submit` | 2 | Planned |
| Docker-based lab provisioner | 3 | Planned |
| WebSocket relay + browser terminal (xterm.js) | 3 | Planned |
| API: `POST /api/v1/labs/{id}/start` | 3 | Planned |
| React frontend: learner UI, dashboard, lesson runner | — | Planned |
| i18n (shqip + anglisht) | — | Planned |
| Initial 3 tracks: NIS2 Article 21 awareness, Phishing recognition, Secure coding | — | Planned |
| Integration tests against live Postgres | — | Planned |

### Success metrics for v1.0.0

- **Time-to-v1.0.0:** ≤ 6 months from scaffold completion
- **Lab spinup p95:** ≤ 30s (Docker)
- **Quiz scoring accuracy:** 100% (deterministic for v1.0.0 banks)
- **Track completion rate (pilot):** ≥ 70% on the NIS2 Article 21
  awareness track
- **First pilot deployment:** 2027 Q1 target

## Phase 2 — Wasm Sandbox + Certification + Audit Evidence (2027 Q2)

Adds the Rust + wasmtime sandbox, certification issuance, and the
CITADEL evidence chain. Ships v1.0.0 by 2027 Q2.

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

- **v1.0.0 ship:** 2027 Q2 or earlier
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

CyberPath is greenfield as of 2026-04-26. Specifically open for
claim once v0.0.1 lands:

- **Track content authoring** (each of the 8 initial tracks)
- **Wasm lab image build pipeline** (Rust + wasmtime)
- **Browser terminal integration** (xterm.js + WebSocket relay)
- **NIS2 Compass coverage API contract** (joint with the NIS2 Compass
  team)
- **CITADEL `cyberpath.completion` schema** (joint with the CITADEL
  team)

Open an issue with label `claim-module` or `good-first-issue`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## Related

- [../ROADMAP.md § Phase 2](../ROADMAP.md) — ecosystem-wide roadmap
- [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md) — strategic decision
- [docs/architecture.md](docs/architecture.md) — detailed architecture
- [docs/module-list.md](docs/module-list.md) — initial 8 tracks
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [docs/nis2-integration.md](docs/nis2-integration.md)
