# CyberPath Changelog

All notable changes to CyberPath are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For the ecosystem-wide changelog, see [../CHANGELOG.md](../CHANGELOG.md).

---

## [1.0.0] — 2026-05-09

First stable release. Modules 1–8 feature-complete.

### Added

- **Module 4 — Wasm Sandbox Labs**
  - wasmtime host (`rust/sandbox-host/`) with per-session `CapabilityBag`
    (fs allowlist, network deny-by-default, fuel + 512 MiB memory cap).
  - `from_lab_manifest()` parses `lab.yaml` into a real `CapabilityBag`
    (replaces v0.9 TODO stub); falls back to defaults on parse error.
  - Lab-image build pipeline: `Dockerfile` template (`FROM scratch`,
    UID 65534) + GitHub Actions workflow `publish-track.yml` that
    builds, pushes to `ghcr.io/opensecstack/cyberpath-labs/`, signs
    keyless with cosign, attaches CycloneDX SBOM attestation, and
    stamps `labs/labs.yaml` with the resolved digest.
- **Module 5 — Certification Issuance** with Ed25519-signed
  completion certificates per track.
- **Module 6 — CITADEL Evidence Emitter**: async
  `cyberpath.completion` event emission (HMAC-SHA256).
- **Module 7 — NIS2 Compass Coverage API**:
  `GET /api/v1/cyberpath/coverage/{user_id}` and
  `GET /api/v1/cyberpath/recommend?gap=<measure>`.
- **Module 8 — Content Versioning**: every completion references an
  immutable `content_version_id`.
- **Pre-audit gap closure** (per `docs/security/pre-audit-plan.md`):
  - **G1** — sandbox-escape integration tests
    (`rust/sandbox-host/tests/escape_attempts.rs`, 41 cases across
    path traversal, SSRF/loopback, fuel exhaustion, capability bag,
    engine isolation).
  - **G2** — content-yaml fuzz harness
    (`internal/content/fuzz_test.go` + seed corpus).
  - **G3** — multi-tenant isolation integration test
    (`tests/integration/multi_tenant_test.go`, build tag
    `integration`).

### Changed

- `rust/sandbox-host` Cargo manifest split into `[lib]` + `[[bin]]`
  so integration tests under `tests/` can import crate symbols.
- `Cargo.toml` adds `serde_yaml = "0.9"` for manifest parsing.

### Pending external work (not a release blocker)

- Third-party security review engagement per
  `docs/security/pre-audit-plan.md`. All G1/G2/G3 prerequisites are
  in place; auditor scheduling is operational.

---

## [Unreleased]

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

### Scaffold

- Initial platform scaffold per [ADR-012](../adrs/ADR-012-cyberpath-platform-strategy.md).
- Root paperwork: README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT,
  LICENSE (Apache 2.0), CHANGELOG, ROADMAP, Makefile (stub),
  `.gitignore`.
- Documentation skeleton:
  - `docs/architecture.md` — Go + React + Rust-Wasm topology, schema
    overview, integration arrows
  - `docs/module-list.md` — initial 8 tracks for v1.0.0
  - `docs/citadel-integration.md` — `cyberpath.completion` event
    schema and WORM submission flow
  - `docs/nis2-integration.md` — NIS2 Compass coverage + recommend
    API contracts
- Ecosystem registration:
  - Listed in [ECOSYSTEM.md](../ECOSYSTEM.md) as Phase 2 platform
  - Port 8086 (API) + 3006 (dashboard) reserved in
    [../docs/deployment-topology.md](../docs/deployment-topology.md)

### Planned (Phase 2 — 2027 Q1 target, v1.0.0)

- **Module 1 (Learning Path Engine):**
  - PostgreSQL schema (users, paths, modules, lessons, quizzes,
    progress, completions, content_versions)
  - Go orchestrator (`internal/path/`)
  - API endpoints: `GET /api/v1/tracks`, `GET /api/v1/tracks/{id}`,
    `POST /api/v1/enrollments`, `POST /api/v1/lessons/{id}/complete`
- **Module 2 (Quiz & Assessment Engine):**
  - Question banks, randomisation, scoring
  - API endpoint: `POST /api/v1/quizzes/{id}/submit`
- **Module 3 (Docker-Based Labs):**
  - Per-session container provisioner
  - WebSocket relay for browser terminal (xterm.js)
  - API endpoint: `POST /api/v1/labs/{id}/start`
- **Frontend (React + Vite):**
  - Learner UI, dashboard, lesson runner, quiz UI, browser terminal
  - i18n: shqip + anglisht
- **Initial track content:**
  - NIS2 Article 21 awareness (drafted)
  - Phishing recognition (drafted)
  - Secure coding (drafted)

### Planned (Phase 2 — 2027 Q2 target, v1.0.0)

- **Module 4 (Wasm Sandbox Labs):**
  - wasmtime host, pre-built lab images
  - Per-session isolation, no host filesystem access
  - Lab-image build pipeline
- **Module 5 (Certification Issuance):**
  - Per-track certification with signed completion certificates
  - Hash-anchored to CITADEL evidence
- **Module 6 (CITADEL Evidence Emitter):**
  - Async `cyberpath.completion` event emission (HMAC-SHA256 signed)
  - Schema: `docs/citadel-integration.md`
- **Module 7 (NIS2 Compass Coverage API):**
  - `GET /api/v1/cyberpath/coverage/{user_id}` — Article 21 measure
    coverage query for NIS2 Compass
  - `GET /api/v1/cyberpath/recommend?gap=<measure>` — gap-driven
    recommendation
- **Module 8 (Content Versioning):**
  - Immutable lesson revisions
  - Evidence references the exact `content_version_id` completed
- **Cross-cutting:**
  - CITADEL Kerkese schema extension with `cyberpath.completion`
    event type
  - IRFlow integration: incident → recommended track mapping
  - Integration tests against live Postgres

---

## Release roadmap

| Version | Phase | Scope | Target |
|---|---|---|---|
| **v0.0.1** (scaffold + first code) | 2 | Repo skeleton wired up; `make build` passes; `/api/v1/health` returns 200 | 2026 Q4 |
| **v1.0.0** (alpha) | 2 | Modules 1 + 2 + 3: Learning path engine, quiz engine, Docker-based labs, browser terminal. Initial 3-track content. | 2027 Q1 |
| **v0.2.0 – v0.4.0** (alpha iterations) | 2 | Track-content expansion (8 tracks complete), false-positive-free quiz banks, operator handbook | 2027 Q1 |
| **v0.5.0 – v0.9.0** (beta iterations) | 2 | Wasm lab runtime hardening, certification issuance preview, CITADEL integration preview | 2027 Q2 |
| **v1.0.0** (stable) | 2 | Modules 4 + 5 + 6 + 7 + 8: Wasm sandbox labs, certification issuance, NIS2 Article 21(2)(g) completion records to CITADEL WORM, NIS2 Compass coverage API | 2027 Q2 |
| **v1.x** | — | New tracks (post-NIS2 amendments), additional EU language coverage, hardware-isolated lab runtime evaluation | 2027 Q3 – 2028 |

## Versioning policy

- **Major** bump: breaking API change, data model migration, lab
  runtime substitution, certification format change.
- **Minor** bump: new tracks, new lab images, new endpoints, new
  integration targets, new question-bank revisions.
- **Patch** bump: bug fixes, content corrections that don't change
  scoring outcomes, documentation.

Track content additions are typically **minor** bumps. Track content
that changes scoring outcomes for already-issued certifications is a
**major** bump — a learner's evidence chain must reference an
immutable content version (see Module 8).
