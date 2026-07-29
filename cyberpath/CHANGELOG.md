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

### Security

- Certification revocation (`DELETE /api/v1/admin/certifications/{id}/revoke`)
  previously had **no CITADEL integration at all** — not even a plain
  audit-log entry — unlike issuance, which already emitted a WORM
  audit event on issue. Closed that gap:
  - Revocation now emits a `cyberpath.certification.revoked` WORM
    audit event (`internal/citadel/events.go`), through the same
    outbox path issuance's `cyberpath.certification.issued` event
    already used, plus a local audit-log entry.
  - Revocation now runs a real CITADEL MARSHAL governance evaluation
    (`POST /api/v1/marshal/evaluate`) before proceeding, using the
    authenticated admin's real identity and bearer token as `Actor`;
    a `REFUSE`/`HARD_STOP` decision blocks the request with `403` and
    the reported reasons.
  - Known, deliberate trade-offs, not defects: the governance check
    **fails open** if CITADEL/MARSHAL is unreachable (an outage does
    not block revocation — it proceeds without a governance record
    for that call; the WORM audit event still fires unconditionally),
    and the Kerkese `Verifier` is a fixed placeholder identity
    (`cyberpath-system-verifier`, no token) since CyberPath has no
    dual-control / second-approver concept to bind a real verifier
    to. See [docs/citadel-integration.md](docs/citadel-integration.md)
    for the full detail.

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

### Delivered (Phase 2, folded into [1.0.0] above)

Modules 1–8 and the frontend/content items originally tracked here as
"planned" all shipped in the [1.0.0] release on 2026-05-09 — see that
entry for the authoritative list. This section is kept only as a
historical record of what was scoped for delivery; nothing below is
still outstanding:

- Module 1 (Learning Path Engine), Module 2 (Quiz & Assessment
  Engine), Module 3 (Docker-Based Labs) with the React + Vite
  frontend and bilingual (shqip + anglisht) i18n.
- Module 4 (Wasm Sandbox Labs), Module 5 (Certification Issuance),
  Module 6 (CITADEL Evidence Emitter), Module 7 (NIS2 Compass Coverage
  API), Module 8 (Content Versioning).
- All 8 initial tracks, IRFlow integration (incident → recommended
  track mapping), and integration tests against live Postgres.

---

## Release history

| Version | Scope | Shipped |
|---|---|---|
| **v1.0.0** | Modules 1–8: learning path engine, quiz engine, Docker-based labs, browser terminal, Wasm sandbox labs, certification issuance (+ governed revocation), NIS2 Article 21(2)(g) completion records to CITADEL WORM, NIS2 Compass coverage API, content versioning. | 2026-05-09 |

### Planned (v1.x — not yet started)

- New tracks (post-NIS2 amendments)
- Additional EU language coverage
- Hardware-isolated lab runtime evaluation
- Per-schema tenant isolation (see [docs/tenancy.md](docs/tenancy.md)
  — a design document; only a bare `tenant_id` column ships today)

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
