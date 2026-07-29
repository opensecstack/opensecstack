# SecureLab Changelog

All notable changes to SecureLab are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-05-10

### Added

- Core attack simulation engine (Go 1.22, chi router, pgx, zap)
- React/TypeScript operator dashboard with MITRE ATT&CK coverage heatmap
- PostgreSQL schema for scenarios, environments, scenario runs, and MITRE ATT&CK coverage
- YAML scenario format with full spec at `docs/scenario-spec.md`
- 15 built-in attack types across API, network, and recon categories
- BOLA (sequential integer ID enumeration and UUID brute force)
- JWT `alg:none` bypass and weak secret brute force attacks
- Mass assignment role escalation attack
- SSRF to AWS metadata endpoint (`169.254.169.254`)
- Rate limit bypass via IP rotation headers
- SYN flood (100k PPS), UDP amplification, HTTP flood, and Slowloris attacks
- TCP port scan (ports 1–1024) and API endpoint enumeration
- Multi-stage APT simulation scenario (recon → auth bypass → BOLA → exfil)
- Full kill chain scenario (recon → initial access → lateral movement → exfil)
- CITADEL integration: emits `securelab.run_completed` events (HMAC-SHA256 signed)
- Detection validation against OpenScrub, APIGuard, and ThreatFlow
- MITRE ATT&CK coverage matrix with gap reporting
- Isolated Docker test environments (`--internal` network, never touches production)
- Target safety validation: blocks URLs matching production/prod keywords
- Rust payload generator crate (`rust/payload-gen`) with BOLA, JWT, mass-assignment, fuzzer, and encoder modules
- CI pipeline: Go tests, vet, lint, frontend build, scenario YAML validation, Cargo check
- Release pipeline: multi-arch Docker images (linux/amd64 + linux/arm64), GHCR push, GitHub release
- ADRs: YAML scenario format, isolated Docker networks, MITRE ATT&CK as framework
- Full documentation: architecture, quick-start, scenario spec, attack library, detection validation, safety controls, MITRE mapping, environment setup, NIS2 mapping, API reference, CITADEL integration, integration validation guides

## [Unreleased]

### Fixed

- CITADEL emit was silently failing on every run: `EmitRunCompleted` posted to `/api/v1/events`, a route CITADEL never exposed. It now POSTs to `/api/v1/worm/emit` wrapped in the `emitRequest` envelope (`source`, `event_type`, `project_id`, `payload`) CITADEL's WORM handler expects, with the HMAC-SHA256 signature computed over the full envelope body. See `docs/citadel-integration.md`.

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

## Versioning policy

- **Major** bump: breaking API change, data model migration, scenario
  format change that requires migration of existing scenarios, payload
  engine ABI change.
- **Minor** bump: new scenarios, new attack primitives, new ATT&CK
  technique coverage, new integration targets, new detection adapters.
- **Patch** bump: bug fixes, scenario corrections that do not change
  execution semantics, documentation updates.

Scenario additions are typically **minor** bumps. A scenario change
that alters execution semantics for already-recorded simulation
evidence is a **major** bump — simulation results must reference an
immutable scenario version (each scenario version is content-hashed
and stored at execution time).
