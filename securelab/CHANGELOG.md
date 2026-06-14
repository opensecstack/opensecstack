# SecureLab Changelog

All notable changes to SecureLab are documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-05-10

### Added

- Core attack simulation engine (Go 1.22, chi router, pgx, zap)
- React/TypeScript operator dashboard with MITRE ATT&CK coverage heatmap
- PostgreSQL schema for runs, scenarios, environments, detection assertions, and audit log
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

### Added

- sinauth SSO integration — authenticate via the SIN identity provider (OAuth 2.0 / OIDC, authorization_code + PKCE); web dashboard added a sinauth.ts client and /auth/callback route.

### Scaffold

- Initial platform scaffold for Phase 3.
- Root paperwork: README, SECURITY, CONTRIBUTING, CODE_OF_CONDUCT,
  LICENSE (Apache 2.0), CHANGELOG, ROADMAP, Makefile (stub),
  `docker-compose.yml` (stub), `.gitignore`.
- Documentation skeleton:
  - `docs/architecture.md` — Python + Rust topology, scenario engine,
    payload engine, integration arrows, security boundaries
  - `docs/quick-start.md` — local development setup, first scenario
    execution
  - `docs/configuration.md` — env vars, config file structure
  - `docs/api.md` — REST API overview, endpoint reference
  - `docs/deployment.md` — Docker, isolation requirements, network
    segmentation
  - `docs/scenario-authoring.md` — YAML scenario format, payload
    references, success criteria
  - `docs/mitre-attack-coverage.md` — ATT&CK technique mapping,
    coverage matrix
  - `docs/citadel-integration.md` — `securelab.simulation` event schema
    and WORM submission flow
  - `docs/operator-handbook.md` — day-2 ops, safe scenario execution,
    audit trail management
- Ecosystem registration:
  - Listed in [ECOSYSTEM.md](../ECOSYSTEM.md) as Phase 3 platform
  - Port 8087 (API) + 3007 (dashboard) reserved in
    [../docs/deployment-topology.md](../docs/deployment-topology.md)

### Planned (Phase 3 — 2027 Q4 target, v0.1.0)

- **Module 1 (Scenario Engine):**
  - PostgreSQL schema (scenarios, executions, steps, results,
    audit_log, scenario_versions)
  - Python orchestrator (`securelab/scenario_engine/`)
  - Celery task worker for async scenario execution
  - API endpoints: `GET /api/v1/scenarios`, `GET /api/v1/scenarios/{id}`,
    `POST /api/v1/scenarios`, `PUT /api/v1/scenarios/{id}`,
    `POST /api/v1/scenarios/{id}/execute`,
    `GET /api/v1/executions/{exec_id}`
- **Module 2 (Attack Library):**
  - Curated YAML attack primitives (`attack_library/`)
  - Initial coverage: T1059 (Command and Scripting Interpreter),
    T1078 (Valid Accounts), T1110 (Brute Force), T1190 (Exploit
    Public-Facing Application), T1566 (Phishing), T1071 (Application
    Layer Protocol), T1055 (Process Injection), T1036 (Masquerading)
  - `GET /api/v1/attack-library` endpoint
- **Module 3 (MITRE ATT&CK Mapper):**
  - Technique → scenario coverage matrix
  - ATT&CK Navigator layer export
  - `GET /api/v1/coverage` and `GET /api/v1/coverage/{technique_id}`
- **Dashboard (React + Vite):**
  - Scenario library browser, execution console, ATT&CK coverage
    heatmap, results viewer
- **Rust payload engine (stub):**
  - PyO3-bound crate scaffold; encoding and mutation primitives land
    at v1.0.0

### Planned (Phase 3 — 2028 Q1 target, v1.0.0)

- **Module 4 (Detection Validator):**
  - OpenScrub adapter: poll `/api/v1/alerts` for technique-tagged
    events within configurable detection window
  - APIGuard adapter: correlate request anomaly events
  - ThreatFlow adapter: correlate IOC-match events
  - Assertion engine: pass / fail / inconclusive per detection rule
  - `GET /api/v1/executions/{exec_id}/detections`
- **Module 5 (Payload Fuzzer):**
  - Rust payload engine: mutation strategies, encoding variants,
    size and character-class fuzzing
  - PyO3 bindings from scenario engine to Rust crate
  - Fuzzing campaigns: generate N variants from a base scenario,
    evaluate detection rate
- **Module 6 (CITADEL Evidence Emitter):**
  - Async `securelab.simulation` event emission (HMAC-SHA256 signed)
  - Schema: `docs/citadel-integration.md`
  - Bounded queue + circuit breaker (same pattern as other platforms)
- **Module 7 (IRFlow Integration):**
  - Push execution results and ATT&CK coverage gaps to IRFlow
  - IRFlow incident → recommended scenario mapping
- **Cross-cutting:**
  - Full integration test suite against live Postgres + Redis
  - Third-party security review (offensive tooling / isolation focus)
  - Full documentation at v1.0 standard

---

## Release roadmap

| Version | Phase | Scope | Target |
|---|---|---|---|
| **v0.0.1** (scaffold + first code) | 3 | Repo skeleton wired up; `make build` passes; `/api/v1/health` returns 200 | 2027 Q3 |
| **v0.1.0** (alpha) | 3 | Modules 1 + 2 + 3: Scenario engine, attack library, MITRE ATT&CK coverage map. Initial 8-technique coverage. | 2027 Q4 |
| **v0.2.0 – v0.4.0** (alpha iterations) | 3 | Scenario library expansion, ATT&CK sub-technique coverage, operator handbook, scenario review pipeline | 2027 Q4 |
| **v0.5.0 – v0.9.0** (beta iterations) | 3 | Detection validator integration previews, payload fuzzer hardening, CITADEL integration preview | 2028 Q1 |
| **v1.0.0** (stable) | 3 | Modules 4 + 5 + 6 + 7: Detection validation against OpenScrub + APIGuard + ThreatFlow, payload fuzzing, CITADEL WORM evidence, IRFlow integration | 2028 Q1 |
| **v1.x** | — | New scenario packs (post-NIS2 threat landscape), additional ATT&CK tactic coverage, hardware-isolated execution environment evaluation | 2028 Q2+ |

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
