# SecureLab Roadmap

> Public roadmap for SecureLab — the attack simulation and detection
> validation platform in the opensecstack (SIN) ecosystem. Phase 3
> delivery across 2027 Q3 – 2028 Q1.
>
> This roadmap complements the ecosystem-wide
> [ROADMAP.md § Phase 3](../ROADMAP.md).

## Guiding principles

1. **Simulate to validate, not to demonstrate.** Every scenario
   execution produces a pass/fail verdict against deployed detections.
   A scenario that runs without a detection assertion is incomplete.
2. **ATT&CK coverage is measured, not claimed.** Coverage is computed
   from execution results, not from the existence of scenarios in the
   library. An untested scenario does not count as coverage.
3. **Isolation is non-negotiable.** SecureLab contains offensive
   tooling. Every deployment configuration enforces network
   segmentation. There is no "permissive mode" that removes isolation
   controls — there is only "misconfigured."
4. **Simulation evidence is audit-grade.** Every execution is sealed
   into the CITADEL WORM ledger with an immutable reference to the
   exact scenario version executed. An auditor can reconstruct the
   simulation state from the CITADEL record.
5. **Rust for payloads.** Payload generation and mutation run in Rust
   for performance, memory safety, and to constrain the attack surface
   of the payload engine itself. Python orchestrates; Rust executes.

## Phase 3 — Scenario Engine + ATT&CK Coverage (2027 Q3 – Q4)

Python API + React dashboard only. Rust payload engine is scaffolded
but not feature-complete. Ships v0.1.0 by 2027 Q4.

### v0.0.1 (2027 Q3 target)

Repository skeleton, build pipeline wired up, health endpoint live.

| Deliverable | Module | Status |
|---|:-:|:-:|
| Scaffold + docs + LICENSE + paperwork | — | In progress |
| Python project layout (`pyproject.toml`, `uv.lock`) | — | Planned |
| FastAPI app skeleton + `/api/v1/health` | — | Planned |
| PostgreSQL schema (scenarios, executions, steps, results, audit_log) | 1 | Planned |
| Celery + Redis worker skeleton | 1 | Planned |
| Rust crate scaffold (`payload-engine/`) with PyO3 binding stub | 5 | Planned |
| Docker Compose: API + worker + Postgres + Redis | — | Planned |
| `make build` and `make test` pass | — | Planned |

### v0.1.0 (2027 Q4 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| Scenario YAML loader and validator | 1 | Planned |
| Scenario versioning (content-hash on write) | 1 | Planned |
| Scenario execution orchestrator (Celery tasks) | 1 | Planned |
| Execution state machine: queued → running → completed / failed | 1 | Planned |
| Dry-run mode (plan generation, no payloads dispatched) | 1 | Planned |
| API: full scenario CRUD + execute + execution status | 1 | Planned |
| Initial attack library: 8 ATT&CK techniques | 2 | Planned |
| Attack primitive YAML schema + validator | 2 | Planned |
| `GET /api/v1/attack-library` endpoint | 2 | Planned |
| MITRE ATT&CK technique → scenario mapping | 3 | Planned |
| Coverage matrix computation (% techniques with passing executions) | 3 | Planned |
| ATT&CK Navigator layer export (JSON) | 3 | Planned |
| `GET /api/v1/coverage` and `GET /api/v1/coverage/{technique_id}` | 3 | Planned |
| React dashboard: scenario library, execution console, coverage heatmap | — | Planned |
| Integration tests against live Postgres + Redis | — | Planned |

### Success metrics for v0.1.0

- **Time-to-v0.1.0:** ≤ 6 months from scaffold completion
- **Initial ATT&CK coverage:** ≥ 8 techniques with executable scenarios
- **Scenario execution reliability:** ≥ 99% of dry-run executions
  complete without engine error
- **Coverage matrix accuracy:** 100% deterministic (coverage
  computed from execution records, not static assertions)
- **First pilot deployment:** 2027 Q4 target

## Phase 3 — Detection Validation + Payload Fuzzing (2028 Q1)

Adds the Rust payload engine, detection validation adapters, CITADEL
evidence emission, and IRFlow integration. Ships v1.0.0 by 2028 Q1.

### v1.0.0 (2028 Q1 target)

| Deliverable | Module | Status |
|---|:-:|:-:|
| OpenScrub detection adapter | 4 | Planned |
| APIGuard detection adapter | 4 | Planned |
| ThreatFlow detection adapter | 4 | Planned |
| Detection assertion engine (pass / fail / inconclusive / timeout) | 4 | Planned |
| Configurable detection window per scenario step | 4 | Planned |
| `GET /api/v1/executions/{exec_id}/detections` | 4 | Planned |
| Rust payload engine: encoding variants (Base64, URL, hex, Unicode) | 5 | Planned |
| Rust payload engine: byte-level mutation strategies | 5 | Planned |
| Rust payload engine: size and character-class fuzzing | 5 | Planned |
| PyO3 bindings: Python ↔ Rust payload engine ABI | 5 | Planned |
| Fuzzing campaign executor: N variants from base scenario | 5 | Planned |
| Fuzzing detection rate reporting: what % of variants were caught | 5 | Planned |
| `securelab.simulation` event emission to CITADEL (HMAC-SHA256) | 6 | Planned |
| CITADEL WORM sealed execution records with scenario version ref | 6 | Planned |
| IRFlow: push execution results + ATT&CK gap summary | 7 | Planned |
| IRFlow: incident type → recommended scenario mapping | 7 | Planned |
| Dashboard: detection validation results, fuzzing reports | — | Planned |
| Scenario version immutability (content-hash lock on execute) | — | Planned |
| v1.0.0 third-party security review (offensive tooling + isolation) | — | Planned |
| Full documentation at v1.0 standard | — | Planned |

### Success metrics for v1.0.0

- **v1.0.0 ship:** 2028 Q1 or earlier
- **Detection validation coverage:** OpenScrub + APIGuard + ThreatFlow
  all wired; ≥ 80% of v0.1.0 scenarios have detection assertions
- **Payload fuzzing throughput:** ≥ 1,000 variants/min from Rust engine
- **CITADEL evidence emission success rate:** ≥ 99.9%
- **Isolation finding count at third-party review:** 0 unmitigated
  highs/criticals at release
- **ATT&CK technique coverage (v1.0.0):** ≥ 20 techniques with
  validated detection assertions

## Post-v1.0 direction (2028 Q2+)

### v1.x (2028 Q2 – 2028)

- New scenario packs aligned with post-NIS2 threat landscape updates
  and new MITRE ATT&CK technique additions
- Cloud-specific attack scenario packs (AWS, Azure, GCP) as
  ecosystem cloud posture tooling matures
- Hardware-isolated execution environment evaluation (Firecracker,
  gVisor) for scenarios requiring kernel-level simulation
- Adversary emulation profiles: chain multiple scenarios into a
  full kill-chain campaign (aligned with APT simulation)
- CyberPath cross-platform integration: detection-validation results
  drive training track recommendations (gap → track → evidence)

### v2.0 (post-NIS2 amendment cycle)

- Federated scenario sharing across CSIRT-network members
- Continuous validation mode: scheduled re-execution of scenarios
  with drift alerting (detection that was passing begins to fail)
- Post-quantum payload variants for cryptographic primitive testing
- Adaptive fuzzing: coverage-guided mutation engine (AFL-style
  feedback loop over detection event corpus)

## Non-goals

- **Not a penetration testing framework.** SecureLab executes
  controlled, pre-authored scenarios in your environment against
  your own systems. It is not a general-purpose exploit framework
  or vulnerability scanner. Metasploit is not a dependency.
- **Not a production attack tool.** SecureLab is for controlled
  simulation in isolated environments. Executing scenarios against
  uncontrolled production systems without authorisation is a misuse
  of the platform.
- **Not a CTF scoring platform.** CyberPath is the ecosystem's
  training and certification platform. SecureLab validates detections,
  not learner skills.
- **Not a threat intelligence feed.** ThreatFlow handles threat
  intelligence collection and enrichment. SecureLab consumes
  ThreatFlow outputs to drive detection validation, not to produce
  threat intelligence.
- **Not a SIEM replacement.** SecureLab validates that your SIEM
  detects what it should. It does not replace the SIEM.

## Call for contributions

SecureLab is greenfield as of scaffold date. Specifically open for
claim once v0.0.1 lands:

- **Scenario authoring** (initial 8-technique coverage pack — see
  attack library issue tracker)
- **Rust payload engine** (`payload-engine/` crate — encoding,
  mutation, fuzzing)
- **Detection adapters** (OpenScrub, APIGuard, ThreatFlow)
- **ATT&CK Navigator layer export** (joint with the MITRE mapper)
- **CITADEL `securelab.simulation` schema** (joint with the CITADEL
  team)

Open an issue with label `claim-module` or `good-first-issue`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

> **Note for scenario contributors:** all scenarios and attack
> primitives require a security review before merge. See
> [CONTRIBUTING.md § Scenario and payload contributions](CONTRIBUTING.md)
> for the mandatory checklist.

## Related

- [../ROADMAP.md § Phase 3](../ROADMAP.md) — ecosystem-wide roadmap
- [docs/architecture.md](docs/architecture.md) — detailed architecture
- [docs/scenario-authoring.md](docs/scenario-authoring.md)
- [docs/mitre-attack-coverage.md](docs/mitre-attack-coverage.md)
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [SECURITY.md](SECURITY.md) — threat model and access control policy
