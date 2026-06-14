# SecureLab

**Attack Simulation + Detection Validation Platform**

SecureLab is an open-source platform for running controlled attack simulations against isolated test environments and validating that your detection stack (OpenScrub, APIGuard, ThreatFlow) actually catches them. It provides a library of YAML-defined attack scenarios mapped to MITRE ATT&CK, a Go-based execution engine, a React dashboard, and a CI-friendly test runner.

---

> [!WARNING]
> **SAFETY NOTICE**: SecureLab must only be used against explicitly authorized test environments. All attack modules run exclusively inside isolated Docker networks with `--internal` flag. Never point SecureLab at production systems. Running attacks against unauthorized systems is illegal and unethical. See [docs/safety-controls.md](docs/safety-controls.md) for full safety documentation.

---

## Features

- YAML scenario library mapped to MITRE ATT&CK techniques
- Isolated Docker test environments (never touches production)
- Detection validation against OpenScrub, APIGuard, and ThreatFlow
- MITRE ATT&CK coverage reports and gap analysis
- CITADEL event emission on run completion (`securelab.run_completed`)
- React + TypeScript dashboard with run history and coverage heatmap
- CI-ready scenario validation and execution

## Quick Start

```bash
# 1. Clone the repo
git clone https://github.com/opensecstack/securelab.git
cd securelab

# 2. Copy and configure environment variables
cp .env.example .env
# Edit .env — set SECURELAB_DB_URL, SECURELAB_JWT_SECRET, etc.

# 3. Start all services
docker compose up -d

# 4. Access the web UI
open http://localhost:3000

# 5. Run your first scenario
curl -X POST http://localhost:8080/api/v1/runs \
  -H "Authorization: Bearer <your-jwt>" \
  -H "Content-Type: application/json" \
  -d '{"scenario": "api/bola-basic", "environment_id": "env_test_01"}'
```

## Scenario Format Overview

Scenarios are YAML files under `scenarios/`. Each scenario defines:

```yaml
name: bola-basic
description: "BOLA via sequential integer ID enumeration on REST objects"
mitre_technique_ids: ["T1078"]
tags: [api, owasp-a1, bola]
severity: high
timeout: 3m
steps:
  - kind: bola
    params:
      endpoint: /api/v1/users/{id}
      id_range: [1, 100]
      auth_token_param: low_privilege_jwt
```

See [docs/scenario-spec.md](docs/scenario-spec.md) for the full specification and [docs/attack-library.md](docs/attack-library.md) for all built-in attack types.

## Documentation

| Document | Description |
|---|---|
| [docs/quick-start.md](docs/quick-start.md) | Detailed setup guide |
| [docs/architecture.md](docs/architecture.md) | System architecture |
| [docs/scenario-spec.md](docs/scenario-spec.md) | YAML scenario specification |
| [docs/attack-library.md](docs/attack-library.md) | All 15 built-in attack types |
| [docs/detection-validation.md](docs/detection-validation.md) | How detection validation works |
| [docs/safety-controls.md](docs/safety-controls.md) | Safety controls (read this first) |
| [docs/mitre-attack-mapping.md](docs/mitre-attack-mapping.md) | MITRE ATT&CK coverage map |
| [docs/configuration.md](docs/configuration.md) | All configuration options |
| [docs/api.md](docs/api.md) | REST API reference |
| [docs/citadel-integration.md](docs/citadel-integration.md) | CITADEL event integration |
| [docs/nis2-mapping.md](docs/nis2-mapping.md) | NIS2 compliance support |

## Integration Validation Guides

- [OpenScrub Validation](docs/openscrub-validation.md)
- [APIGuard Validation](docs/apiguard-validation.md)
- [ThreatFlow Validation](docs/threatflow-validation.md)

## License

AGPL-3.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome — especially new attack scenarios.

---

<!-- Legacy scaffold notice retained below for ecosystem context -->

> **Status (ecosystem):** Phase 3 platform in the opensecstack ecosystem.
> Active code starts at v0.0.1; this commit is paperwork only.
>
> **ACCESS CONTROL WARNING:** SecureLab contains offensive tooling —
> attack scenarios, payload libraries, and exploitation primitives.
> It must be deployed in an isolated network segment, accessible only
> to authorised red-team and security operations personnel. See
> [SECURITY.md](SECURITY.md) and [docs/deployment.md](docs/deployment.md)
> for mandatory isolation requirements before running any scenario.
>
> See the ecosystem-wide [ROADMAP.md § Phase 3](../ROADMAP.md) for the
> delivery timeline.

![Build](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Phase](https://img.shields.io/badge/phase-3-orange)
![Version](https://img.shields.io/badge/version-v1.0.0-brightgreen)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![Rust](https://img.shields.io/badge/rust-1.77%2B-orange)

SecureLab is the attack simulation and detection validation platform
in the opensecstack (SIN) ecosystem. It exists to answer a single
operational question: **do your deployed defences actually detect the
attacks they are supposed to detect?**

Existing SIEM deployments and detection stacks are configured against
threat models written at rule-creation time. Environments drift.
Configurations change. Rules that passed a smoke test in 2025 may
silently fail to fire against a 2027 variant of the same technique.
SecureLab closes this gap by running controlled, MITRE ATT&CK-mapped
attack scenarios inside your environment and validating detection
outcomes against OpenScrub, APIGuard, and ThreatFlow in real time.

## Module overview

SecureLab ships as a single platform with the following logical
modules across two releases:

| # | Module | Purpose | Release | Status |
|:-:|---|---|:-:|---|
| 1 | **Scenario Engine** | Author, version, and execute multi-step attack scenarios | v1.0.0 | Implemented |
| 2 | **Attack Library** | Curated, tagged attack primitives referenced by scenarios | v1.0.0 | Implemented |
| 3 | **MITRE ATT&CK Mapper** | Map scenarios to ATT&CK techniques / sub-techniques; coverage matrix | v1.0.0 | Implemented |
| 4 | **Detection Validator** | Assert detection events fired in OpenScrub, APIGuard, ThreatFlow within expected window | v1.0.0 | Implemented |
| 5 | **Payload Fuzzer** | Generate payload variants from a base scenario to stress-test detection rule boundaries | v1.0.0 | Implemented |
| 6 | **CITADEL Evidence Emitter** | Emit `securelab.simulation` events to CITADEL WORM for immutable audit trail | v1.0.0 | Implemented |
| 7 | **IRFlow Integration** | Push simulation results and coverage gaps to IRFlow for incident-response correlation | v1.0.0 | Implemented |

## Why SecureLab exists

- **Detections degrade silently.** Log pipelines change, field names
  are renamed, parsers are patched. A detection that matched in 2025
  can fail with zero alert in 2027 without anyone noticing.
- **ATT&CK coverage is asserted, not measured.** Most organisations
  claim MITRE ATT&CK coverage based on which rules exist, not on
  whether those rules fire when the technique is executed.
- **Purple-team exercises are expensive and infrequent.** SecureLab
  makes controlled scenario execution a continuous, automated
  practice rather than an annual event.
- **Detection gaps must be audit-traceable.** Regulators increasingly
  ask not "do you have detections?" but "show me the immutable record
  of when you last validated them." SecureLab emits evidence to the
  CITADEL WORM ledger.

SecureLab is the complement to CyberPath (training), IRFlow
(incident response), and ThreatFlow (threat intelligence) — it closes
the loop by proving that what you have deployed catches what you
trained against and investigated.

## Quick start (v0.0.1 preview — once code lands)

> **Warning:** Never run SecureLab against a production environment
> without explicit authorisation and a tested rollback plan. Read
> [docs/deployment.md](docs/deployment.md) and
> [docs/operator-handbook.md](docs/operator-handbook.md) before
> executing any scenario.

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

cp .env.example .env
# Edit .env — set isolation network, target integration endpoints

docker compose up -d

# Health check
curl http://localhost:8087/api/v1/health

# List available scenarios
curl http://localhost:8087/api/v1/scenarios

# Fire a scenario (dry-run — no payloads sent, plan only)
curl -X POST http://localhost:8087/api/v1/scenarios/T1059.001-powershell-exec/execute \
     -H "Content-Type: application/json" \
     -d '{"dry_run": true}'
```

Full deployment guide: [docs/deployment.md](docs/deployment.md).
Scenario authoring: [docs/scenario-authoring.md](docs/scenario-authoring.md).

## Architecture at a glance

```
                   ┌─────────────────────────────────┐
                   │  SecureLab Dashboard (React)     │
                   │  :3007                           │
                   │  • scenario library              │
                   │  • execution console             │
                   │  • ATT&CK coverage heatmap       │
                   │  • detection validation results  │
                   └─────────────┬───────────────────┘
                                 │ HTTPS
                                 ▼
                   ┌─────────────────────────────────┐
                   │  SecureLab API (Python)  :8087  │
                   │  ─────────────────────────────  │
                   │  FastAPI · SQLAlchemy ·          │
                   │  Celery · structlog ·            │
                   │  prometheus-client               │
                   │                                  │
                   │  scenario_engine/   (Module 1)  │
                   │  attack_library/    (Module 2)  │
                   │  mitre_mapper/      (Module 3)  │
                   │  detection_validator/(Module 4) │
                   │  payload_fuzzer/    (Module 5)  │
                   │  citadel_emitter/   (Module 6)  │
                   │  irflow_adapter/    (Module 7)  │
                   └──────────┬──────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
   ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
   │  Payload     │  │  PostgreSQL  │  │  Integrations    │
   │  Engine      │  │  (state,     │  │                  │
   │  (Rust)      │  │   results,   │  │  → CITADEL WORM  │
   │              │  │   audit log) │  │  → OpenScrub     │
   │  • fuzzing   │  │              │  │  → APIGuard      │
   │  • mutation  │  │              │  │  → ThreatFlow    │
   │  • encoding  │  │              │  │  → IRFlow        │
   └──────────────┘  └──────────────┘  └──────────────────┘
```

- **Python (FastAPI + Celery):** API server, scenario engine,
  orchestration, integration adapters, MITRE mapping, detection
  validation. Async task execution via Celery + Redis.
- **Rust:** Payload engine — high-performance payload generation,
  mutation, fuzzing, and encoding. Called from Python via PyO3
  bindings.
- **React + TypeScript + Vite:** Operator dashboard, ATT&CK coverage
  heatmap, execution console, results viewer.

Full architecture: [docs/architecture.md](docs/architecture.md).

## Endpoints (planned)

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness + DB ping |
| `GET` | `/api/v1/scenarios` | List scenarios |
| `GET` | `/api/v1/scenarios/{id}` | Scenario detail + ATT&CK mapping |
| `POST` | `/api/v1/scenarios` | Create scenario |
| `PUT` | `/api/v1/scenarios/{id}` | Update scenario |
| `DELETE` | `/api/v1/scenarios/{id}` | Delete scenario |
| `POST` | `/api/v1/scenarios/{id}/execute` | Execute scenario (dry-run or live) |
| `GET` | `/api/v1/executions/{exec_id}` | Execution status + result |
| `GET` | `/api/v1/executions/{exec_id}/detections` | Detection events captured |
| `GET` | `/api/v1/coverage` | ATT&CK technique coverage matrix |
| `GET` | `/api/v1/coverage/{technique_id}` | Coverage detail for one technique |
| `GET` | `/api/v1/attack-library` | List attack primitives |

Full API reference: [docs/api.md](docs/api.md).

## Configuration

Minimum required env vars (v0.1.0 target):

```bash
SECURELAB_DB_URL=postgres://...
SECURELAB_REDIS_URL=redis://...
SECURELAB_CITADEL_API_URL=https://citadel.internal
SECURELAB_CITADEL_KEY_SECRET=<hmac secret>
SECURELAB_OPENSCRUB_API_URL=https://openscrub.internal
SECURELAB_APIGUARD_API_URL=https://apiguard.internal
SECURELAB_THREATFLOW_API_URL=https://threatflow.internal
SECURELAB_IRFLOW_API_URL=https://irflow.internal
SECURELAB_ISOLATION_MODE=strict   # strict | permissive
```

Full configuration reference: [docs/configuration.md](docs/configuration.md).

## Authentication

SecureLab authenticates web dashboard users via **sinauth** SSO, the
SIN ecosystem identity provider. Authentication uses OAuth 2.0 / OIDC
with the `authorization_code` + PKCE (S256) flow; the dashboard's
`sinauth.ts` client handles the popup login and `/auth/callback` route.
The API validates RS256-signed tokens against the sinauth JWKS endpoint
(`https://auth.sin.to/.well-known/jwks.json`). See the
[SecureLab sinauth integration guide](../sinauth/docs/integration/securelab.md).

## License

Apache 2.0. SecureLab is a tool platform — embeddable in proprietary
red-team pipelines and security operations centres. The permissive
licence is deliberate and matches APIGuard, ThreatFlow, OpenScrub,
CyberPath. See [LICENSE](LICENSE).

**Note:** The Apache 2.0 licence grants you broad rights to use,
modify, and distribute SecureLab. It does not grant authorisation to
use SecureLab against systems you do not own or have explicit written
permission to test. Operators are solely responsible for ensuring
legal and ethical use.

## Development status

- **Phase 3 v0.1.0 planned** (2027 Q4): Modules 1, 2, 3 — Scenario
  engine, attack library, MITRE ATT&CK coverage map.
- **Phase 3 v1.0.0 planned** (2028 Q1): Modules 4, 5, 6, 7 —
  Detection validation against OpenScrub + APIGuard + ThreatFlow,
  payload fuzzing, CITADEL evidence emission, IRFlow integration.

See [ROADMAP.md](ROADMAP.md) for the detailed timeline.

## Contributing

SecureLab is greenfield — pre-v0.0.1 as of scaffold date. Early
contributors have outsized influence on the scenario format, the
payload engine design, and the ATT&CK mapping schema.

**Scenario and payload contributions require a security review before
merge.** See [CONTRIBUTING.md](CONTRIBUTING.md) for the full review
checklist.

Specifically open for claim once v0.0.1 lands:

- **Scenario authoring** (initial ATT&CK technique coverage — T1059,
  T1078, T1110, T1190, T1566, T1071, T1055, T1036)
- **Payload engine** (Rust crate: mutation, encoding, fuzzing)
- **ATT&CK mapper** (technique → scenario coverage matrix)
- **Detection validator** (OpenScrub + APIGuard + ThreatFlow adapters)

## Related

- [ECOSYSTEM.md](../ECOSYSTEM.md) — full ecosystem overview
- [ROADMAP.md](../ROADMAP.md) — ecosystem-wide roadmap (Phase 3 entries)
- [docs/deployment-topology.md](../docs/deployment-topology.md) — ports, network segments
- [docs/architecture.md](docs/architecture.md)
- [docs/quick-start.md](docs/quick-start.md)
- [docs/scenario-authoring.md](docs/scenario-authoring.md)
- [docs/mitre-attack-coverage.md](docs/mitre-attack-coverage.md)
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [docs/operator-handbook.md](docs/operator-handbook.md)
- [SECURITY.md](SECURITY.md) — vulnerability reporting + threat model
- [CHANGELOG.md](CHANGELOG.md)

## Security

SecureLab ships a public security policy ([SECURITY.md](SECURITY.md)).
SecureLab contains offensive tooling and must be deployed in a
strictly isolated network segment. Unauthorised access to a SecureLab
instance must be treated as a critical security incident. See
SECURITY.md for the full threat model, access control requirements,
and responsible disclosure terms.
