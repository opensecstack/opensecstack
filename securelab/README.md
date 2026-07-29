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

Apache 2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions welcome — especially new attack scenarios.

---

## Future / Not Yet Implemented

Reasonable extensions that do **not** exist in the codebase today, so
future contributors don't reinvent or assume them:

- **IRFlow integration** — pushing simulation results and ATT&CK
  coverage gaps to IRFlow for incident-response correlation.
- **Payload fuzzing wired into the API** — `rust/payload-gen` is a
  standalone, unit-tested Rust crate with real BOLA/JWT/mass-assignment
  payload generation and byte-mutation fuzzing, but it is not yet
  called from the live Go API request path; attack modules under
  `internal/attacks/` currently generate their own payloads natively.
- **Automatic MITRE ATT&CK coverage population** — the `mitre_coverage`
  table and `GET /api/v1/coverage` endpoint are real, but nothing in
  the run-completion path writes to that table automatically yet.
- **Audit log, Prometheus metrics, CITADEL retry/re-emit tooling** —
  see [docs/operator-handbook.md](docs/operator-handbook.md) for
  details on what operational tooling is and isn't in place.

See [SECURITY.md](SECURITY.md) for the full threat model, access
control requirements, and responsible disclosure terms.
