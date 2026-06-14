# Contributing to SecureLab

SecureLab is the attack simulation and detection validation platform
in the opensecstack ecosystem. Contributions are welcome — especially
scenario authoring, attack library expansion, the Rust payload engine,
and detection adapter work.

> **Security notice:** SecureLab contains offensive tooling. All
> scenario and payload contributions require a mandatory security
> review before merge. Contributions that introduce new attack
> primitives or modify execution semantics will not be merged without
> sign-off from a core-security-team member. See
> [Scenario and payload contributions](#scenario-and-payload-contributions)
> below.

## Licence

SecureLab is **Apache 2.0**. Contributions are licensed under the
same terms. See [LICENSE](LICENSE).

The permissive licence is deliberate — SecureLab is designed to be
embeddable in proprietary red-team pipelines and SOC workflows.
It does not grant authorisation to use contributed scenarios or
payloads against systems you do not own.

## Development setup

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

# Copy the example env (lands with v0.0.1)
cp .env.example .env

# Create and activate Python virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate       # Windows

# Install Python dependencies
pip install -e ".[dev]"

# Build the Rust payload engine
cargo build -p payload-engine

# Start the integration test stack
docker compose -f docker-compose.test.yml up -d postgres redis

# Build + run unit tests
make build
make test
```

## Required tools

- Python 3.12+
- Rust 1.77+ (for the payload engine)
- Docker + Docker Compose
- `ruff` (linting + formatting for Python)
- `mypy` (type checking, strict mode)
- `cargo clippy` and `rustfmt` (Rust)
- `uv` (recommended for dependency management)

## Code style

- **Python:** `ruff format` + `ruff check`, enforced via pre-commit
  hook. `mypy --strict` required for all new modules. No `Any` without
  a justifying comment.
- **Rust:** `rustfmt` + `clippy` at `deny(warnings)` level. `deny(unsafe_code)`
  in payload-engine by default; unsafe blocks require explicit
  maintainer sign-off in the PR description.
- **TypeScript / React:** `prettier` + `eslint`, strict TS
  (`noImplicitAny`, `strict: true`).
- **YAML (scenarios, attack library):** validated against the
  published JSON Schema (`schemas/scenario.schema.json`,
  `schemas/attack-primitive.schema.json`).
- **Comments:** focus on *why*, not *what*. Especially for anything
  that touches payload generation or scenario execution logic.

## Module structure (post-v0.0.1)

SecureLab has 7 logical modules across two releases. Each module has:

- `securelab/<module>/` — Python package
- `web/src/<module>/` — React UI surface (where applicable)
- `payload-engine/src/<module>/` — Rust code (payload engine only)
- `docs/<module>.md` — module-specific docs

### v0.1.0 modules (Phase 3 first cut)

- **Module 1: Scenario Engine** — `securelab/scenario_engine/`,
  `web/src/scenarios/`, `docs/scenario-authoring.md`
- **Module 2: Attack Library** — `securelab/attack_library/`,
  `attack_library/*.yaml`
- **Module 3: MITRE ATT&CK Mapper** — `securelab/mitre_mapper/`,
  `web/src/coverage/`, `docs/mitre-attack-coverage.md`

### v1.0.0 modules

- **Module 4: Detection Validator** — `securelab/detection_validator/`,
  `web/src/detections/`
- **Module 5: Payload Fuzzer** — `securelab/payload_fuzzer/`,
  `payload-engine/` (Rust)
- **Module 6: CITADEL Evidence Emitter** — `securelab/citadel_emitter/`,
  `docs/citadel-integration.md`
- **Module 7: IRFlow Integration** — `securelab/irflow_adapter/`

---

## Scenario and payload contributions

> **This section is mandatory reading for all scenario and attack
> library contributors. Contributions in this category will be
> rejected without security review sign-off.**

Scenario and attack primitive contributions are the largest —
and the most security-sensitive — contribution surface in SecureLab.
A poorly authored scenario can execute destructive payloads against
out-of-scope systems; a malicious scenario PR is a supply-chain
attack against every operator who runs SecureLab.

### What counts as a scenario / payload contribution

Any PR that creates or modifies:

- `scenarios/*.yaml` — scenario definitions
- `attack_library/*.yaml` — attack primitive definitions
- `payload-engine/src/` — Rust payload generation code
- `securelab/payload_fuzzer/` — Python fuzzer orchestration
- `schemas/scenario.schema.json` — the scenario format itself
- `schemas/attack-primitive.schema.json` — the primitive format

### Mandatory security review checklist

Before a scenario or payload contribution is reviewed, the author
must complete and check off every item in the PR description:

**Scenario safety:**
- [ ] `target_scope` field is present and restricted to the minimum
      necessary scope (no `0.0.0.0/0` or `*`)
- [ ] Every step has a documented `impact` field describing what
      the step does to the target
- [ ] Steps with destructive potential (file write, process kill,
      registry modification) are flagged with `destructive: true`
- [ ] The scenario has a documented `rollback` procedure for every
      destructive step
- [ ] The scenario does not contain hardcoded credentials, internal
      hostnames, or infrastructure references from any specific
      organisation
- [ ] The scenario has been test-executed in dry-run mode with no
      errors

**Attack library primitives:**
- [ ] The primitive does not reference a live C2 server, external
      download URL, or third-party infrastructure
- [ ] The primitive's payload content is self-contained or references
      only local resources within the scenario scope
- [ ] The `mitre_technique` and `mitre_sub_technique` fields are
      accurate and verified against the current ATT&CK matrix
- [ ] The primitive has at least one associated detection assertion
      in `expected_detections` so the detection validator can assert
      coverage

**Payload engine (Rust):**
- [ ] Unsafe blocks (if any) are justified in the PR description
- [ ] New encoding or mutation strategies are covered by unit tests
- [ ] Fuzzing inputs are bounded; the engine cannot generate
      unbounded-size payloads
- [ ] `cargo clippy` passes at `deny(warnings)` level

**Security review sign-off:**
- [ ] PR has been reviewed by at least one core-security-team member
      (label: `security-review`)
- [ ] For new ATT&CK technique coverage: the technique mapping is
      verified against ATT&CK v15+ matrix
- [ ] For primitives with destructive capability: a second
      core-security-team member has reviewed (two-person rule)

Scenarios merged without this checklist complete will be reverted.

---

## Testing

| Command | Scope |
|---|---|
| `make test` | Unit tests only — fast, no Docker/Redis |
| `make test-integration` | Full suite including HTTP E2E against live Postgres + Redis |
| `make test-scenarios` | Scenario YAML schema validation + dry-run execution |
| `make test-rust` | Rust payload engine unit + integration tests |
| `make lint` | `ruff check`, `mypy --strict`, `cargo clippy`, `eslint` |

Key conventions:

- Integration tests use a dedicated test schema; `make test-integration`
  provisions and tears down the schema automatically.
- `make test-scenarios` runs every scenario in the library in dry-run
  mode. A scenario that fails dry-run cannot be merged.
- Rust tests are run with `--release` to catch optimisation-dependent
  behaviour in the payload engine.

## Commit message format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(scenario-engine): add rollback step execution on failure

Executes rollback steps in reverse order on scenario failure so
destructive scenarios leave targets in a known clean state.
See securelab/scenario_engine/executor.py.

Closes #17
```

Common scopes: `scenario-engine`, `attack-library`, `mitre-mapper`,
`detection-validator`, `payload-fuzzer`, `payload-engine`,
`citadel-emitter`, `irflow`, `api`, `web`, `db`.

## Pull request checklist

- [ ] `make test` and `make lint` pass locally.
- [ ] `make test-integration` passes (or explain why not affected).
- [ ] CHANGELOG.md `[Unreleased]` section updated.
- [ ] ADR filed under `../adrs/` if a new decision surface is
      introduced.
- [ ] Scenario / payload contributions: full security review
      checklist completed (see above).
- [ ] Detection adapter changes: tested against the adapter's
      platform in a non-production environment.
- [ ] CITADEL integration changes: schema compatibility verified
      against current `securelab.simulation` event spec.

## Security-sensitive paths

These paths require security-team review (label: `security-review`):

- `scenarios/` — scenario YAML definitions
- `attack_library/` — attack primitive YAML definitions
- `payload-engine/src/` — Rust payload generation
- `securelab/payload_fuzzer/` — fuzzer orchestration
- `securelab/citadel_emitter/` — evidence emitter
- `securelab/detection_validator/` — detection adapters
- `schemas/` — scenario and primitive format schemas
- `SECURITY.md`
- `docs/deployment.md`

Any PR touching these paths is automatically assigned to the security
team for review, regardless of the change size.

## Reporting security issues

Never open a public issue for a SecureLab vulnerability. This is
especially true for:

- Isolation bypasses (scenarios reaching out-of-scope hosts)
- Payload engine bugs that could allow host compromise
- API authentication bypasses
- Attack library content that constitutes an unannounced malicious payload

See [SECURITY.md](SECURITY.md) for the disclosure channels.

## Code of conduct

We follow the [Contributor Covenant](CODE_OF_CONDUCT.md).

## Release flow

SecureLab follows the ecosystem release process. See
[../docs/release-process.md](../docs/release-process.md).

Versions follow semver:

- `securelab/v0.0.1` — scaffold + skeleton code
- `securelab/v0.1.0` — alpha (Modules 1, 2, 3)
- `securelab/v1.0.0` — stable, detection validation + payload fuzzing

## Related

- Root [CONTRIBUTING.md](../CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md) — threat model and access control
- [docs/scenario-authoring.md](docs/scenario-authoring.md)
