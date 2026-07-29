# SecureLab Roadmap

> Public roadmap for SecureLab — the attack simulation and detection
> validation platform in the opensecstack (SIN) ecosystem. v1.0.0
> shipped 2026-05-10 as a Go 1.22 API + React/TypeScript dashboard,
> with a standalone Rust payload-generation crate.
>
> This roadmap complements the ecosystem-wide
> [ROADMAP.md](../ROADMAP.md).

## Guiding principles

1. **Simulate to validate, not to demonstrate.** Every scenario
   execution produces a pass/fail-style verdict (`detected` /
   detection latency) against deployed detections.
2. **ATT&CK coverage is measured, not claimed.** The `mitre_coverage`
   table and `GET /api/v1/coverage` endpoint report coverage; today
   that table is not populated automatically by run completion — see
   [docs/mitre-attack-coverage.md](docs/mitre-attack-coverage.md).
3. **Isolation is non-negotiable.** SecureLab contains offensive
   tooling. Every deployment configuration must enforce network
   segmentation. There is no "permissive mode" that removes isolation
   controls — there is only "misconfigured." See
   [docs/deployment.md](docs/deployment.md).
4. **Simulation evidence should be audit-grade.** Every completed run
   can be sealed into the CITADEL WORM ledger via the
   `securelab.run_completed` event. Today this is a single
   best-effort, non-fatal POST per run (no retry queue, no
   evidence-hash field) — see
   [docs/citadel-integration.md](docs/citadel-integration.md) for the
   current limits, and § Near-term below for where this is headed.
5. **Go for the API, Rust for payload primitives.** The API,
   scenario engine, and attack modules are Go. Payload generation and
   byte-mutation fuzzing are being built as a separate, memory-safe
   Rust crate (`rust/payload-gen`) to keep untrusted-input-adjacent
   code out of the API's own memory space, even though it is not yet
   called from the live request path.

## Shipped — v1.0.0 (2026-05-10)

See [CHANGELOG.md](CHANGELOG.md) for the full list. Highlights:

- Go 1.22 attack simulation engine (chi router, pgx, zap)
- React/TypeScript operator dashboard with MITRE ATT&CK coverage
  heatmap
- PostgreSQL schema: `scenarios`, `environments`, `scenario_runs`,
  `mitre_coverage`
- YAML scenario format (`docs/scenario-spec.md`)
- 15 built-in attack types across API, network, and recon categories,
  implemented natively in Go under `internal/attacks/`
- Detection polling against OpenScrub, APIGuard, and ThreatFlow
  (`internal/detection/`)
- CITADEL integration: `securelab.run_completed` events, HMAC-SHA256
  signed, POSTed to CITADEL's `/api/v1/worm/emit`
- Isolated Docker test environments (`--internal` network) for attack
  targets
- Target safety validation: refuses to run against hostnames matching
  a built-in production blocklist (`internal/scenarios/validator.go`)
- Standalone Rust payload-generation crate (`rust/payload-gen`) —
  BOLA/JWT/mass-assignment payload generation and byte-mutation
  fuzzing, unit-tested, not yet linked into the Go API
- CI pipeline: Go tests, vet, lint, frontend build, scenario YAML
  validation, Cargo check; release pipeline builds multi-arch Docker
  images, pushes to GHCR, and cuts a GitHub release
- sinauth SSO integration (OAuth 2.0 / OIDC, authorization_code + PKCE)

## Known gaps in the current v1.0.0 (tracked, not yet scheduled)

These are real limitations in the shipped implementation, not planned
features with dates — see [README.md § Future / Not Yet Implemented](README.md)
and [docs/operator-handbook.md § Future / Not Yet Implemented](docs/operator-handbook.md)
for the authoritative, currently-accurate list:

- **Rust payload-gen not wired into the API.** `internal/attacks/`
  still generates its own payloads natively in Go.
- **`mitre_coverage` is not populated automatically.** Nothing in the
  run-completion path writes to that table yet; coverage numbers are
  only as fresh as the last manual/administrative update.
- **No dedicated audit-log table.** `scenarios`, `environments`, and
  `scenario_runs` are the only queryable record of activity.
- **No CITADEL retry queue or circuit breaker.** A failed emit is
  logged once and dropped; the next completed run tries again
  independently.
- **No IRFlow integration.** Simulation results and ATT&CK coverage
  gaps are not currently pushed to IRFlow for incident-response
  correlation.
- **No `/metrics` endpoint and no token-revocation API.**

## Near-term direction

Reasonable next steps, in rough priority order, contingent on
contributor bandwidth — none of these have committed dates:

- Wire `rust/payload-gen` into the live attack-module request path,
  replacing the native-Go payload generation in `internal/attacks/`
  where it overlaps.
- Populate `mitre_coverage` automatically from run completion instead
  of requiring manual updates.
- Add a CITADEL emission retry queue (bounded, with backoff) and a
  manual re-emit path for runs whose emission failed.
- IRFlow integration: push simulation results and ATT&CK coverage
  gaps for incident-response correlation.
- Evaluate a dedicated append-only audit-log table for
  `scenarios`/`environments`/`scenario_runs` mutations.

## Longer-term direction

Directional, not committed:

- New scenario packs aligned with evolving MITRE ATT&CK technique
  additions and post-NIS2 threat-landscape updates
- Cloud-specific attack scenario packs (AWS, Azure, GCP) as ecosystem
  cloud posture tooling matures
- Adversary emulation profiles: chain multiple scenarios into a
  kill-chain campaign (aligned with APT simulation)
- CyberPath cross-platform integration: detection-validation results
  drive training-track recommendations (gap → track → evidence)
- Federated scenario sharing across CSIRT-network members
- Continuous validation mode: scheduled re-execution of scenarios with
  drift alerting (a detection that was passing begins to fail)

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
  ThreatFlow's detection surface to drive detection validation, not to
  produce threat intelligence.
- **Not a SIEM replacement.** SecureLab validates that your detection
  stack fires as expected. It does not replace the SIEM.

## Call for contributions

- **Scenario authoring** — new YAML scenarios under `scenarios/` for
  broader ATT&CK technique coverage
- **Wiring `rust/payload-gen` into the API** — the crate is
  feature-complete and tested; the integration work is what's missing
- **Detection adapters** — extending `internal/detection` beyond
  OpenScrub, APIGuard, and ThreatFlow
- **`mitre_coverage` automation** — populating the coverage table from
  run completion

Open an issue with label `claim-module` or `good-first-issue`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

> **Note for scenario contributors:** all scenarios and attack
> primitives require a security review before merge. See
> [CONTRIBUTING.md § Mandatory security review checklist](CONTRIBUTING.md)
> for the mandatory checklist.

## Related

- [../ROADMAP.md](../ROADMAP.md) — ecosystem-wide roadmap
- [CHANGELOG.md](CHANGELOG.md) — what has actually shipped
- [docs/architecture.md](docs/architecture.md) — detailed architecture
- [docs/mitre-attack-coverage.md](docs/mitre-attack-coverage.md)
- [docs/citadel-integration.md](docs/citadel-integration.md)
- [SECURITY.md](SECURITY.md) — threat model and access control policy
