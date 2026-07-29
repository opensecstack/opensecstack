# ADR-013: SecureLab Platform Strategy

**Status:** Accepted
**Date:** 2026-05-05
**Deciders:** core-maintainers, securelab-platform-team
**Supersedes:** —
**Related:** [ADR-012 CyberPath Platform Strategy](./ADR-012-cyberpath-platform-strategy.md), [ADR-010 VertGuard Platform Strategy](./ADR-010-vertguard-platform-strategy.md), [ROADMAP.md § Phase 3](../ROADMAP.md)

---

## Context

The opensecstack ecosystem covers a broad threat-management surface:
APIGuard scans API traffic, ThreatFlow aggregates IOCs, OpenScrub
mitigates DDoS, IRFlow orchestrates incident response, and CITADEL
preserves immutable audit evidence. **Every platform assumes its
detection logic is correct. None of them proves it.**

This is a structural gap because:

1. **Detection rules drift silently.** Firewall rules age, SIEM
   queries rot, IDS signatures miss new evasion techniques. A rule
   that fires reliably on day one may fail silently eighteen months
   later after a software upgrade, a schema change, or a network
   topology shift. Without periodic simulation-driven validation,
   operators have no automated signal that a defence has stopped
   working.
2. **NIS2 Article 21(2)(a) mandates regular testing of security
   controls.** Essential and important entities must demonstrate
   that their risk-analysis and information-security policies are
   regularly reviewed and tested — not merely documented. Auditors
   are beginning to ask for evidence that controls fire, not just
   that controls exist. A log of "we ran these attack simulations
   and these detections triggered" is precisely the evidence
   Article 21(2)(a) demands.
3. **The ecosystem already has the targets.** OpenScrub defends
   against DDoS — but does its XDP ruleset actually drop the
   attack traffic it is configured to drop? APIGuard scans API
   requests — but does its ruleset detect the malformed payloads it
   claims to catch? ThreatFlow correlates IOCs — but does a new
   indicator actually trigger an alert within the configured
   time-window? IRFlow runs playbooks — but does the playbook fire
   in the scenario it was designed for? Without a simulation layer,
   all four questions go unanswered in production.
4. **Phase 3 timing matches regulatory pressure.** First-cycle NIS2
   audits are landing across EU member states in 2027–2028.
   Operators who can present a quarterly simulation log sealed in
   CITADEL WORM have a materially stronger audit posture than those
   who cannot. SecureLab v1.0.0 targets 2028 Q1 — on the right side
   of that audit window.
5. **Existing attack-simulation tools do not integrate with the
   ecosystem's evidence chain.** MITRE Caldera and Atomic Red Team
   are capable frameworks, but they produce results that live in
   their own databases. They have no knowledge of opensecstack's
   CITADEL WORM, OpenScrub's mitigation API, APIGuard's rule
   taxonomy, or ThreatFlow's IOC schema. Bridging them would require
   maintaining external adapters for each platform-specific contract
   with no upstream incentive to keep them aligned.

Without SecureLab, the ecosystem's positioning as "the EU's sovereign
NIS2 compliance stack" is incomplete: platforms detect threats, but
no platform validates that detections actually fire.

## Decision

**Add SecureLab as the attack simulation and detection validation
platform in opensecstack**, delivered in two releases across Phase 3.

### Scope — 6 modules across 2 releases

| Module | Purpose | Language | Release |
|---|---|---|---|
| **1. Scenario Engine** | Scenario definition, scheduling, execution orchestration | Python | **v0.1.0** |
| **2. Attack Library** | Curated attack scenario catalogue with metadata | Python | **v0.1.0** |
| **3. MITRE ATT&CK Mapper** | Map scenarios to ATT&CK techniques; coverage gap reporting | Python | **v0.1.0** |
| **4. Payload Engine** | High-speed payload generation, packet crafting, protocol fuzzing | Rust | **v1.0.0** |
| **5. Detection Validator** | Fire attack → query target platform API → assert alert raised | Python | **v1.0.0** |
| **6. Integration Adapters** | Per-platform adapters: OpenScrub, APIGuard, ThreatFlow, IRFlow | Python | **v1.0.0** |

### Phased timeline

| Release | Target | Scope | Requires |
|---|---|---|---|
| **v0.0.1** (scaffold + skeleton) | 2027 Q3 | Repo skeleton; `make build`; `/api/v1/health` | Existing engineering team |
| **v0.1.0** (alpha) | 2027 Q4 | Modules 1, 2, 3 — Scenario engine, attack library, ATT&CK coverage map | Existing engineering team |
| **v1.0.0** (stable) | 2028 Q1 | Modules 4, 5, 6 — Payload engine, detection validator, platform adapters | Rust + Python engineering capacity |

### Architecture

- **Python**: HTTP API (FastAPI), scenario orchestration, attack
  library, MITRE ATT&CK mapper, detection validator, integration
  adapters, CITADEL evidence emitter. Python is the right language
  for scenario scripting: the offensive-security tooling ecosystem
  (scapy, impacket, paramiko, requests) is Python-native, making
  the attack library dramatically easier to compose and extend.
  Operator-contributed scenarios are also Python scripts, matching
  the skill-set of the security-practitioner community.
- **Rust**: Payload engine (v1.0.0+). Payload generation and
  high-speed packet crafting are performance-critical paths where
  Python's GIL and interpreter overhead are prohibitive. Rust
  provides memory-safe, zero-copy packet construction at line rates
  relevant to DDoS simulation scenarios. The Rust payload engine is
  a library crate called from Python via PyO3 bindings, keeping a
  single API surface.
- **PyO3 boundary** between Python and the Rust payload engine —
  chosen over subprocess (IPC latency), REST (overhead), or ctypes
  (unsafety at the FFI boundary).
- **PostgreSQL** schema spans: `scenarios`, `executions`,
  `results`, `detections`, `mitre_mappings`, `schedule`,
  `operators`, `audit_log`. One DB instance per platform
  (ecosystem standard).
- **MITRE ATT&CK mapper** ingests the ATT&CK STIX 2.1 bundle from
  `data/attack/enterprise-attack.json` (pinned version, SHA-256
  checked). Coverage gaps are surfaced as `GET
  /api/v1/coverage/gaps`.
- **Detection Validator** follows the pattern: (1) fire the attack
  scenario against the configured target, (2) wait for the
  configured detection window, (3) query the target platform's
  alert API, (4) assert the expected alert is present, (5) record
  PASS / FAIL + evidence payload.
- **Integrations**:
  - CITADEL — `securelab.simulation` evidence events (HMAC-SHA256
    signed, async drain queue, circuit breaker — same pattern as
    VertGuard and CyberPath CITADEL emitters). Simulation results
    are sealed into the WORM chain and are available to auditors as
    immutable evidence of control testing.
  - OpenScrub — fire DDoS simulation scenarios; assert OpenScrub
    mitigation rules activated and traffic was dropped.
  - APIGuard — replay malformed API payloads; assert APIGuard
    scanning rules triggered the correct alert class.
  - ThreatFlow — introduce known-bad IOCs into the feed; assert
    ThreatFlow correlated and alerted within the configured window.
  - IRFlow — trigger scenario conditions mapped to IR playbooks;
    assert the correct playbook fired and the correct steps
    executed.
  - CyberPath — SecureLab scenario definitions are referenced by
    CyberPath lab exercises, providing hands-on attack scenarios
    grounded in real simulation data. Read-only coupling: CyberPath
    queries `GET /api/v1/scenarios/{id}` for lab metadata.
  - opensecstack/sdk — auth, Argon2id password hashing, shared
    primitives.

### Security posture

SecureLab is itself a high-value target: a compromised SecureLab
instance could fire real attacks against production systems while
appearing to be a legitimate simulation. The following controls are
non-negotiable and must be enforced before v0.1.0 ships:

- **Air-gapped or isolated network segment.** SecureLab must not
  run on the same network segment as production workloads. The
  recommended deployment topology is a dedicated simulation VLAN
  with firewall rules that permit SecureLab egress only to
  explicitly allowlisted target platform API ports. See
  `docs/deployment-topology.md`.
- **Operator authentication before any scenario fires.** No
  scenario execution may start without a valid operator session.
  Operator accounts require MFA (TOTP minimum). The execution
  endpoint (`POST /api/v1/scenarios/{id}/execute`) requires the
  `securelab:execute` permission scope, which is not granted to
  read-only accounts.
- **All executions logged to CITADEL WORM.** Every scenario
  execution — including cancelled and failed runs — emits a
  `securelab.simulation` event to CITADEL before execution begins
  (START event) and on completion (RESULT event). The log is
  therefore tamper-evident: a gap in the sequence is detectable.
- **Attack library read-only in production.** The attack library
  is a versioned, read-only asset in production. New scenarios are
  added only via a signed release process. The `scenarios/`
  directory is checksum-verified on startup.
- **No plaintext credential storage.** Target platform API keys
  used by integration adapters are stored in an operator-provided
  secrets store (HashiCorp Vault or Kubernetes Secrets). SecureLab
  never writes credentials to its PostgreSQL database.

### Licence

**Apache 2.0** — consistent with the ecosystem's tool-platform tier
(APIGuard, ThreatFlow, OpenScrub, CyberPath). SecureLab is intended
to be embeddable in proprietary security-operations pipelines and
CI/CD validation workflows; copyleft would block that integration.
The audit-grade evidence chain is enforced by integration with
CITADEL (AGPL-licensed), not by SecureLab's own licence.

### Ports

- API: **8087** (already reserved in
  [docs/deployment-topology.md](../docs/deployment-topology.md))
- Dashboard: **3007** (already reserved)

## Alternatives considered

### Alternative A: Use MITRE Caldera

Deploy Caldera as the attack simulation engine and write a thin
opensecstack adapter that pipes results to CITADEL.

- **Rejected** because: Caldera's plugin API is unstable between
  major versions, creating an ongoing maintenance burden. Caldera
  has no native knowledge of OpenScrub's mitigation API, APIGuard's
  rule taxonomy, ThreatFlow's IOC schema, or IRFlow's playbook
  contract — each adapter would need to be maintained externally
  with no upstream incentive to keep the contracts aligned. Most
  critically, Caldera produces results in its own internal schema;
  mapping those results to CITADEL's `Kerkese` evidence format is
  lossy and non-trivial. The end result would be a fragile
  integration with an external project's release schedule, rather
  than a first-class platform designed around the ecosystem's
  contracts from day one.

### Alternative B: Use Atomic Red Team

Use the Atomic Red Team test catalogue as the attack library,
wrapping it with a Python orchestrator that emits to CITADEL.

- **Rejected** because: Atomic Red Team atomics are designed for
  Windows-endpoint adversary emulation (T1086, T1059, etc.) and
  assume agent installation on target hosts. The opensecstack
  simulation targets — OpenScrub (XDP/eBPF network), APIGuard
  (HTTP API), ThreatFlow (IOC correlation), IRFlow (playbook
  orchestration) — are network-facing services and platform APIs,
  not Windows endpoints. The Atomic Red Team model is fundamentally
  misaligned with opensecstack's target surface. Adopting it would
  require heavy adaptation of a framework designed for a different
  threat model, producing worse coverage than a purpose-built
  scenario engine.

### Alternative C: Distribute validation into each platform

Add a "validate my own rules" self-test feature to OpenScrub,
APIGuard, ThreatFlow, and IRFlow respectively, rather than building
a standalone simulation platform.

- **Rejected** because: self-testing has an inherent conflict of
  interest — a platform cannot reliably validate its own detection
  logic using the same code paths that implement it. A shared bug
  in the detection and the self-test will produce a false PASS.
  A standalone simulation platform fires external attacks and
  validates responses via the platform's public API, giving an
  independent signal. Additionally, distributed per-platform
  self-tests produce fragmented evidence; CITADEL needs a unified
  `securelab.simulation` event schema, not four heterogeneous
  self-test schemas.

### Alternative D: Defer until 2029 (post-OpenCSIRT)

Complete OpenCSIRT v1.0.0 before starting SecureLab.

- **Rejected** because: SecureLab and OpenCSIRT are both Phase 3
  platforms with parallel development tracks; SecureLab v0.1.0
  targets 2027 Q4 and OpenCSIRT v0.1.0 targets 2028 Q1 — they are
  sequential within Phase 3, not dependent on each other. Deferring
  SecureLab past 2028 would miss the first-cycle NIS2 audit window
  for EU entities who need simulation evidence in 2028.

### Chosen: Phase-3 standalone platform (Apache 2.0)

Build SecureLab as a standalone platform in Phase 3. Modules 1–3
ship in v0.1.0 with no Rust dependency (Python-only scenario engine,
attack library, and ATT&CK coverage mapper); Modules 4–6 ship in
v1.0.0 with the Rust payload engine and the full detection-validator
and adapter suite.

## Consequences

### Positive

- **Closes the detection-validation gap** that no opensecstack
  platform currently addresses: operators can now prove that
  their defences fire, not just that they exist.
- **NIS2 Article 21(2)(a) evidence, production-grade.** Simulation
  results sealed in CITADEL WORM give auditors an immutable,
  time-stamped record of control testing. The evidence chain
  (scenario definition → execution START event → attack fired →
  detection asserted → RESULT event → CITADEL seal) is
  independently verifiable.
- **MITRE ATT&CK coverage visibility.** The coverage mapper shows
  which ATT&CK techniques are exercised by the current scenario
  library and which are gaps — a direct input to prioritisation.
- **Closes the ecosystem feedback loop.** OpenScrub, APIGuard,
  ThreatFlow, and IRFlow each gain an external validation layer.
  Detection-rule regressions surface automatically rather than at
  the next real incident.
- **CyberPath enrichment.** CyberPath hands-on labs can reference
  real simulation scenarios, grounding training content in
  production-grade attack data.
- **Python scenario ecosystem.** Operators can write and contribute
  new scenarios using scapy, impacket, and the wider Python
  offensive-security tooling ecosystem, with no build toolchain
  requirements beyond `pip install`.

### Negative

- **SecureLab is itself a high-value target.** A platform capable
  of firing real attacks against production systems is attractive
  to attackers. The air-gapped deployment requirement and operator
  authentication controls (see Security posture above) are
  mitigations, not eliminations. The access-control and network
  isolation requirements must be documented clearly in
  `docs/deployment-topology.md` and enforced by the installer.
- **Strict access control burden on operators.** The requirement
  that SecureLab run in an isolated network segment and that every
  execution requires MFA authentication adds operational overhead.
  This is intentional and non-negotiable, but it increases
  the barrier to deployment for smaller teams.
- **Rust payload engine adds build complexity.** v1.0.0 introduces
  a PyO3-linked Rust crate. CI must build the Rust crate before the
  Python package is installable. Mitigated by pre-built wheels in
  the release pipeline for the supported platform matrix.
- **Attack library curation is ongoing work.** Scenarios must be
  reviewed for accuracy, safety, and alignment with ATT&CK before
  inclusion. An outdated or incorrect scenario produces a false
  PASS. Mitigated by a scenario review gate in the contribution
  process (documented in `CONTRIBUTING.md`).
- **Detection-window tuning is environment-specific.** The
  detection validator's assertion window (how long to wait for an
  alert to appear) is deployment-specific. Too short and slow
  platforms produce false FAILs; too long and the simulation
  takes prohibitively long. Operators must configure
  `detection_window_seconds` per adapter. Defaults documented
  in `docs/tuning-guide.md`.
- **PyO3 ABI coupling.** The Rust payload engine is compiled
  against a specific CPython ABI. Python version upgrades require
  a recompile. Mitigated by CI matrix tests across supported Python
  versions and pre-built wheels per Python version.

### Neutral

- **Ecosystem total grows by one Phase-3 platform.** Already
  reflected in [ECOSYSTEM.md](../ECOSYSTEM.md) and
  [ROADMAP.md](../ROADMAP.md); no schema changes in other platforms
  beyond the CITADEL `securelab.simulation` event type.
- **Doc count grows** as v1.0.0 paperwork lands (initial scaffold:
  ~12 docs; full v1.0.0 audit-readiness package: ~24 docs).

## Open questions (defer to Phase 3 kickoff)

1. Scenario sandboxing: should Python scenario scripts run inside a
   restricted interpreter (RestrictedPython, PyPy sandbox) or is
   process isolation (subprocess with resource limits) sufficient?
   Default working assumption is process isolation; revisit at
   v0.0.1.
2. ATT&CK bundle pinning cadence: MITRE releases ATT&CK updates
   quarterly. Should SecureLab update the pinned bundle on a fixed
   cadence (quarterly) or on each release? Default working
   assumption is quarterly cadence aligned with MITRE's release
   schedule.
3. Scenario contribution model: community-contributed scenarios
   accepted via pull request (same as code), or a separate curated
   catalogue with a higher review bar? Default working assumption
   is pull-request model with a mandatory review checklist.
4. Dashboard scope: is the v0.1.0 dashboard read-only (view
   scenario library, view execution history, view ATT&CK coverage
   map) or does it include scenario triggering? Default working
   assumption is read-only in v0.1.0; execution via API only.

## Implementation checklist (Phase 3 kickoff)

- [ ] This ADR approved by core-maintainers.
- [ ] SecureLab lead identified.
- [ ] `opensecstack/securelab/` directory created with scaffold
      paperwork (this commit).
- [ ] Updated: [ECOSYSTEM.md](../ECOSYSTEM.md),
      [ROADMAP.md](../ROADMAP.md),
      [docs/deployment-topology.md](../docs/deployment-topology.md),
      [docs/compatibility-matrix.md](../docs/compatibility-matrix.md).
- [ ] CITADEL Kerkese schema extended with `securelab.simulation`
      event type (START + RESULT) — joint with the CITADEL team.
- [ ] OpenScrub, APIGuard, ThreatFlow, IRFlow adapter contracts
      reviewed and approved — joint with respective platform leads.
- [ ] Network isolation deployment guide drafted in
      `docs/deployment-topology.md` before v0.0.1 tag.
- [ ] `good-first-issue` label applied to the first 5 v0.1.0
      tasks (PostgreSQL schema, scenario engine skeleton, attack
      library structure, ATT&CK STIX bundle ingestor, scenario
      execution API endpoint).

## References

- NIS2 Directive (EU) 2022/2555, Article 21(2)(a) — risk-analysis
  and information-security policies, regular testing requirement
- MITRE ATT&CK Enterprise Matrix — scenario-to-technique mapping
  source
- MITRE Caldera — alternative considered (not adopted)
- Atomic Red Team (Red Canary) — alternative considered (not adopted)
- scapy — Python packet crafting library (attack library dependency)
- impacket — Python Windows protocol implementation library (attack
  library dependency)
- PyO3 — Rust/Python FFI binding framework (payload engine)
- CITADEL ADR (ADR-TBD) — WORM evidence chain contract

## Review

Quarterly review by core-maintainers. Next review: 2027 Q3 (before
Phase 3 kickoff).
