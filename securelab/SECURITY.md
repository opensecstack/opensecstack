# SecureLab Security Policy

> **Canonical security index:** lands at [`docs/security/`](docs/security/)
> with v1.0.0 — threat model, control checklist, isolation
> requirements, pentest scoping, disclosure terms, compliance
> traceability.

---

## ACCESS CONTROL WARNING

**SecureLab contains offensive tooling.**

SecureLab ships attack scenarios, payload generation primitives, and
exploitation techniques mapped to the MITRE ATT&CK framework. This
is intentional — it is a detection validation platform that must be
able to replicate real attacker behaviour.

This means:

- **SecureLab must never be deployed on a network reachable from the
  public internet.** It must run in an isolated network segment with
  explicit allow-list firewall rules. See
  [docs/deployment.md](docs/deployment.md).
- **Access must be restricted to authorised red-team and security
  operations personnel only.** Treat access to the SecureLab API and
  dashboard as equivalent to giving someone root on your internal
  systems.
- **Unauthorised access to a running SecureLab instance must be
  treated as a critical security incident.** Escalate immediately via
  your incident response procedure.
- **Scenario execution against systems you do not own or do not have
  explicit written authorisation to test is illegal in most
  jurisdictions.** Apache 2.0 grants you a software licence, not
  authorisation to attack systems.

See [docs/deployment.md](docs/deployment.md) for the mandatory
isolation architecture and [docs/operator-handbook.md](docs/operator-handbook.md)
for safe operation procedures.

---

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities** —
this exposes deployers before a fix is available. Disclosures related
to the offensive tooling (payload engine, scenario execution, isolation
bypass) are treated as high-severity by default and routed directly to
the core security team.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Key: `keybase.io/opensecstack` | Isolation bypasses, payload engine escapes, and any vulnerability requiring encryption. |

See the root [SECURITY.md](../SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- SecureLab Python API server (`securelab/`)
- Rust payload engine (`payload-engine/`) and PyO3 bindings
- React dashboard (`web/`)
- Scenario engine: scenario YAML loader, executor, result recorder
- Detection validator: OpenScrub, APIGuard, ThreatFlow adapters
- CITADEL `securelab.simulation` evidence emitter
- Docker images published to `ghcr.io/opensecstack/securelab:*`
- Network isolation controls in the reference Docker Compose and
  Kubernetes deployment configurations
- Attack library: YAML primitives under `attack_library/`
- Scenario library: YAML scenarios under `scenarios/`

**OUT OF SCOPE:**

- Vulnerabilities in the target systems being simulated (those are
  findings from your own red-team exercise, not SecureLab bugs)
- OpenScrub, APIGuard, ThreatFlow, IRFlow vulnerabilities (report to
  those platforms)
- Scenarios or attack primitives contributed by the community that
  are themselves malicious (report as a content security issue per the
  contribution review process)
- Feature requests for new attack techniques or evasion primitives
  (open a standard issue; do not use the security channel)

## Threat model

SecureLab's threat model spans five axes specific to an offensive
tooling platform:

### 1. Isolation escape

**Adversary goal:** break out of the SecureLab execution environment
and affect systems outside the intended simulation target, or reach
systems that are explicitly out of scope for the exercise.

**Attack vectors:**
- Misconfigured Docker network allowing SecureLab to reach production
  systems
- Scenario step with a payload that pivots beyond the target host
- Operator error: running a scenario against a production target
- Rust payload engine memory safety defect allowing host compromise

**Mitigations:**
- Default Docker Compose configuration uses an isolated bridge network
  with no external routing. Operators must explicitly configure target
  network access via allow-list rules
- `SECURELAB_ISOLATION_MODE=strict` enforces egress filtering at the
  API layer: scenario steps that target hosts outside the configured
  target CIDR are rejected before dispatch
- Scenario YAML includes a mandatory `target_scope` field; the
  executor validates targets against scope before execution
- Rust payload engine compiled with `deny(unsafe_code)` where
  possible; unsafe blocks require explicit maintainer sign-off
- All scenario executions are logged to the audit trail before
  dispatch (not after) so a failed scope check is still visible

### 2. Offensive tooling misuse

**Adversary goal:** extract attack payloads, scenarios, or primitives
from SecureLab and use them outside the platform against unauthorised
targets.

**Attack vectors:**
- API endpoint exposed without authentication
- Dashboard accessible without MFA
- Attack library exported in bulk via API without authorisation check
- Insecure default configuration leaves the API on `0.0.0.0:8087`
  with no authentication

**Mitigations:**
- API requires authenticated session for all non-health endpoints;
  no anonymous access to scenario content or attack library
- Attack primitive endpoints return metadata only by default; payload
  content requires operator-level role
- Default binding is `127.0.0.1:8087`; operators must explicitly
  configure network exposure
- `SECURELAB_ISOLATION_MODE=strict` (default) refuses to start if
  `SECURELAB_HTTP_ADDR` resolves to a public interface without an
  explicit `SECURELAB_ALLOW_PUBLIC_BIND=true` override
- Audit log records every API call that touches attack content or
  triggers execution; log is append-only and forwarded to CITADEL

### 3. Result tampering

**Adversary goal:** falsify simulation results so that detections
appear to pass when they did not, or suppress evidence of a detection
gap to mislead an audit.

**Attack vectors:**
- Direct database modification of execution results
- Replay of a passing execution record for a different scenario
- Suppression of the CITADEL evidence emission so a gap is not
  recorded in the WORM ledger
- Altering the scenario version referenced in a result

**Mitigations:**
- Execution results are immutable once committed; the result record
  includes a BLAKE3 hash of the full execution state
- Scenario version is content-hashed at execution time and stored
  alongside the result; post-hoc scenario modification does not
  affect existing result records
- CITADEL emission is mandatory for live executions; failure to emit
  within the circuit-breaker timeout marks the result as
  `evidence_pending` and blocks the result from being marked `passed`
- Audit log is append-only at the database level (INSERT only, no
  UPDATE/DELETE on audit tables); enforced via Postgres row-level
  security

### 4. Supply chain

**Adversary goal:** compromise scenario content, attack primitives,
or the payload engine crate to introduce malicious behaviour that
executes against simulation targets without operator awareness.

**Attack vectors:**
- Malicious scenario PR that adds a step with a destructive payload
- Compromised PyPI or crates.io dependency
- Backdoored Docker image used as the API container

**Mitigations:**
- Scenarios and attack primitives require mandatory security review
  before merge; no scenario merges without sign-off from a
  core-security-team member (see [CONTRIBUTING.md](CONTRIBUTING.md))
- `uv.lock` + `Cargo.lock` pinned and committed; dependency updates
  are PRs and go through the same review process
- SBOM (CycloneDX) generated at release for both Python and Rust
  dependency trees
- Docker images are Cosign-signed at release; deployers should
  verify signatures before deployment (procedure in
  `docs/deployment.md`)

### 5. Lateral movement via detection adapters

**Adversary goal:** use the detection validator's outbound connections
to OpenScrub, APIGuard, or ThreatFlow as a pivot point to reach those
platforms under SecureLab's service identity.

**Attack vectors:**
- Overly permissive HMAC key shared between SecureLab and a detection
  platform
- Detection adapter with excessive API permissions used to query or
  modify detection rules
- SecureLab compromised; attacker uses adapter credentials to
  exfiltrate detection rule content

**Mitigations:**
- Each integration uses a dedicated HMAC key with the minimum
  required scope (read-only for detection query endpoints)
- Integration keys are stored as environment secrets; never in
  `config.yaml` or committed to version control
- Detection adapters are read-only by default; no SecureLab API path
  creates or modifies rules in connected platforms
- Network egress from SecureLab is allow-listed to the specific
  IP/port of each integration endpoint; no general outbound internet
  access

## Security design principles

SecureLab inherits the ecosystem's principles (see root
[SECURITY.md](../SECURITY.md)) and adds:

1. **Offensive tools require defensive controls on the tool itself.**
   SecureLab's own API must be at least as hardened as the systems
   it simulates attacks against.
2. **Execution is authorised or it does not happen.** Every scenario
   execution requires an authenticated operator; every execution is
   recorded in the audit log before dispatch; every live execution
   is sealed in the CITADEL WORM ledger.
3. **Isolation is a hard requirement, not a recommendation.** The
   default configuration enforces isolation. Operators who weaken
   isolation controls do so explicitly and accept full responsibility
   for the consequences.
4. **Payloads are never stored in plaintext logs.** Execution logs
   record scenario IDs, step IDs, and outcome codes. Payload content
   is stored in the payload engine's content-addressed store, not in
   plain log lines that may be shipped to a log aggregator.
5. **Detection gaps are evidence too.** A scenario execution that
   produces no detection event is a finding. SecureLab records it
   as `detection_verdict: not_detected` and emits it to CITADEL.
   The absence of a detection is not the absence of an audit record.

## Post-quantum strategy

SecureLab uses:

| Primitive | Usage | Quantum-safe? | Migration |
|---|---|:-:|---|
| HMAC-SHA256 | Webhooks to CITADEL, integration adapters | ✓ | No change |
| BLAKE3 | Execution result integrity, scenario content hashing | ✓ | No change |
| SHA-256 | Scenario version content-addressing | ✓ (reduced security) | Tracking ecosystem migration |
| Argon2id (via opensecstack/sdk) | Operator password hashing | ✓ | No change |

See ecosystem-wide [post-quantum roadmap](../docs/post-quantum-roadmap.md)
and [ADR-011](../adrs/ADR-011-post-quantum-agility.md).

## Data handling

### Execution data

SecureLab stores scenario execution records, detection assertions,
and audit logs. Privacy considerations:

- **Execution records** contain: scenario ID (content-hashed version),
  operator ID, target scope, step outcomes, detection verdicts,
  timestamps. No payload content in execution records.
- **Audit log** is append-only and retained for the deployment
  lifetime. Operators may pseudonymise the `operator_id` field for
  GDPR compliance while retaining the execution audit chain.
- **Payload content** is stored in the payload engine's
  content-addressed store. Operators may purge payload content after
  a configurable retention period; execution records (which reference
  payloads by hash) remain intact.
- **No outbound telemetry** of payload content, scenario content, or
  operator identity to any third-party service. CITADEL is a
  first-party ecosystem component under the operator's control.

## Known limitations

- **Isolation depends on operator configuration.** The platform
  enforces isolation controls; it cannot prevent a misconfigured
  firewall from routing simulation traffic to production.
- **Detection validation depends on integration availability.**
  If OpenScrub, APIGuard, or ThreatFlow is unreachable during a
  validation window, the verdict is `inconclusive`, not `passed`.
- **Scenario content quality is the responsibility of contributors.**
  First-party scenarios are reviewed; community-contributed scenarios
  undergo review before merge but operators should validate scope
  before executing a third-party scenario.
- **The Rust payload engine does not sandbox payloads against the
  host OS.** It generates payloads as data; dispatching them to
  targets is the scenario engine's job, which enforces scope. The
  payload engine itself does not require network access.

## Related

- [`docs/security/`](docs/security/) — full audit-readiness package
  (lands with v1.0.0)
- [`docs/deployment.md`](docs/deployment.md) — mandatory isolation
  architecture
- [`docs/operator-handbook.md`](docs/operator-handbook.md) — safe
  operation procedures
- Root [SECURITY.md](../SECURITY.md) — ecosystem disclosure policy
- [ADR-011](../adrs/ADR-011-post-quantum-agility.md)
