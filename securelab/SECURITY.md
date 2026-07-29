# SecureLab Security Policy

> **Canonical security index:** lands at [`docs/security/`](docs/security/)
> with v1.0.0 — threat model, control checklist, isolation
> requirements, pentest scoping, disclosure terms, compliance
> traceability.

---

## ACCESS CONTROL WARNING

**SecureLab contains offensive tooling.**

SecureLab ships attack scenarios and attack-simulation modules mapped
to the MITRE ATT&CK framework. This is intentional — it is a detection
validation platform that must be able to replicate real attacker
behaviour.

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
to the offensive tooling (attack modules, scenario execution, isolation
bypass) are treated as high-severity by default and routed directly to
the core security team.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Key: `keybase.io/opensecstack` | Isolation bypasses and any vulnerability requiring encryption. |

See the root [SECURITY.md](../SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- SecureLab API server, Go 1.22 (`internal/`, `cmd/server`) — chi
  router, pgx, zap
- Rust payload-generation crate (`rust/payload-gen`) — standalone,
  unit-tested library; not currently linked into the live API request
  path (see [README.md § Future / Not Yet Implemented](README.md))
- React/TypeScript dashboard (`web/`)
- Scenario engine: YAML scenario loader (`scenarios/`), validator,
  executor, result recorder (`internal/scenarios/`)
- Attack modules: native Go attack primitives under `internal/attacks/`
- Detection validator: OpenScrub, APIGuard, ThreatFlow polling adapters
  (`internal/detection/`)
- CITADEL `securelab.run_completed` evidence emitter
  (`internal/citadel/connector.go`)
- Docker images published to `ghcr.io/opensecstack/securelab:*`
- Network isolation controls in the reference Docker Compose
  (`docker-compose.yml`) — no Kubernetes/Helm manifests ship today
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

SecureLab's threat model spans four axes specific to an offensive
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

**Mitigations:**
- The reference Docker Compose deployment binds `securelab-api` and
  `securelab-web` to `127.0.0.1` and keeps `securelab-db` unpublished;
  it does **not** itself enforce a hardened `internal: true` /
  egress-restricted network. Network isolation is the operator's
  responsibility at the VLAN/firewall level — see
  [docs/deployment.md](docs/deployment.md).
- `internal/scenarios/validator.go` refuses to run a scenario whose
  target hostname matches a fixed production-hostname blocklist
  (`*.prod`, `*.production`, `production.*`) before dispatch. This is
  a hostname pattern check, not a CIDR/scope validator, and the
  blocklist is not currently operator-configurable.
- All scenario executions are logged to the CITADEL WORM ledger on
  completion (see § CITADEL evidence below); there is currently no
  pre-dispatch audit record in the application database — see
  [docs/operator-handbook.md § Future / Not Yet Implemented](docs/operator-handbook.md).

### 2. Offensive tooling misuse

**Adversary goal:** extract attack payloads, scenarios, or attack
modules from SecureLab and use them outside the platform against
unauthorised targets.

**Attack vectors:**
- API endpoint exposed without authentication
- Dashboard accessible without authentication
- Scenario content exported in bulk via API without authorisation
  check
- Insecure default configuration leaves the API bound to a public
  interface

**Mitigations:**
- The API requires an authenticated JWT (local HS256 or sinauth RS256
  SSO) for all non-health endpoints; there is no anonymous access to
  scenario content
- RBAC via `internal/api/middleware.RequireRole` — three roles:
  `analyst` (read-only), `operator` (read + create/run scenarios),
  `admin` (also create/delete environments). See
  [docs/operator-handbook.md § Roles](docs/operator-handbook.md)
- Default listen address in code is `:8085`; the shipped
  `docker-compose.yml` binds the container's `8080` to
  `127.0.0.1:8080` on the host, not `0.0.0.0`. There is no built-in
  "public bind" guard in `internal/config` — operators are responsible
  for not exposing `SECURELAB_HTTP_ADDR` publicly (see
  [docs/deployment.md § Production hardening checklist](docs/deployment.md))
- If you suspect a compromised token, rotate `SECURELAB_JWT_SECRET`
  (invalidates all locally-issued tokens) and/or revoke the session at
  your sinauth identity provider — there is no local
  `/auth/revoke-all` endpoint today

### 3. Result tampering

**Adversary goal:** falsify simulation results so that detections
appear to pass when they did not, or suppress evidence of a detection
gap to mislead an audit.

**Attack vectors:**
- Direct database modification of `scenario_runs` rows
- Suppression of the CITADEL evidence emission so a gap is not
  recorded in CITADEL's WORM ledger

**Mitigations:**
- CITADEL emission (`securelab.run_completed`) is attempted once per
  completed run, synchronously, under a 5-second timeout, when
  `SECURELAB_CITADEL_API_URL` is set and `SECURELAB_CITADEL_DRY_RUN=false`.
  The event body is signed with HMAC-SHA256 over the full request and
  sent as `X-CITADEL-Signature: sha256=<hex>`. See
  [docs/citadel-integration.md](docs/citadel-integration.md) for the
  exact wire format.
- **This is a best-effort, non-fatal integration, not a tamper-proof
  one on SecureLab's side.** A failed or slow CITADEL call is logged
  and does not fail the run; there is no retry queue, circuit breaker,
  or evidence-hash field emitted by SecureLab for independent
  tamper-checking. Once an event reaches CITADEL, its immutability is
  enforced by CITADEL's own WORM chain (TripleHash), not by anything
  SecureLab does locally.
- There is currently **no dedicated audit-log table** for
  `scenarios`/`environments`/`scenario_runs` mutations in the
  application database. In an incident, those application tables
  themselves are the available record — see
  [docs/operator-handbook.md § Incident response](docs/operator-handbook.md).
  Treat this as a known gap, not a shipped control.

### 4. Detection-adapter misuse

**Adversary goal:** use the detection validator's outbound polling of
OpenScrub, APIGuard, or ThreatFlow as a pivot point, or exhaust those
platforms' APIs, under SecureLab's service identity.

**Attack vectors:**
- Overly permissive credentials shared between SecureLab and a
  detection platform
- Detection adapter with excessive API permissions used to query
  detection state beyond what SecureLab needs
- SecureLab compromised; attacker uses adapter credentials against the
  connected platforms

**Mitigations:**
- `internal/detection` polls OpenScrub, APIGuard, and ThreatFlow for
  detection confirmation; each integration is enabled independently by
  setting its `SECURELAB_*_URL` variable (empty disables polling for
  that platform) — see [docs/configuration.md](docs/configuration.md)
- Integration URLs and secrets are supplied as environment variables;
  never commit them to `config.yaml` (there is no `config.yaml` —
  configuration is env-var only) or to version control

## Security design principles

SecureLab inherits the ecosystem's principles (see root
[SECURITY.md](../SECURITY.md)) and adds:

1. **Offensive tools require defensive controls on the tool itself.**
   SecureLab's own API must be at least as hardened as the systems
   it simulates attacks against.
2. **Execution requires an authenticated operator.** Every scenario
   execution requires a valid JWT with `operator` or `admin` role.
   Completed runs are recorded in CITADEL when CITADEL emission is
   enabled — see § Result tampering above for the current limits of
   that guarantee.
3. **Isolation is a hard requirement, not a recommendation.** The
   mandatory isolation topology is documented in
   [docs/deployment.md](docs/deployment.md). It is enforced at the
   operator's VLAN/firewall layer, not inside the application; operators
   who weaken isolation controls do so explicitly and accept full
   responsibility for the consequences.
4. **Detection gaps are evidence too.** A scenario run whose `detected`
   field is `false`/`null` is a finding, not a silent pass. See
   [docs/operator-handbook.md § Interpreting run results](docs/operator-handbook.md).

## Post-quantum strategy

SecureLab uses:

| Primitive | Usage | Quantum-safe? | Migration |
|---|---|:-:|---|
| HMAC-SHA256 | CITADEL event signing (`internal/citadel/connector.go`) | ✓ | No change |
| RS256 (RSA) | sinauth SSO token verification | Tracking ecosystem migration | See sinauth JWKS rollout |
| HS256 (HMAC-SHA256) | Locally-issued JWT signing (`SECURELAB_JWT_SECRET`) | ✓ | No change |
| Argon2id (via opensecstack/sdk) | Operator password hashing, where local credentials are used | ✓ | No change |

See ecosystem-wide [post-quantum roadmap](../docs/post-quantum-roadmap.md)
and [ADR-011](../adrs/ADR-011-post-quantum-agility.md).

## Data handling

### Execution data

SecureLab stores scenario, environment, and run records in PostgreSQL.
Privacy considerations:

- **`scenario_runs` records** contain: scenario ID, environment ID,
  status, timestamps, `attack_events`/`detection_events` (JSONB),
  detection latency, and the `detected` boolean. See
  `internal/db/migrations/003_results.sql` for the exact schema.
- **No dedicated audit-log table exists today.** See § Result
  tampering above and
  [docs/operator-handbook.md § Future / Not Yet Implemented](docs/operator-handbook.md)
  for what operational logging is and isn't in place.
- **No outbound telemetry** of scenario content or operator identity
  to any third-party service beyond the explicitly configured
  CITADEL, OpenScrub, APIGuard, ThreatFlow, and sinauth endpoints —
  all first-party ecosystem components under the operator's control.

## Known limitations

- **Isolation depends on operator configuration.** The shipped
  `docker-compose.yml` does not itself enforce network isolation; it
  binds services to `127.0.0.1` but a misconfigured host firewall can
  still route simulation traffic to production. See
  [docs/deployment.md](docs/deployment.md).
- **Detection validation depends on integration availability.**
  `internal/detection` polls OpenScrub, APIGuard, and ThreatFlow; if a
  platform is unreachable or its URL is unset, that platform is simply
  not polled — there is no distinct `inconclusive` verdict state in
  the current implementation. See
  [docs/operator-handbook.md § Interpreting run results](docs/operator-handbook.md).
- **Scenario content quality is the responsibility of contributors.**
  First-party scenarios are reviewed; community-contributed scenarios
  undergo mandatory security review before merge (see
  [CONTRIBUTING.md](CONTRIBUTING.md)), but operators should validate
  scope before executing a third-party scenario.
- **The Rust payload-generation crate is not wired into the API.**
  `rust/payload-gen` is a standalone, tested library exposing BOLA/JWT/
  mass-assignment payload generation and byte-mutation fuzzing;
  `internal/attacks/` currently generates its own payloads natively in
  Go. Treat any claim of Rust-backed payload generation in a running
  deployment as inaccurate until this is wired up — see
  [README.md § Future / Not Yet Implemented](README.md).
- **No dedicated audit-log table, retry queue, or token-revocation
  API.** See [docs/operator-handbook.md § Future / Not Yet Implemented](docs/operator-handbook.md)
  for the full list of operational gaps.

## Related

- [`docs/security/`](docs/security/) — full audit-readiness package
  (lands with v1.0.0)
- [`docs/deployment.md`](docs/deployment.md) — mandatory isolation
  architecture
- [`docs/operator-handbook.md`](docs/operator-handbook.md) — safe
  operation procedures
- [`docs/citadel-integration.md`](docs/citadel-integration.md) —
  CITADEL emission wire format and limits
- Root [SECURITY.md](../SECURITY.md) — ecosystem disclosure policy
- [ADR-011](../adrs/ADR-011-post-quantum-agility.md)
