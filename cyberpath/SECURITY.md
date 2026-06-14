# CyberPath Security Policy

> **Canonical security index:** lands at [`docs/security/`](docs/security/)
> with v1.0.0 — threat model, control checklist, sandbox-escape
> threat-modelling, pentest scoping, disclosure terms, compliance
> traceability.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities** —
this exposes deployers before a fix is available. **Sandbox-escape
findings are treated as high-severity by default** and routed
directly to the core security team.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Key: `keybase.io/opensecstack` | Sandbox-escape disclosures and any vulnerability requiring encryption. |

See the root [SECURITY.md](../SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- CyberPath Go API server + CLI
- React frontend (`web/`)
- Rust crates under `rust/` (Wasm lab runtime, v1.0.0+)
- Wasm sandbox host and per-session isolation policy
- Pre-built lab images: `labs/labs.yaml` is the in-repo registry
  pinning each lab to a SHA-256 digest, while the actual lab images
  live at `ghcr.io/opensecstack/cyberpath-labs/<track>:<version>`
  (Cosign-signed per [`docs/security/image-signing.md`](docs/security/image-signing.md)).
  Both must be verified at deploy time.
- Docker images published to `ghcr.io/opensecstack/cyberpath:*`
- Certification signing (Ed25519) and verification flow
- CITADEL `cyberpath.completion` evidence emitter
- NIS2 Compass coverage / recommend API contracts

**OUT OF SCOPE:**

- wasmtime upstream (report to Bytecode Alliance; notify us so we can
  pin / patch)
- Third-party lab images contributed by the community (report
  upstream; notify us if a contributed image carries a CVE)
- Generic LMS feature requests (CyberPath is cyber-training-specific)
- Issues in user-authored track content (raise as a content quality
  issue, not a security advisory)

## Threat model

CyberPath's threat model spans four axes:

### 1. Sandbox escape

**Adversary goal:** escape the Wasm lab sandbox and read or write
host state — the most critical class of bug for v1.0.0+.

**Attack vectors:**
- Wasm runtime CVEs (wasmtime upstream)
- Lab-image-supplied modules that exploit sandbox host functions
- Resource exhaustion (CPU / memory / fuel) leading to host
  destabilisation
- Side-channels via timing or resource counters

**Mitigations:**
- wasmtime pinned and patched promptly on advisory
- Sandbox host functions enumerated and reviewed (no host filesystem
  access by default)
- Per-session isolation: no cross-session state
- Resource caps enforced via wasmtime fuel + memory limits
- `make test-sandbox` covers known escape patterns (target: lands with v1.0.0; tracked as gap G1 in [docs/security/pre-audit-plan.md](docs/security/pre-audit-plan.md))

### 2. Evidence forgery

**Adversary goal:** issue a forged completion or alter an existing
completion record so an audit query returns a false positive.

**Attack vectors:**
- Replay of HMAC-signed `cyberpath.completion` events
- Submission of completions for users without their authentication
- Altering `content_version_id` references after issuance
- Compromise of the certification signing key

**Mitigations:**
- HMAC-SHA256 with timestamp + nonce; replay window enforced by
  CITADEL
- Completion endpoint requires authenticated session; no service-
  token bypass
- `content_version_id` is foreign-keyed to an immutable revision
  table (Module 8)
- Certification signing key stored in a KMS-backed secret store; key
  rotation procedure documented in `docs/operator-handbook.md`
  (lands with v1.0.0)

### 3. Service abuse

**Adversary goal:** exhaust CyberPath resources or use the platform
to attack other systems.

**Attack vectors:**
- Mass lab-session spinup (Docker / Wasm host exhaustion)
- Outbound network from lab containers (lateral movement)
- Quiz brute-force to mine question banks
- Excessive completion-event emission to flood CITADEL

**Mitigations:**
- Per-caller rate limiting at API layer
- Lab sessions default to no outbound network; egress is
  per-deployment policy
- Quiz banks are randomised; raw question IDs not exposed in scoring
  responses
- CITADEL emitter has a bounded async queue + circuit breaker (same
  pattern as VertGuard)

### 4. Supply chain

**Adversary goal:** compromise lab images, dependencies, or content.

**Attack vectors:**
- Malicious lab image uploaded under a familiar name
- Compromised npm / Go / Cargo dependency
- Backdoored track content with credential phishing payloads in
  example exercises

**Mitigations:**
- SHA-256 checksums on all lab images in `labs/labs.yaml`
- `Cargo.lock` + `go.sum` + `package-lock.json` pinned and committed
- SBOM (CycloneDX) generated at release
- Track content review by at least one core-maintainer before merge

## Security design principles

CyberPath inherits the ecosystem's principles (see root
[SECURITY.md](../SECURITY.md)) and adds:

1. **Sandboxes are not trust boundaries by accident.** Every Wasm
   host function is enumerated, reviewed, and accounted for in the
   threat model.
2. **Completions are immutable.** A completion is appended to the
   audit chain; it cannot be edited. Mistakes are corrected by
   issuing a follow-on `cyberpath.correction` event, never by
   modifying history.
3. **Content integrity is verifiable.** Every completion references
   a `content_version_id` that resolves to an immutable revision; an
   auditor can rerun the same lesson the learner saw.
4. **Lab egress is opt-in.** Default is no outbound network from
   lab sessions. Operators enable egress per-track deliberately.
5. **No PII in lab telemetry.** Lab session telemetry contains
   resource metrics, not user inputs.

## Post-quantum strategy

CyberPath uses:

| Primitive | Usage | Quantum-safe? | Migration |
|---|---|:-:|---|
| HMAC-SHA256 | Webhooks to CITADEL, NIS2 Compass | ✓ | No change |
| SHA-256 | Lab image integrity, content versioning | ✓ (reduced security) | Tracking ecosystem migration |
| **Ed25519** | Certification signing | **✗ Vulnerable** | v2.0 hybrid ML-DSA per ecosystem PQ migration |
| Argon2id (via opensecstack/sdk) | Password hashing | ✓ | No change |

See ecosystem-wide
[post-quantum roadmap](../docs/post-quantum-roadmap.md) and
[ADR-011](../adrs/ADR-011-post-quantum-agility.md).

## Data handling

### Learner PII

CyberPath stores learner identity (email, display name) and
completion history. Privacy considerations:

- **Default retention:** completions are retained for the lifetime
  of the deployment (audit-grade evidence). Learner-personal data
  (display name, email) is separable from completion records via
  `user_id` indirection.
- **Right to erasure:** learner-personal fields can be redacted in
  place; completion records remain anchored to the (now-pseudonymous)
  `user_id` so the audit chain is preserved.
- **No outbound telemetry** of lesson content or quiz answers. Ever.

### GDPR compliance

CyberPath ships supporting GDPR-compliant deployments:

- Right to erasure handled via `user_id` redaction
- Data minimisation: only metadata required for evidence is stored
- Purpose limitation: deployment configures which integrations are
  active

Data Protection Impact Assessment (DPIA) scope: see
[docs/security/compliance-map.md](docs/security/compliance-map.md)
§ 3 (GDPR Article 32) for the per-control evidence matrix; the
template lands with v1.0.0.

## Known limitations

- **Wasm sandbox escapes depend on wasmtime upstream.** We track
  Bytecode Alliance advisories and patch within the SLA documented
  in the root SECURITY.md.
- **Audit-grade evidence requires CITADEL.** Without CITADEL,
  completions are stored locally but lack the immutable cross-
  platform audit chain.
- **Track content quality is the deployer's responsibility for
  content authored outside the ecosystem.** First-party tracks are
  reviewed; third-party tracks are not.

## Related

- [`docs/security/`](docs/security/) — full audit-readiness package
  (lands with v1.0.0)
- Root [SECURITY.md](../SECURITY.md) — ecosystem disclosure policy
- [../adrs/ADR-012-cyberpath-platform-strategy.md](../adrs/ADR-012-cyberpath-platform-strategy.md)
- [../adrs/ADR-011-post-quantum-agility.md](../adrs/ADR-011-post-quantum-agility.md)
