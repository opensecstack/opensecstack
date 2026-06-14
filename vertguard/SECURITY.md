# VertGuard Security Policy

> **Canonical security index:** [`docs/security/`](docs/security/) —
> threat model, control checklist, static-analysis report, pentest
> scoping, disclosure terms, compliance traceability, pre-audit plan.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities** —
this exposes users before a fix is available.

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | Preferred. Private. GitHub handles coordination. |
| Email | `security@opensecstack.org` | Alternative if GitHub advisory not accessible. |
| PGP encrypted email | Key: `keybase.io/opensecstack` | Sensitive vulnerabilities requiring encryption. |

See the root [SECURITY.md](../SECURITY.md) for ecosystem-wide
disclosure policy and response SLA.

## Scope

**IN SCOPE:**

- VertGuard Go API server + CLI
- Rust crates under `rust/` (c2pa, prompt-patterns, audio-fingerprint)
- Python ML service (Phase 4.2+)
- Docker images published to `ghcr.io/opensecstack/vertguard:*`
- Model registry (`models.yaml`) and dataset registry integrity
- gRPC contracts between Go and Python ML layer
- VertGuard-specific webhooks and integrations (CITADEL, ThreatFlow)

**OUT OF SCOPE:**

- Third-party ML models downloaded from HuggingFace (report upstream;
  notify us of supply-chain concerns)
- C2PA specification itself (report to c2pa.org)
- MITRE ATLAS framework content (report to MITRE)
- Known limitations of ML-based detection (see
  [docs/false-positive-handling.md](docs/false-positive-handling.md))

## Threat model

VertGuard's core threat model spans three axes:

### 1. Detection bypass

**Adversary goal:** craft AI-generated content that VertGuard
classifies as authentic.

**Attack vectors:**
- Adversarial perturbations on images/video (Phase 4.2 concern)
- Prompt injection payloads crafted to evade our pattern engine
- Obfuscated AI-generated text (Unicode tricks, zero-width spaces)
- Novel generation models whose fingerprints we don't recognise

**Mitigations:**
- Pattern engine updated quarterly; `pattern-registry` versioned
- Adversarial robustness testing in `tests/adversarial/`
- Confidence thresholds configurable per deployment
- Research partnerships to track emerging attack techniques

### 2. Service abuse

**Adversary goal:** exhaust VertGuard resources or exfiltrate data.

**Attack vectors:**
- Large payloads to ML inference (GPU exhaustion)
- Rapid scan requests to Rust pattern engine (CPU exhaustion)
- Crafted inputs that trigger expensive code paths
- Exfiltration via verbose error messages or timing side-channels

**Mitigations:**
- Per-caller rate limiting at API layer
- ML inference budget caps per deployment
- Input size limits enforced at API layer
- Structured error responses with no sensitive data leakage

### 3. Supply chain

**Adversary goal:** compromise ML models, datasets, or dependencies.

**Attack vectors:**
- Malicious HuggingFace model uploaded under a familiar name
- Poisoned training dataset used for fine-tuning
- Compromised Rust crate dependency
- Backdoored Python package

**Mitigations:**
- SHA-256 checksums on all models in `models.yaml`
- Dataset provenance recorded in `datasets.yaml`
- `Cargo.lock` + `go.sum` + `requirements.txt` pinned and committed
- SBOM (CycloneDX) generated at release
- Dependency review in [CODEOWNERS](../.github/CODEOWNERS)

## Security design principles

VertGuard inherits the ecosystem's principles (see root
[SECURITY.md § Security Design Principles](../SECURITY.md)) and adds:

1. **No outbound inference by default.** The ML service runs locally
   — never sends inputs to third-party inference APIs unless
   explicitly configured. This matters for privacy-sensitive content.
2. **Model integrity verified at load time.** SHA-256 mismatch = hard
   refusal to start.
3. **Confidence is a contract, not a suggestion.** Every classification
   returns a numeric confidence; operators decide the action threshold.
4. **False positives are bugs.** The `tests/fp/` suite is part of the
   release gate.
5. **Detections are WORM-logged.** Every positive classification
   produces a CITADEL WORM entry for audit and appeal.

## Post-quantum strategy

VertGuard uses:

| Primitive | Usage | Quantum-safe? | Migration |
|---|---|:-:|---|
| HMAC-SHA256 | Webhooks to/from IRFlow, CITADEL | ✓ | No change |
| SHA-256 + SHA-512 + BLAKE3 | Evidence hashing | ✓ (reduced security) | v2.5 QuintHash |
| **X.509 / ECDSA** | C2PA provenance certificates | **✗ Vulnerable** | v2.0 hybrid per upstream C2PA spec |
| Ed25519 | CITADEL integration (inherited) | ✗ | v2.0 hybrid ML-DSA |

C2PA provenance migration to post-quantum depends on the upstream
C2PA specification adopting PQ algorithms. We track the C2PA working
group's PQ decisions and mirror them.

See ecosystem-wide [post-quantum roadmap](../docs/post-quantum-roadmap.md)
and [ADR-011](../adrs/ADR-011-post-quantum-agility.md).

## Data handling

### PII and content scanning

VertGuard processes potentially sensitive content (emails, images,
documents, video streams). Privacy is a core concern:

- **Default retention:** scan inputs are **not persisted** beyond the
  request lifecycle. Only detection results + metadata are stored.
- **Optional content retention** for post-hoc review: configurable via
  `VERTGUARD_CONTENT_RETENTION=false` (default) or `true` with
  per-tenant encryption at rest.
- **No outbound telemetry** of scanned content. Ever.
- **Audit log never contains raw content** — only hashes and metadata.

See [docs/privacy-ml-inference.md](docs/privacy-ml-inference.md)
(Phase 4.2) for the full privacy architecture.

### GDPR compliance

VertGuard as shipped supports GDPR-compliant deployments:

- Right to erasure: scan history tied to request ID; delete endpoint
  available
- Data minimisation: detection results stripped of content bodies
- Purpose limitation: deployment configures which modules are active

Data Protection Impact Assessment (DPIA) template: coming Phase 4.2.

## Known limitations

See [docs/false-positive-handling.md](docs/false-positive-handling.md)
for detection-quality limitations. A short summary:

- **Prompt injection patterns age fast.** Attackers adapt; quarterly
  pattern refresh is part of the maintenance contract.
- **C2PA coverage depends on ecosystem adoption.** Content without
  C2PA manifests cannot be provenance-verified; absence of manifest
  is not evidence of manipulation.
- **MITRE ATLAS is a framework in flux.** Mapping will evolve with
  ATLAS updates.
- **No silver-bullet detection.** VertGuard reduces risk; it does not
  eliminate it. Defence-in-depth with human review remains essential.

## Related

- [`docs/security/`](docs/security/) — full audit-readiness package
  (threat model, checklist, pentest scope, disclosure, compliance
  map, pre-audit plan)
- Root [SECURITY.md](../SECURITY.md) — ecosystem disclosure policy
- [docs/false-positive-handling.md](docs/false-positive-handling.md)
- [docs/privacy-ml-inference.md](docs/privacy-ml-inference.md) — Phase 4.2
- [../adrs/ADR-010-vertguard-platform-strategy.md](../adrs/ADR-010-vertguard-platform-strategy.md)
- [../adrs/ADR-011-post-quantum-agility.md](../adrs/ADR-011-post-quantum-agility.md)
