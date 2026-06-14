# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in any opensecstack platform,
please report it responsibly. **Do not open a public GitHub issue for
security vulnerabilities** — this exposes users before a fix is
available.

| Channel | Address | Use For |
|---------|---------|---------|
| GitHub Security Advisory | Per-platform: `github.com/opensecstack/<platform>/security/advisories/new` | Preferred method. Private. GitHub handles coordination. |
| Email | security@opensecstack.org | Alternative if GitHub advisory not accessible. |
| PGP Encrypted Email | Key: keybase.io/opensecstack | For sensitive vulnerabilities requiring encryption. |

## Response SLA

| Action | Timeline |
|--------|----------|
| Acknowledgment | Within 48 hours of report |
| Initial assessment | Within 7 days |
| Fix for CRITICAL | Within 14 days of confirmation |
| Fix for HIGH | Within 30 days of confirmation |
| Fix for MEDIUM/LOW | Within 90 days of confirmation |
| Public disclosure | After fix is released and users have had 30 days to update |
| CVE assignment | Requested for all confirmed vulnerabilities |

## Scope

**IN SCOPE:**

- All opensecstack platform code: APIGuard, NIS2 Compass, IRFlow,
  ThreatFlow, CITADEL, plus planned platforms (OpenScrub, CyberPath,
  SecureLab, OpenCSIRT, VertGuard) once they enter the repository
- CITADEL governance layer — MARSHAL engine, WORM chain, anchor
  signing, all cryptographic paths
- opensecstack/sdk (Go / Python / TypeScript / Rust)
- Shared modules: `sdk/go/password`, `sdk/python-password`
- Docker images published to `ghcr.io/opensecstack/*`
- opensecstack.org website and infrastructure

**OUT OF SCOPE:**

- Target systems being scanned/tested by opensecstack tools (those are
  your systems)
- Intentionally vulnerable test targets (VAmPI, crAPI, etc.)
- Third-party dependencies (report to the upstream project, but let us
  know)

## Security Design Principles

opensecstack is built on these principles:

1. **Untrusted input is parsed in memory-safe languages** (Rust)
   wherever possible
2. **Secrets never appear in logs** — all logging redacts sensitive
   material
3. **CITADEL audit trail is append-only** — no record can be modified
   after creation
4. **Separation of duties enforced cryptographically, not by
   convention** — MARSHAL Gate 3 (NDS) checks operator ≠ verifier AND
   cross-role-group at every privileged action
5. **Every platform publishes an SBOM** with each release
6. **Cryptographic agility, not single-algorithm bets** — see
   Post-Quantum Strategy below

## Post-Quantum Strategy

NIST finalised the post-quantum cryptographic standards (ML-KEM,
ML-DSA, SLH-DSA) in August 2024. Harvest-now-decrypt-later attacks
are already happening. NIS3 (expected 2030-2032) is projected to
mandate post-quantum migration for essential entities.

**Our commitment:** the opensecstack ecosystem is migrating to PQC
**before** it becomes mandatory, using cryptographic agility
(algorithm identifiers on every signature and hash) rather than a
hard cut-over.

### Current state (v1.0.0)

- **Safe:** WORM chain integrity (SHA-256 + SHA-512 + BLAKE3), HMAC
  webhook signatures
- **Vulnerable to future quantum adversaries:** Ed25519 chain anchor
  signatures, X.509 / ECDSA in C2PA provenance (VertGuard roadmap),
  TLS key exchange (handled by ingress — hybrid KEMs track upstream)

### Migration timeline

| Version | Year | Action |
|---|---|---|
| v1.0.0 | 2026 (now) | Ed25519 anchors + TripleHash. Baseline. |
| v1.1 | 2026-2027 | Add `digest_version` + `signature.alg` schema fields. No breaking change. |
| v2.0 | 2028 | Hybrid Ed25519 + ML-DSA-65 signatures on every new anchor. |
| v2.5 | 2029 | QuintHash — extend TripleHash with 2 PQ-resistant primitives. |
| v3.0 | 2030 | ML-DSA becomes default. Aligned with expected NIS3 transposition. |
| v4.0 | 2033 | Ed25519 signing removed. Historical verification retained indefinitely. |

### Why this matters to your deployment

**Anything you sign today with Ed25519 must still verify when that
algorithm is considered broken.** For a 7-year evidence retention,
that means 2033 reads must succeed on 2026 signatures. The only way
to guarantee that is:

1. Schema-level algorithm identifiers (so future verifiers know what
   to do).
2. Hybrid signing during the transition period (so Ed25519 breaks
   don't invalidate the audit trail).
3. Pubkey registries that retain historical public keys indefinitely.

All three are tracked by [ADR-011](adrs/ADR-011-post-quantum-agility.md)
and executed per the timeline above.

### Operator-facing guide

For per-version upgrade steps and deployment-tier guidance, see:

→ **[docs/post-quantum-roadmap.md](docs/post-quantum-roadmap.md)**

### Architectural rationale

For the full design rationale, alternatives considered, and library
strategy, see:

→ [adrs/ADR-011-post-quantum-agility.md](adrs/ADR-011-post-quantum-agility.md)

## Deployment-tier guidance

v1.0.0's cryptographic primitives are state-of-the-art for classical
adversaries, but whether that's enough depends on your threat model.
Before deploying to production, confirm which tier you fit into — the
matrix spells out exactly what v1.0.0 guarantees per deployment
profile, what you must add in ops, and what remains for v1.1:

→ [docs/security-maturity.md](./docs/security-maturity.md)

Short version:

| Profile | v1.0.0 verdict |
|---|---|
| Standard (single region, trusted operator, typical SaaS / NGO / public admin) | Production-ready |
| Elevated (multi-region, multi-tenant, zero-trust) | Production-ready with Vault + service mesh + OpenTelemetry |
| High assurance (banking Tier 1, NIS2 essential entities, national CSIRTs) | **Not yet** — wait for v1.1 (JWKS, mTLS, third-party audit) |

## Anchor key management

CITADEL's Ed25519 anchor key is the single most sensitive secret in
the ecosystem. Compromise of the key compromises all future anchor
signatures (not past ones — those are already committed). See:

→ [citadel/SECURITY.md § Key management](citadel/SECURITY.md)
→ [citadel/docs/chain-anchor.md](citadel/docs/chain-anchor.md)
→ [citadel/docs/sop-012-incident.md § SOP-012B](citadel/docs/sop-012-incident.md#sop-012b--anchor-key-compromise)

Rotation cadence: quarterly for production deployments. Anchor
pubkeys are **never** deleted, even after rotation — they remain
required to verify historical anchors for the full evidence retention
window.

## Supply chain

Every platform publishes:

- **SBOM** (`SBOM.json`) at release time — CycloneDX format
- **Pinned dependencies** in `go.sum`, `Cargo.lock`, `package-lock.json`,
  `requirements.txt`
- **Docker images signed** with cosign once CI support lands (v1.1)
- **No reproducible builds yet** — roadmap item for Phase 2

Third-party dependencies are reviewed at each version bump. Critical
dependencies (cryptographic libraries especially) have named reviewers
in [.github/CODEOWNERS](.github/CODEOWNERS).

## Related

- [citadel/SECURITY.md](citadel/SECURITY.md) — CITADEL-specific security policy + anchor key runbook
- [irflow/SECURITY.md](irflow/SECURITY.md) — IRFlow-specific security policy
- [docs/security-architecture.md](docs/security-architecture.md) — ecosystem-wide security architecture
- [docs/security-maturity.md](docs/security-maturity.md) — deployment tiers
- [docs/post-quantum-roadmap.md](docs/post-quantum-roadmap.md) — PQ migration timeline
- [adrs/ADR-011-post-quantum-agility.md](adrs/ADR-011-post-quantum-agility.md) — PQ strategy rationale
