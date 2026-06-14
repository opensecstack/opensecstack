# CITADEL Security Model

This document captures what CITADEL trusts, what it enforces, and what
operators must provide.

For user-facing API details, see [api.md](./api.md). For engineering
internals, see [architecture.md](./architecture.md). For reporting a
vulnerability, see [../SECURITY.md](../SECURITY.md).

## What CITADEL protects

CITADEL's security value is in two properties:

1. **Non-repudiable authorisation** — no privileged action on the
   ecosystem can be executed without a MARSHAL decision whose outcome,
   inputs, and signatories are recorded.
2. **Tamper-evident audit trail** — the WORM chain guarantees that the
   record of the above cannot be silently edited after the fact.

Those properties are how NIS2 Article 21(2)(a) (risk management),
21(2)(b) (incident handling), and 21(2)(h) (cryptography and encryption
policies) are satisfied by architecture rather than by documentation.

## What CITADEL trusts

CITADEL is deliberately a thin, inward-facing service. It trusts:

| Assumption | Why |
|---|---|
| Callers are on a trusted network segment (private subnet, service mesh, VPC, or Tailscale network) | CITADEL does not terminate TLS itself; see [deployment-topology.md](../../docs/deployment-topology.md) |
| Upstream platforms have already authenticated the human/machine initiating the action | MARSHAL cares about the Kerkese's actor/verifier IDs, not about how the caller obtained those IDs |
| The `X-Citadel-Signature` HMAC secret is not leaked to an attacker | v1.0.0 does not server-side-enforce the signature; it relies on network-layer trust. See "Known limitations" below |
| Operators rotate the WORM anchor key on compromise | CITADEL has no automatic rotation; see [Keys](#keys) |
| PostgreSQL is not writable by the attacker | A DB-level write bypass would allow history rewrites — this is always true of any audit log |

## What CITADEL enforces

| Control | Mechanism |
|---|---|
| **Separation of Duties (SoD)** | MARSHAL Gate 2 rejects any Kerkese where `actor.user_id == verifier.user_id`. This is the main defence against a single compromised operator pushing arbitrary actions |
| **Role-to-action policy** | MARSHAL Gate 3 checks a project-scoped matrix: which roles may submit which `action.type` values. Policy updates are themselves WORM-logged |
| **Rate limiting** | MARSHAL Gate 4 applies a token bucket per `(actor, project)` pair. Prevents runaway automation or a compromised service account from flooding the system |
| **Emergency override audit** | Gate 5 demands a non-empty `emergency_justification` when `emergency=true`. The justification is logged verbatim to WORM; operators reviewing the audit trail see why normal gates were bypassed |
| **Append-only audit chain** | WORM entries are inserted only — there is no UPDATE or DELETE path in `internal/db/worm.go`. Rewriting history requires direct DB-level write access |
| **TripleHash integrity** | See [architecture.md § WORM chain](./architecture.md#worm-chain). Attacker needs collisions in SHA-256 + SHA-512 + BLAKE3 simultaneously |
| **Ed25519 anchor signatures** | Periodic signed snapshots of `chain_hash` turn offline audit into a constant-time "does the signature match?" check |

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Single compromised operator signs off their own action | SoD (Gate 2) forces distinct `actor`/`verifier` |
| Compromised service account floods governance queue | Rate limit (Gate 4) |
| Policy drift (someone widens role permissions silently) | Policy updates are WORM-logged; diffing the policy history exposes unauthorised changes |
| Post-incident evidence tampering | TripleHash + Ed25519 anchors — any entry mutation breaks chain verification |
| Hash algorithm weakness (SHA-256 collision) | BLAKE3 and SHA-512 still bind the entry |

### Out of scope (pushed to other layers)

| Threat | Handled by |
|---|---|
| Lateral movement on host | OS hardening, container isolation (Layer 3 — see [docs/security-architecture.md](../../docs/security-architecture.md)) |
| Network eavesdropping | TLS termination at ingress + mTLS between platforms (Layer 2; operator-provided, not in v1.0.0 code) |
| Authentication of the human behind the request | Upstream IdP (Keycloak, Auth0, enterprise SSO) |
| DDoS | Upstream WAF / CDN |
| PostgreSQL integrity | Managed PostgreSQL with customer-managed keys, PITR, replication |

## Keys

CITADEL owns three long-lived secrets:

| Key | Purpose | Rotation |
|---|---|---|
| `CITADEL_HMAC_SECRET` | Verifying `X-Citadel-Signature` on inbound calls | Quarterly (recommended). Rotate any time the secret might have leaked. Support for overlapping-secret windows is v1.1 |
| `CITADEL_ANCHOR_KEY` | Ed25519 private key used to sign chain anchors | Annual (recommended). Old public keys must remain verifiable forever — never discard them; publish in the anchor log with a `key_rotation` event |
| `CITADEL_DB_PASSWORD` | PostgreSQL credential | Per standard DB password policy (quarterly) |

All three live in environment variables in v1.0.0. For production-grade
key hygiene, source them from a secret manager (Vault, AWS KMS, GCP
Secret Manager). See [security-maturity.md](../../docs/security-maturity.md#tier-2--elevated-deployment)
for guidance by tier.

### Anchor key compromise playbook

1. Revoke the compromised key immediately at the secret manager.
2. Generate a new Ed25519 key pair.
3. Emit a `key_rotation` WORM event referencing the new public key and
   the last `chain_hash` signed under the old key.
4. All subsequent anchors use the new key.
5. **Do not delete the old public key** — entries signed under it must
   remain independently verifiable for the retention period (NIS2 Art.
   23 recommends ≥ 2 years; consult your regulator).

## Known limitations in v1.0.0

| Limitation | Impact | Tracked in |
|---|---|---|
| Server-side `X-Citadel-Signature` verification not enforced | A peer inside the trusted network can spoof an arbitrary source field on a Kerkese | v1.1 — middleware that rejects unsigned or badly-signed requests |
| Anchor keys in env vars, not HSM | A host compromise leaks the long-term anchor key | v1.1 for Vault integration, v1.2 for HSM |
| Single-writer WORM chain | Horizontal scale is active/passive only | v2.0 — sharded multi-writer chains by `project_id` |
| No forward secrecy for anchors | Long-term compromise of the anchor key retroactively weakens older entries' non-repudiation | v2.0 — per-epoch anchor keys |
| No webhook `event_id` deduplication | A replayed event with a fresh timestamp and valid signature is processed twice | v1.1 |

## Compliance mapping

| NIS2 Article 21(2) measure | How CITADEL contributes |
|---|---|
| (a) Risk analysis and information system security policies | Role-action policy is machine-readable and WORM-logged |
| (b) Incident handling | HARD_STOP decisions trigger automatic P1 incidents via IRFlow |
| (c) Business continuity and crisis management | Anchored WORM chain provides cryptographic evidence of what the system was doing before an incident |
| (h) Policies on cryptography and encryption | TripleHash + Ed25519 anchors are documented here and in the codebase; no hand-rolled primitives |
| (i) Human resources security and access control | SoD enforced by architecture (Gate 2), not by HR policy alone |

## Related

- [Reporting a vulnerability](../SECURITY.md)
- [Ecosystem-wide maturity tiers](../../docs/security-maturity.md)
- [Layered defence model](../../docs/security-architecture.md)
