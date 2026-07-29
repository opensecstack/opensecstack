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
   inputs, and signatories are recorded. The signatory identity (sinauth
   token) and non-repudiation evidence (Ed25519 `sig_operator`/
   `sig_verifier`) mechanisms behind this are implemented ([ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md),
   [ADR-005](../adrs/005-sinauth-identity-bridge.md)) but only *enforced*
   — i.e. capable of blocking a decision — once `citadel.enforce_identity`/
   `citadel.enforce_signatures` are turned on, and both **default to
   `false`** today. See [Known limitations](#known-limitations-in-v100).
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
| The `X-Citadel-Signature` HMAC secret on `POST /worm/emit` is not leaked to an attacker | v1.0.0 does not server-side-enforce this webhook-transport signature ([ADR-002](../adrs/002-hmac-sha256-event-signing.md)); it relies on network-layer trust. See "Known limitations" below. This is a separate mechanism from the Kerkese-level Ed25519 signatures below |
| `citadel.enforce_identity`/`citadel.enforce_signatures` being off does not get exploited before they're turned on | Both flags default `false` (soft mode) — see "What CITADEL enforces" and "Known limitations" below. Until enabled, a Kerkese with a forged `actor.user_id`/`verifier.user_id` and no token/signature still produces a decision (with `WARN` gates, not a `REFUSE`) |
| Operators rotate the WORM anchor key on compromise | CITADEL has no automatic rotation; see [Keys](#keys) |
| PostgreSQL is not writable by the attacker | A DB-level write bypass would allow history rewrites — this is always true of any audit log |

## What CITADEL enforces

| Control | Mechanism |
|---|---|
| **Separation of Duties (SoD)** | MARSHAL Gate 3 (NDS) unconditionally `HARD_STOP`s any Kerkese where `sod.operator_user_id == sod.verifier_user_id`, or where Operator/Verifier share a role privilege group. This is the main defence against a single compromised operator pushing arbitrary actions, and it is **not** behind a soft-mode flag |
| **Role-to-action policy (RBAC)** | MARSHAL Gate 2 (AuthZ) checks a fixed matrix (`rbacMap` in `internal/marshal/types.go`): which roles may submit which `action.type` values. This is a hard, unconditional check — but the map currently only covers legacy action types, not the 9 producer platforms wired this session. See [Known limitations](#known-limitations-in-v100) |
| **Identity authentication (sinauth)** | MARSHAL Gate 1/Gate 3 verify `actor_token`/`verifier_token` — real sinauth-issued bearer JWTs — against sinauth's JWKS (`internal/auth.SinauthVerifier`). Real and implemented, but only *enforced* (i.e. blocks the decision on failure) when `citadel.enforce_identity=true`, which **defaults to `false`**. See [ADR-005](../adrs/005-sinauth-identity-bridge.md) |
| **Non-repudiation (Ed25519 Kerkese signatures)** | MARSHAL Gate 1/Gate 3 verify `sig_operator`/`sig_verifier` — Ed25519 signatures over `CanonicalPayload(k)` — against the `signing_keys` registry (self-custody keys via `citadel keygen`, never held by CITADEL). Persisted on the WORM entry as long-term evidence, satisfying the IEEE paper's Definition 2. Only *enforced* when `citadel.enforce_signatures=true`, which **defaults to `false`** — no producer has per-user signing UX yet. See [ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md) |
| **Behavioral heuristics (AUGUR)** | MARSHAL Gate 4 applies 3 rules: off-hours action → `WARN`; >10 actions by one actor in 5 minutes → `WARN`; `DATA_EXPORT` without `incident_id` → unconditional `HARD_STOP`. There is no general per-`(actor, project)` token-bucket rate limiter today |
| **Append-only audit chain** | WORM entries are inserted only — there is no UPDATE or DELETE path in `internal/db/worm.go`. Rewriting history requires direct DB-level write access |
| **TripleHash integrity** | See [architecture.md § WORM chain](./architecture.md#worm-chain). Attacker needs collisions in SHA-256 + SHA-512 + BLAKE3 simultaneously |
| **Ed25519 anchor signatures** | Periodic signed snapshots of `chain_hash` turn offline audit into a constant-time "does the signature match?" check. A different key from the per-Kerkese `sig_operator`/`sig_verifier` signatures above — see [Keys](#keys) |

## Threat model

### In scope

| Threat | Mitigation |
|---|---|
| Single compromised operator signs off their own action | SoD (Gate 3/NDS) unconditionally `HARD_STOP`s a matching `operator_user_id`/`verifier_user_id`, regardless of enforce-flag state |
| A caller claims an identity it doesn't hold (spoofed `actor.user_id`) | Gate 1/Gate 3 sinauth token + Ed25519 signature checks — **only actually blocks the decision once `enforce_identity`/`enforce_signatures` are turned on**; today it warns |
| Compromised service account floods governance queue with high-frequency actions | AUGUR (Gate 4) rule_02 flags — but only `WARN`s; there is no hard per-actor rate limit today |
| `rbacMap` drift (a role is granted an action type it shouldn't have) | `rbacMap` is a static Go map compiled into the binary, not a runtime-editable policy — changing it requires a code change and redeploy, so drift is a code-review problem, not a runtime one |
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

CITADEL owns these long-lived secrets/credentials:

| Key | Purpose | Rotation |
|---|---|---|
| `CITADEL_HMAC_SECRET` | Verifying `X-Citadel-Signature` on inbound `POST /worm/emit` calls (not yet server-side enforced — see [Known limitations](#known-limitations-in-v100)) | Quarterly (recommended). Rotate any time the secret might have leaked. Support for overlapping-secret windows is v1.1 |
| `CITADEL_CITADEL_MASTER_KEY` (`ANCHOR_KEY`) | Ed25519 private key used to sign periodic chain anchors (`internal/db`, `anchors` table) | Annual (recommended). Old public keys must remain verifiable forever — never discard them; publish in the anchor log with a `key_rotation` event |
| `CITADEL_DB_PASSWORD` (part of `CITADEL_DB_URL`) | PostgreSQL credential | Per standard DB password policy (quarterly) |

CITADEL does **not** own a fourth kind of key: per-user **Operator/Verifier
Ed25519 signing keys** (`sig_operator`/`sig_verifier` — see
[ADR-004](../adrs/004-operator-verifier-ed25519-signatures.md)) are
deliberately self-custodied. `citadel keygen` generates the keypair on the
Operator's/Verifier's own machine; only the *public* key is ever sent to
CITADEL, via `POST /api/v1/keys/register`, and stored in the `signing_keys`
table. CITADEL never sees, stores, or can reconstruct the private key —
compromise of CITADEL's database does not expose any Operator's/Verifier's
private key. Revocation is application-level (`RevokeKey`, sets
`revoked_at`), not a CITADEL-issued rotation.

The HMAC secret, anchor key, and DB password live in environment variables
in v1.0.0. For production-grade key hygiene, source them from a secret
manager (Vault, AWS KMS, GCP Secret Manager). See
[security-maturity.md](../../docs/security-maturity.md#tier-2--elevated-deployment)
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
| `enforce_identity` and `enforce_signatures` both default `false` | A Kerkese with a missing/invalid `actor_token`/`verifier_token`/`sig_operator`/`sig_verifier` still gets a decision (`WARN` gates, not `REFUSE`) — identity and non-repudiation are implemented but **not enforced** by default | [ADR-006](../adrs/006-split-enforce-identity-and-signatures.md); turning them on requires apiguard's `require_approval` (or equivalent) by default, a real second-approver flow for threatflow, and at least one producer implementing Ed25519 signing |
| `rbacMap`/`roleGroupMap` do not cover most real producer platforms | 9 producer platforms (apiguard, irflow, threatflow, opencsirt, openscrub, securelab, community, cyberpath, nis2compass) submit real Kerkese requests, but their real `action.type`/role values are largely missing from `internal/marshal/types.go`'s `rbacMap` — most of those calls `REFUSE` at Gate 2 (AuthZ) today, unconditionally (this gate has no soft mode) | Open — not yet scheduled; see [architecture.md](./architecture.md) |
| Server-side `X-Citadel-Signature` verification not enforced (`POST /worm/emit`) | A peer inside the trusted network can spoof an arbitrary source field on a webhook-style WORM emit. Distinct from the Kerkese-level Ed25519 signatures above, which now exist for `/marshal/evaluate` | v1.1 — middleware that rejects unsigned or badly-signed requests |
| Anchor keys in env vars, not HSM | A host compromise leaks the long-term anchor key | v1.1 for Vault integration, v1.2 for HSM |
| Single-writer WORM chain | Horizontal scale is active/passive only | v2.0 — sharded multi-writer chains by `project_id` |
| No forward secrecy for anchors | Long-term compromise of the anchor key retroactively weakens older entries' non-repudiation | v2.0 — per-epoch anchor keys |
| No webhook `event_id` deduplication | A replayed event with a fresh timestamp and valid signature is processed twice | v1.1 |
| No general per-`(actor, project)` rate limiter | AUGUR (Gate 4) only `WARN`s on high frequency; there is no hard token-bucket enforcement | Not yet scheduled |

## Compliance mapping

| NIS2 Article 21(2) measure | How CITADEL contributes |
|---|---|
| (a) Risk analysis and information system security policies | Role-action policy (`rbacMap`) is machine-readable; every decision it drives is WORM-logged, though the map itself is compiled into the binary, not runtime-editable |
| (b) Incident handling | HARD_STOP decisions trigger automatic P1 incidents via IRFlow |
| (c) Business continuity and crisis management | Anchored WORM chain provides cryptographic evidence of what the system was doing before an incident |
| (h) Policies on cryptography and encryption | TripleHash + Ed25519 anchors + per-Kerkese Ed25519 signatures are documented here and in the codebase; no hand-rolled primitives |
| (i) Human resources security and access control | SoD enforced by architecture (Gate 3/NDS), unconditionally, not by HR policy alone; identity is authenticated via sinauth (Gate 1/Gate 3), enforced once `enforce_identity` is turned on |

## Related

- [Reporting a vulnerability](../SECURITY.md)
- [Ecosystem-wide maturity tiers](../../docs/security-maturity.md)
- [Layered defence model](../../docs/security-architecture.md)
