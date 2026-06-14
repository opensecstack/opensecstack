# Security Policy — CITADEL

CITADEL is the governance and audit-chain service for the OpenSecStack
ecosystem. A vulnerability here affects every platform that relies on
CITADEL for dual-control authorisation or tamper-evident logging, so
please treat the disclosure process seriously.

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Preferred channels, in order:

| Channel | Address |
|---|---|
| GitHub Security Advisory | <https://github.com/opensecstack/opensecstack/security/advisories/new> (private) |
| Email | security@opensecstack.org |
| PGP-encrypted email | Key via `keybase.io/opensecstack` |

### Scope

**In scope**:

- CITADEL handler code (`internal/api`, `internal/marshal`, `internal/db`)
- WORM chain integrity (TripleHash, anchor signing, sequence invariants)
- Any issue that would let a caller bypass a MARSHAL gate, forge a
  `sequence_num`, or mutate a historical WORM entry without detection
- Configuration defaults that silently weaken the security posture

**Out of scope**:

- PostgreSQL vulnerabilities (report upstream; we'll track)
- `golang.org/x/crypto` implementation bugs (report upstream)
- DDoS via unauthenticated endpoints (Layer 2 concern — handled by
  upstream WAF / rate limiter; not CITADEL's job)

### Response SLA

| Action | Timeline |
|---|---|
| Acknowledgement | 48 h |
| Initial assessment | 7 days |
| Fix for CRITICAL (chain bypass, sequence forgery) | 14 days |
| Fix for HIGH (gate bypass, signature spoof) | 30 days |
| Fix for MEDIUM / LOW | 90 days |
| Public disclosure | After fix release + 30 days for upgrades |
| CVE assignment | For all confirmed issues with user impact |

## Threat Model (summary)

The full model lives in [docs/security-model.md](./docs/security-model.md).
In brief:

| Threat | Defence |
|---|---|
| Single compromised operator approves their own action | MARSHAL Gate 2 (SoD) rejects when `actor == verifier` |
| Silent policy drift | Policy updates themselves go through MARSHAL and are WORM-logged |
| Rewriting history after an incident | TripleHash (SHA-256 + SHA-512 + BLAKE3) + Ed25519 anchor signatures |
| Runaway automation flooding the queue | MARSHAL Gate 4 token bucket |
| Emergency override abuse | Gate 5 demands non-empty `emergency_justification`; justification is audit-visible |

## Key management

CITADEL owns three long-lived secrets:

| Key | What it does | Rotation |
|---|---|---|
| `CITADEL_HMAC_SECRET` | Verifies the `X-Citadel-Signature` on inbound HMAC-signed requests | Quarterly, or immediately on suspected compromise |
| `CITADEL_ANCHOR_KEY` | Ed25519 signing key for periodic WORM chain anchors | Annually, or immediately on suspected compromise |
| `CITADEL_DB_PASSWORD` | PostgreSQL credential | Per standard DB policy |

In v1.0.0 all three live in environment variables. For production-grade
deployments, source them from a secret manager (HashiCorp Vault, AWS
Secrets Manager, GCP Secret Manager). See the ecosystem
[security-maturity tiers](../docs/security-maturity.md) for the
tier-by-tier recommendation.

### Anchor key rotation runbook

1. Provision a new Ed25519 key pair at the secret manager.
2. Roll the running CITADEL instance so it picks up the new key.
3. CITADEL emits a `key_rotation` WORM event referencing:
   - The last `chain_hash` signed under the old key.
   - The new public key.
4. All subsequent anchors are signed under the new key.
5. **Retain the old public key indefinitely** in your key archive —
   historical anchors must remain independently verifiable for the
   full retention period (NIS2 Art. 23 suggests ≥ 2 years; consult
   your regulator).

### Emergency revocation

If the anchor key is known-compromised:

1. Stop CITADEL's anchor job immediately.
2. Revoke the key at the secret manager.
3. Provision a replacement (see rotation runbook above).
4. Independently sign a "break-glass" notice with the replacement key
   stating the compromise window — auditors will need this to judge
   which historical entries were anchored under a trustworthy key.

## WORM integrity failure runbook

If `GET /api/v1/worm/verify` returns `valid: false`:

1. **Stop writes immediately.** Take CITADEL out of the load balancer
   pool — further emits will extend a corrupt chain.
2. Note the `break_at` entry ID. Everything **before** that point is
   still trustworthy if the chain verified up to it.
3. Pull a forensic snapshot of the WORM table (pg_dump of the relevant
   rows) to preservation storage before touching anything.
4. Compare `chain_hash` values in the DB against the most recent Ed25519
   anchor to narrow the window of possible tampering.
5. Do **not** attempt to rewrite entries to "fix" the chain — any such
   fix would be indistinguishable from the original tampering. The
   correct path is to fork a new chain from the last good entry and
   document the break.

## Known limitations in v1.0.0

- **Server-side `X-Citadel-Signature` verification is advisory**, not
  enforced. Relies on network-layer trust (private subnet, service
  mesh). Enforcement lands in v1.1.
- **No forward secrecy** for WORM anchors — a long-term compromise of
  the anchor key retroactively weakens non-repudiation of older
  entries. Per-epoch anchor keys are scheduled for v2.0.
- **Single-writer chain** — two concurrent CITADEL instances emitting
  to the same chain produce a divergence. Active/passive failover is
  supported via external leader election (Consul, Kubernetes Lease).
- **Webhook deduplication not yet implemented** — a replay with a
  fresh timestamp and a valid signature is accepted twice. Tracked for
  v1.1.

## Supported versions

| Version | Status |
|---|---|
| 1.0.x | Actively supported — security fixes land here |
| pre-1.0 | Development snapshots; do not run in production |

## Further reading

- [docs/security-model.md](./docs/security-model.md) — full threat model
- [docs/architecture.md](./docs/architecture.md) — WORM chain and MARSHAL internals
- [Ecosystem security maturity tiers](../docs/security-maturity.md)
- [Root SECURITY.md](../SECURITY.md) — ecosystem-wide policy
