# ADR-011: Post-Quantum Cryptographic Agility

**Status:** Proposed
**Date:** 2026-04-20
**Deciders:** core-maintainers, security-team, citadel-maintainers
**Supersedes:** —
**Related:** [ADR-010 VertGuard Platform Strategy](./ADR-010-vertguard-platform-strategy.md), [citadel/docs/chain-anchor.md](../citadel/docs/chain-anchor.md), [citadel/docs/triple-hash.md](../citadel/docs/triple-hash.md)

---

## Context

In August 2024, NIST finalised three post-quantum cryptographic
standards:

- **FIPS 203 — ML-KEM** (Kyber): key encapsulation mechanism
- **FIPS 204 — ML-DSA** (Dilithium): digital signature algorithm
- **FIPS 205 — SLH-DSA** (SPHINCS+): hash-based signature alternative

These replace RSA, ECDSA, and ECDH for scenarios where future
quantum-capable adversaries could compromise today's encrypted traffic
or forge today's signatures.

### Threat timeline

| Year | Event (estimated) |
|---|---|
| 2024 | NIST PQC standards finalised |
| 2026 (now) | Harvest-now-decrypt-later attacks are well-documented |
| 2027-2029 | EU (BSI, ANSSI, ENISA) expected to mandate PQC for new systems |
| 2028-2030 | NIS3 likely to mandate PQC migration for essential entities |
| 2030-2033 | RSA-2048 and ECC considered "suspect" by security community |
| 2033-2036 | First credible public break of RSA-1024 or ECC-192 (speculative) |

### Current opensecstack cryptographic surface

| Primitive | Usage | Quantum-safe? | Priority |
|---|---|:-:|:-:|
| SHA-256 (WORM chain_hash) | Chain integrity | ✓ (reduced security) | Medium |
| SHA-512 (TripleHash) | Defence-in-depth | ✓ (reduced security) | Medium |
| BLAKE3 (TripleHash) | Defence-in-depth | ✓ (reduced security) | Medium |
| **Ed25519** (chain anchors, SDK webhooks) | Authenticity | **✗ Vulnerable** | **HIGH** |
| HMAC-SHA256 (webhooks, Kerkese) | Integrity + replay protection | ✓ | Low |
| **X25519** (future key exchange) | Confidentiality | **✗ Vulnerable** | **HIGH** |
| **X.509 / RSA / ECDSA** (C2PA content provenance, VertGuard) | Authenticity | **✗ Vulnerable** | **HIGH** |

Without a migration plan, the opensecstack ecosystem's
tamper-*resistance* guarantee (anchor signatures) becomes vulnerable
as soon as cryptographically relevant quantum computers exist —
projected 2030-2036 window.

### Why agility, not just migration

A single "swap Ed25519 for ML-DSA" migration would work technically
but fails operationally because:

1. **Long-tail auditing** — WORM entries from 2026 must verify with
   2026-era pubkeys for their entire retention window (often 7-10
   years). Historical pubkeys remain valid even after rotation.
2. **Multi-algorithm audits** — by 2030, evidence bundles will contain
   anchors from different signature eras. Verifiers must handle both.
3. **Unknown future primitives** — ML-DSA itself could be broken by
   2040. A flexible design accommodates another swap.

The decision is not "migrate" but "**make migration cheap, repeatable,
and auditable**."

## Decision

Adopt **cryptographic agility** as a first-class design principle
across the opensecstack ecosystem, with a phased migration plan
targeting PQC-default by v3.0 (~2030).

### Four design commitments

#### 1. Hash agility

Every on-chain digest stores an **algorithm identifier** alongside
the digest bytes. The TripleHash structure (SHA-256 + SHA-512 +
BLAKE3) extends to accept additional primitives without breaking
older entries.

Proposed on-disk format for new entries:

```
digest_version: u8       // 1 = legacy TripleHash, 2 = QuintHash, 3 = ...
digest_bytes:   []byte   // variable length based on version
```

Verifiers reject unknown versions — forward compatibility is
intentional, so unsupported future versions fail fast rather than
silently misverify.

#### 2. Signature agility

Chain anchors and webhook signatures carry an **algorithm identifier**
field:

```json
{
  "signature": {
    "alg":   "ed25519",       // or "ml-dsa-65", "ml-dsa-87", "slh-dsa-sha2-256s"
    "value": "<hex>"
  }
}
```

A single chain can contain anchors signed by different algorithms
across its lifetime. Auditors verify each anchor with the algorithm
declared in its envelope.

#### 3. Hybrid signatures during transition

From v2.0 (2028) through v3.0 (~2030), every new anchor is signed
with **both** Ed25519 **and** ML-DSA. Verifier accepts either
(configurable; default "require at least one"). This provides:

- **Backward compatibility** with existing Ed25519-only verifiers.
- **Forward protection** against quantum adversaries (ML-DSA holds if
  Ed25519 is broken).

Hybrid mode adds ~30-100 µs per anchor (ML-DSA sign is slower than
Ed25519) — negligible compared to the 4.22 ms WORM append cost.

#### 4. Pubkey registry evolution

Each pubkey in the registry (`citadel/SECURITY.md` → pubkey section)
carries metadata that identifies its algorithm:

```yaml
- id:         citadel-anchor-2026Q1
  alg:        ed25519
  pubkey:     <hex>
  issued:     2026-01-01
  revoked:    null
  replaced_by: null

- id:         citadel-anchor-2028Q1-ml-dsa
  alg:        ml-dsa-65
  pubkey:     <hex>
  issued:     2028-01-01
  revoked:    null
```

Old pubkeys **never** disappear — they continue to verify historical
anchors signed with them, even after the algorithm itself is
superseded.

### Phased migration timeline

| Phase | Version | Scope | Year |
|---|---|---|---|
| **0 — Foundation** | v1.0.0 (current) | TripleHash + Ed25519 anchors. No agility yet. Immutable baseline for future verifiers. | 2026 |
| **1 — Agility ADR-enforced** | v1.1 | Add `digest_version` + `signature.alg` fields to all new entries. Existing entries unchanged. Verifiers read both legacy + versioned formats. | 2026-2027 |
| **2 — Hybrid signatures** | v2.0 | Every new anchor signed with Ed25519 **and** ML-DSA-65. Webhook signatures gain optional ML-DSA alongside HMAC-SHA256. | 2028 |
| **3 — QuintHash** | v2.5 | Extend TripleHash to include 2 PQ-resistant primitives (candidates: SLH-DSA-based hash, a lattice-hash). Becomes default for new entries. Legacy TripleHash still verifiable. | 2029 |
| **4 — PQC default** | v3.0 | ML-DSA becomes the default anchor signature. Ed25519 support retained for verification of historical anchors. New deployments use PQ-only. Aligned with NIS3 transposition (2030-2032). | 2030 |
| **5 — Sunset Ed25519 signing** | v4.0 | Ed25519 no longer usable for new anchors. Verification of historical anchors remains supported indefinitely. | 2033 |

### Library strategy

| Need | Library | Notes |
|---|---|---|
| ML-DSA (Dilithium) in Go | `github.com/cloudflare/circl/sign/dilithium` | Cloudflare's post-quantum-aware curve library; production-grade |
| ML-KEM (Kyber) in Go | `github.com/cloudflare/circl/kem/kyber` | Same provider |
| ML-DSA in Rust | `pqcrypto-dilithium` (pqcrypto crates) | Reference implementation wrappers |
| Hybrid signatures | Custom wrapper in `sdk/go/pqsign` | To be built Phase 1 |
| SLH-DSA (for hash-based signatures if needed) | TBD — evaluate when NIST finalises parameter sets for stateless variants | Decision deferred to v2.5 |

**vantage-hash** (the Rust crate extracted in Phase 5 Tier A) ships
PQC-aware hash compositions as a first-class feature — it will be
the canonical TripleHash/QuintHash implementation for the ecosystem.

## Alternatives considered

### Alternative A: Wait for NIS3 mandate before migrating

- **Rejected** because: harvest-now-decrypt-later attacks are active
  today; NIS3 mandate expected 2030-2032 leaves insufficient
  engineering runway if started reactively; agility ADR itself is
  low-cost now (design decision, not implementation).

### Alternative B: Replace Ed25519 with ML-DSA in v2.0 (hard cut)

- **Rejected** because: breaks every existing verifier, forces
  clients through a coordinated cut-over, and loses the hybrid
  period's safety. Hybrid mode (Decision point 3) is strictly better.

### Alternative C: Full homomorphic / zero-knowledge crypto stack

- **Rejected** for ecosystem-level adoption because: performance
  costs are orders of magnitude higher than PQC signatures, the
  threat model for opensecstack is integrity + authenticity (which
  PQC handles directly), and the tooling maturity isn't there yet.
  Leave as future Phase 5+ research.

### Chosen: Agility-first with hybrid transition period

Minimal change now (schema fields for algorithm identifiers), hybrid
signatures from 2028, PQ-default by 2030. Gives the ecosystem a
10-year runway with no breaking migrations.

## Consequences

### Positive

- **Future-proofs the audit chain.** Historical evidence remains
  verifiable for its full retention window even as primitives age out.
- **Survives algorithm breaks** — if ML-DSA itself is broken in 2040,
  the agility infrastructure lets us swap to ML-DSA's successor
  without another redesign.
- **NIS3-ready by 2030** — the post-quantum migration story is done
  before NIS3 makes it mandatory.
- **Competitive advantage** — bank-grade audit chains must migrate
  legacy SHA-2-only systems; opensecstack ships PQ-ready by design.
- **Compliance narrative** — "We migrated to PQ before it was
  mandatory" is a strong trust signal for regulated entities.

### Negative

- **Implementation complexity** — agility requires more code than
  hard-coded primitives. Mitigated by `sdk/go/pqsign` centralising
  the algorithm negotiation.
- **Storage overhead** — hybrid signatures double the signature
  bytes per anchor (~128 bytes Ed25519 + ~2.4 KB ML-DSA-65 = 2.5 KB
  per anchor). At 100-entry anchor interval, this is ~0.0025% of
  payload data. Negligible.
- **Verification cost doubles during hybrid period** — each anchor
  verified twice. At 50-80 µs per verification, this is under 200 µs
  per anchor. Negligible against 4.22 ms WORM append.
- **Library dependency growth** — Cloudflare CIRCL, pqcrypto crates.
  Audit hygiene: pinned versions, `go.sum` / `Cargo.lock` enforcement,
  supply-chain attestation.

### Neutral

- **v1.0.0 chain stays untouched** — no retroactive signature changes
  or chain rewrites. Historical Ed25519 anchors remain valid forever.
- **Webhook signatures unchanged until v2.0** — HMAC-SHA256 is not
  quantum-vulnerable; no change needed until separate signed
  webhooks land (Phase 4 VertGuard evidence export).

## Open questions

1. **QuintHash composition** — which two PQ-resistant hashes join
   SHA-256 + SHA-512 + BLAKE3? Lattice-based hash candidates are
   maturing; decide at v2.5 design time (2029).
2. **Pubkey distribution mechanism** — today pubkeys are pasted in
   `citadel/SECURITY.md`. For PQ pubkeys (~1.5 KB each), a dedicated
   `pubkeys.yaml` registry or a DNS-based published key record might
   be better ergonomics. Revisit v1.1.
3. **Hardware signing** — HSM/PKCS#11 support for ML-DSA is nascent
   (as of 2026). Timeline for HSM-backed PQ anchor keys depends on
   vendor rollout (Thales, Utimaco, AWS CloudHSM, GCP Cloud KMS). Not
   required for v1.x; reassess for v2.0.
4. **QUIC / TLS 1.3 hybrid KEMs** — opensecstack platforms talk
   HTTP/REST, TLS handled by ingress. If we deploy mesh mTLS in v2.0
   (Istio/Linkerd), hybrid KEMs (X25519 + ML-KEM) come into scope
   then.

## Implementation checklist

### Phase 1 — v1.1 (2026-2027)

- [ ] This ADR approved.
- [ ] `sdk/go/pqsign` package scaffolded (agility wrapper interface).
- [ ] `citadel/internal/db/worm.go` — add `digest_version` column to
      `worm_entries`; default 1 for existing entries.
- [ ] `citadel/internal/db/worm.go` — add `signature.alg` field to
      `chain_anchors`; default `ed25519` for existing entries.
- [ ] Chain verifier accepts both legacy-format and versioned-format
      anchors.
- [ ] `docs/compatibility-matrix.md` — add PQC migration status column.

### Phase 2 — v2.0 (2028)

- [ ] Cloudflare CIRCL pinned in `go.mod`.
- [ ] Hybrid anchor signing enabled (feature flag `CITADEL_HYBRID_ANCHORS=true`
      defaults true for new deployments).
- [ ] `pubkeys.yaml` registry published in `citadel/SECURITY.md`.
- [ ] External auditor walkthrough updated with hybrid verification steps.

### Phase 3 — v2.5 (2029)

- [ ] QuintHash composition finalised (pick 2 PQ-resistant primitives).
- [ ] `vantage-hash` crate ships QuintHash as default for new entries.
- [ ] Chain verifier supports QuintHash alongside TripleHash.

### Phase 4 — v3.0 (2030)

- [ ] ML-DSA becomes default anchor algorithm.
- [ ] Ed25519 deprecated for signing new anchors (still verified for
      historical anchors).
- [ ] NIS3 compliance statement updated to reference PQ alignment.

### Phase 5 — v4.0 (2033)

- [ ] Ed25519 signing removed from new deployments.
- [ ] Historical verification path remains.
- [ ] Audit: no production deployment still relying on Ed25519 signing.

## References

- NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- NIST FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- Cloudflare CIRCL: https://github.com/cloudflare/circl
- BSI PQ Migration Handbook (2023): reference for EU regulator
  posture on timelines
- Signal's PQXDH protocol (2023): precedent for hybrid classical + PQ
  design in production systems

## Review

This ADR is foundational for the ecosystem's 10-year roadmap. Review
at the start of each phase (v1.1, v2.0, v2.5, v3.0, v4.0). A new ADR
supersedes this one when NIST publishes a successor to ML-DSA or the
hash composition of QuintHash is finalised.
