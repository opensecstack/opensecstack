# Post-Quantum Roadmap

Operator-facing summary of how OpenSecStack migrates to post-quantum
cryptography. This is the practical deployment guide; for the full
architectural rationale, see [ADR-011 Post-Quantum Agility](../adrs/ADR-011-post-quantum-agility.md).

## Why this matters to you

Three facts, no hype:

1. NIST finalised post-quantum standards (ML-KEM, ML-DSA, SLH-DSA) in
   August 2024.
2. Quantum computers capable of breaking RSA-2048 / Ed25519 are
   plausibly **2030-2036** — credible enough that
   harvest-now-decrypt-later attacks are already happening.
3. NIS3 (expected 2030-2032) is likely to mandate PQC migration for
   essential entities.

**If your deployment has a 7-year evidence retention, anything you
sign today with Ed25519 must still verify in 2033** — when the
algorithm may be broken. OpenSecStack is migrating so your historical
audits remain attestable.

## What's at risk today vs tomorrow

| What it protects | Today | After quantum break |
|---|---|---|
| WORM chain hash integrity (SHA-256 + SHA-512 + BLAKE3) | ✓ Safe | ✓ Safe (reduced security margin, but core guarantee holds) |
| HMAC-SHA256 on webhooks | ✓ Safe | ✓ Safe |
| **Ed25519 chain anchor signatures** | ✓ Safe | **✗ Forgeable** — historical evidence loses tamper-resistance |
| **X.509 / ECDSA in C2PA provenance** (VertGuard) | ✓ Safe | **✗ Forgeable** |
| TLS at ingress (X25519 / ECDHE) | ✓ Safe | **✗ Past sessions decryptable** (harvest-now-decrypt-later) |

The items in **bold** are where we migrate first.

## Your migration, version by version

### Today (v1.0.0)

- All anchors signed with Ed25519.
- Chain integrity via TripleHash.
- No action needed. Your deployment is secure against classical
  adversaries.

### v1.1 (late 2026)

- Add schema fields: every new anchor carries an algorithm
  identifier (`signature.alg`), every new WORM entry carries a
  digest version (`digest_version`).
- **No breaking change.** Historical entries stay valid. Verifiers
  are updated to read both old and new formats.
- **Your action:** upgrade to v1.1 when it ships; that's all.

### v2.0 (2028)

- **Hybrid signatures.** Every new anchor is signed with **both**
  Ed25519 and ML-DSA-65. Verifier accepts either.
- Storage impact: ~2.5 KB per anchor (was ~64 bytes). At 100-entry
  anchor interval, total overhead ~0.0025% of payload.
- Verification cost: ~2x per anchor (still < 1 ms, negligible vs
  4.22 ms WORM append).
- **Your action:** upgrade to v2.0. Feature flag
  `CITADEL_HYBRID_ANCHORS` defaults to true for new deployments.
  Existing deployments can stage the rollout.

### v2.5 (2029)

- **QuintHash.** Default hash composition extends from 3 primitives
  (SHA-256 + SHA-512 + BLAKE3) to 5, including 2 PQ-resistant
  candidates.
- New WORM entries use QuintHash; legacy TripleHash entries still
  verify.
- **Your action:** no action for existing data. New writes adopt
  automatically.

### v3.0 (2030)

- **ML-DSA becomes the default.** Ed25519 support retained for
  verifying historical anchors but not used for new ones.
- Aligned with expected NIS3 transposition window.
- **Your action:** upgrade to v3.0 before your regulator's PQC
  deadline.

### v4.0 (2033)

- Ed25519 **signing** removed. Historical anchors still verified.
- **Your action:** confirm no part of your deployment still relies on
  Ed25519 signing (there shouldn't be by now).

## Deployment guidance by tier

### Tier 1 (standard deployment)

Follow the default version progression. Auto-upgrades to new anchor
algorithms as they become default. No special migration work.

### Tier 2 (elevated deployment)

Test the migration in staging before production. Specifically:

- v1.1 → v2.0: verify hybrid signatures produce compatible chain
  anchors on both sides of your deployment (primary + standby).
- v2.5: confirm QuintHash entries verify correctly when older
  verifiers in your infrastructure still read them.
- v3.0: plan for pubkey redistribution — new ML-DSA pubkeys are
  ~1.5 KB each, larger than Ed25519. Update any pubkey caching layers.

### Tier 3 (high-assurance)

- Consider HSM-backed ML-DSA anchor keys when vendor support matures
  (2028-2030). Until then, in-process keys with proper secret-manager
  rotation.
- Archive anchor pubkeys indefinitely per
  [citadel/docs/evidence-custody.md](../citadel/docs/evidence-custody.md).
  Every pubkey that ever signed a retained anchor must remain
  available to verifiers.
- Consider publishing anchor pubkeys via DNSSEC or a transparency log
  for independent third-party verification.

## What you can do *before* v1.1 ships

Even today, you can prepare:

1. **Inventory your anchor pubkeys.** Know which pubkey signed which
   range of anchors. You'll need this for the hybrid period.
2. **Verify your backup strategy covers pubkeys.** Losing a pubkey
   means losing the ability to verify all anchors signed with it.
3. **Track NIST FIPS 203/204/205 final parameters.** No surprises
   expected, but confirm once v1.1 ships.
4. **Educate your auditors** on the migration timeline. "We'll be
   hybrid-signing by 2028 and PQ-default by 2030" is a compliance
   talking point worth having ready.

## FAQ

### "Can I just keep using Ed25519 forever?"

Through ~2028-2029, yes. After that, new anchors signed Ed25519-only
will be considered suspect by any auditor paying attention to the
threat landscape. After 2033, v4.0 removes the option entirely.

### "What if ML-DSA itself is broken?"

That's exactly why we adopt *agility*, not just migration. The
`signature.alg` field means we can add a successor (ML-DSA
replacement, SLH-DSA, or a lattice-based alternative) without
redesigning. Historical ML-DSA-signed anchors remain verifiable with
archived ML-DSA pubkeys.

### "Does this break my SDK clients?"

No. SDK clients verify webhook signatures (HMAC-SHA256, unaffected by
quantum). The anchor verification path is only used when a consumer
fetches `/worm/verify` — and that endpoint returns the algorithm
identifier, so SDK clients just need to know which verification code
path to call. We'll ship updated SDK versions alongside each CITADEL
version.

### "Can I opt out?"

Yes, via config (`CITADEL_HYBRID_ANCHORS=false`). Not recommended —
the cost is negligible and the benefit accrues over years. But if
your threat model explicitly rules out quantum adversaries for a
specific deployment, opt-out is supported.

### "What about TLS, mesh mTLS, gRPC?"

Handled by your ingress / service mesh (Istio, Linkerd, Envoy).
Hybrid TLS 1.3 KEMs (X25519 + ML-KEM) are landing across those
projects 2026-2028. When you enable hybrid TLS at your ingress,
OpenSecStack platforms benefit transparently.

### "Is VertGuard affected differently?"

Yes — VertGuard's Module 1 (Media Authenticity) uses C2PA, which is
currently X.509 / ECDSA based. The C2PA spec is developing its own
PQC migration; VertGuard tracks that spec and will support hybrid
C2PA manifests when the spec lands (~2028).

## Timeline summary

| Year | Milestone | Your burden |
|---|---|---|
| 2026 | v1.0 shipped with Ed25519 | Nothing — deploy as-is |
| 2026-2027 | v1.1 with schema agility fields | Routine upgrade |
| 2028 | v2.0 with hybrid anchors | Routine upgrade; storage grows ~0.003% |
| 2029 | v2.5 with QuintHash | Routine upgrade |
| 2030 | v3.0 with PQ-default | Standard NIS3-compliance upgrade |
| 2033 | v4.0 with Ed25519-signing retired | Confirm nothing broken |

## Related

- [ADR-011 Post-Quantum Agility](../adrs/ADR-011-post-quantum-agility.md) — full technical rationale
- [CITADEL chain anchor spec](../citadel/docs/chain-anchor.md)
- [CITADEL TripleHash spec](../citadel/docs/triple-hash.md)
- [CITADEL evidence custody](../citadel/docs/evidence-custody.md) — pubkey retention requirements
- [security-maturity.md](./security-maturity.md) — tier-specific guidance
- NIST PQC: https://csrc.nist.gov/projects/post-quantum-cryptography
