# TripleHash — Composite Digest

TripleHash is CITADEL's per-entry content-addressable digest. Every
WORM entry carries a 128-byte hash composed of **three independent
cryptographic hash functions** concatenated together. This document
explains what it is, why three hashes, and how to verify one.

For the WORM chain it feeds into, see [worm-log.md](./worm-log.md).
For the Go implementation, see [internal/db/worm.go:33](../internal/db/worm.go#L33).

## Layout

```
          0                    32                               96           128
          ├──────── SHA-256 ───┼──────── SHA-512 ───────────────┼── BLAKE3 ──┤
          │      32 bytes      │           64 bytes             │  32 bytes  │
```

The on-disk form is hex-encoded — 128 bytes × 2 = **256 hex characters**.

## Computation

```go
h256 := sha256.Sum256(payload)  // 32 bytes
h512 := sha512.Sum512(payload)  // 64 bytes
hB3  := blake3.Sum256(payload)  // 32 bytes

composite := append(h256[:], append(h512[:], hB3[:]...)...)
return hex.EncodeToString(composite)
```

The order is fixed: SHA-256, then SHA-512, then BLAKE3. Any other
ordering yields a different digest and does not validate.

## Why three hashes?

Cryptographic hashes fail in three different ways:

1. **Collision attack** — an attacker finds `H(A) == H(B)` without
   control over A.
2. **Preimage attack** — given `H(A)`, an attacker finds `A`.
3. **Algorithmic break** — a future cryptanalytic advance renders a
   family of hashes unsafe (as happened to MD5 and SHA-1).

TripleHash is resistant to (3) because the three primitives have
**independent design histories**:

| Hash | Family | Design pedigree |
|---|---|---|
| SHA-256 | Merkle–Damgård | NIST FIPS 180-4, widely scrutinised since 2001 |
| SHA-512 | Merkle–Damgård (wider) | Same family but different word size; a break in SHA-256 does not automatically break SHA-512 |
| BLAKE3 | Sponge / Merkle-tree, derived from ChaCha permutation | Completely different internal structure; resistant to extension attacks SHA-2 tolerates |

A hypothetical collision in SHA-256 does not give you a collision in
SHA-512 or BLAKE3 for the same payload. An attacker who wants to
substitute a forged `payload'` for `payload` must find a triple where
`H₁(payload') == H₁(payload)` AND `H₂(payload') == H₂(payload)` AND
`H₃(payload') == H₃(payload)` — the difficulty multiplies, not adds.

## Why these three?

Other triples were considered:

| Candidate | Reason excluded |
|---|---|
| SHA-256 + SHA-3-256 + BLAKE3 | SHA-3 is excellent, but BLAKE3 is faster and has wider library support in Go |
| SHA-256 + SHA-512 + Keccak-256 | Keccak has hardware adoption bias; keeps us tied to Ethereum-style ecosystems |
| SHA-512/256 + BLAKE3 + Argon2 | Argon2 is a KDF, not a hash — including it confuses the semantics |

The chosen combination gives us (a) a NIST-approved primitive for
regulators who require one, (b) a different NIST primitive of different
internal width, (c) a permutation-based alternative with demonstrated
resistance to length-extension attacks.

## Performance

v1.0.0 benchmark (Intel Core i7-7600U, Go 1.24.4, 100-byte payload):

| Component | Time |
|---|---|
| SHA-256 | ~0.35 µs |
| SHA-512 | ~0.55 µs |
| BLAKE3  | ~0.40 µs |
| Hex encode | ~0.22 µs |
| **Total TripleHash** | **1.52 µs / 100-byte payload** |

The SHA-512 implementation in Go's stdlib dominates — moving to a
SIMD-accelerated library could cut it by half, but the absolute
number is well under the 4.22 ms of the surrounding WORM append, so
optimisation doesn't move the needle.

## Verification

To verify a stored entry:

```go
entry := GetWORMEntry(...)
computed := TripleHash(entry.Payload)

if computed != entry.TripleHash {
    // chain is broken at this entry — tampering, or DB corruption
}
```

This is exactly what `VerifyChain` does, for every entry in the
requested range, before the chain-link step. A triple_hash mismatch
means the payload bytes on disk don't match the bytes that were
originally hashed — the only legitimate cause is DB corruption, and
anything else is tampering.

## Space cost

256 hex characters per entry × 1 MiB entries/day × 10 years ≈
1 GB of index for a decade of logs. On modern hardware, this is
negligible.

The alternative — storing all three hashes in separate columns —
would save nothing (same bytes) while adding query complexity.
Storing them concatenated lets the entire triple be matched with a
single `WHERE triple_hash = $1`.

## Limitations

- **Not a MAC.** TripleHash uses no secret key. Two parties with the
  same payload compute the same digest. Authentication comes from the
  Ed25519 chain anchor, not from TripleHash itself.
- **Not length-prefixed.** Payloads of different lengths that happen
  to share the same digest are vanishingly unlikely, but `H("a")`
  and `H("a\n")` differ by design — callers must agree on byte-for-byte
  canonical forms before hashing. CITADEL stores the raw JSON bytes
  it received; do not canonicalise.
- **BLAKE3 dependency.** The `github.com/zeebo/blake3` package is an
  external dependency. A future security advisory in that package
  would affect CITADEL; the dependency is pinned in go.mod and the
  checksum is in go.sum.

## Related

- [WORM log](./worm-log.md) — where TripleHash is used
- [Chain anchor](./chain-anchor.md) — Ed25519 signature that turns
  WORM into a publishable proof chain
- [Architecture § TripleHash rationale](./architecture.md) — design decisions in context
- [Security model](./security-model.md) — threat model TripleHash defends against
