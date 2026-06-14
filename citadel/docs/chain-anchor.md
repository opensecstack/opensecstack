# Chain Anchor — Ed25519-Signed Block Boundaries

A WORM chain with TripleHash + linked chain_hash is **tamper-evident**
against a database-level attacker: changing any byte forces re-hashing
of every subsequent entry, which a simple verification pass catches.
But it is not **tamper-resistant** against an attacker who can also
rewrite the chain_hash values — they would need more work, but the
tail of the chain would re-validate against itself.

Chain anchors close that gap. At a configurable interval, CITADEL
computes an **Ed25519 signature** over the latest chain_hash plus the
sequence_num at which it was taken, and persists it. An auditor
holding the public key can then verify *the anchor* independently —
an attacker who doesn't have the private key cannot forge the
signature no matter how many chain_hashes they rewrite.

For the per-entry digest, see [triple-hash.md](./triple-hash.md). For
the chain-hash linking, see [worm-log.md](./worm-log.md).

## The anchor flow

```
                  every CITADEL_ANCHOR_INTERVAL entries
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      │                            ▼                            │
      │         ┌─────────────────────────────────────┐         │
      │         │  anchor_payload = sequence_num ||   │         │
      │         │                   ts_utc         || │         │
      │         │                   chain_hash      |        │
      │         └─────────────────────────────────────┘         │
      │                            │                            │
      │                            ▼                            │
      │           Ed25519.Sign(master_private_key,              │
      │                        SHA-512(anchor_payload))          │
      │                            │                            │
      │                            ▼                            │
      │        INSERT INTO chain_anchors                        │
      │          (sequence_num, ts_utc, chain_hash, signature)  │
      └────────────────────────────┬────────────────────────────┘
                                   │
                              next entry…
```

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `CITADEL_CITADEL_MASTER_KEY` | — | Ed25519 private key (hex, 64 chars). Never leaves the CITADEL service memory after startup. |
| `CITADEL_CITADEL_ANCHOR_INTERVAL` | `100` | Anchor every N entries. Lower = stronger guarantee, more Ed25519 ops. 100 means every ~100 × 4.22 ms ≈ 0.4 s batch of entries. |

Setting `MASTER_KEY` to an empty or invalid value disables anchor
emission with a warn log. Without anchors, the WORM chain is still
tamper-*evident* but not tamper-*resistant* — do not run production
this way.

## Anchor storage

```sql
CREATE TABLE chain_anchors (
    id           UUID        PRIMARY KEY,
    sequence_num BIGINT      NOT NULL REFERENCES worm_entries(sequence_num),
    ts_utc       TIMESTAMPTZ NOT NULL,
    chain_hash   TEXT        NOT NULL,   -- the chain_hash at anchor time
    signature    BYTEA       NOT NULL,   -- 64-byte Ed25519 signature
    pubkey_id    TEXT        NOT NULL,   -- identifier for the key that signed
    created_at   TIMESTAMPTZ NOT NULL
);
```

Anchors reference the exact `sequence_num` and `chain_hash` they cover
— an auditor queries the anchor they trust, reads its
`(sequence_num, chain_hash)`, and runs chain verification up to that
point.

## Verification

```go
pubKey := LoadTrustedPubKey("citadel-anchor-2026")
anchor := GetAnchor(sequenceNum)

payload := fmt.Sprintf("%d|%s|%s",
    anchor.SequenceNum,
    anchor.TsUTC.Format(time.RFC3339),
    anchor.ChainHash,
)
digest := sha512.Sum512([]byte(payload))

if !ed25519.Verify(pubKey, digest[:], anchor.Signature) {
    // anchor is forged or the private key was rotated after this anchor
}
```

For the chain to verify end-to-end:

1. Pick an anchor `A` whose signature you trust.
2. Run linear chain verification from the previous trusted anchor (or
   genesis) up to `A.sequence_num`.
3. Confirm the chain_hash you reach matches `A.chain_hash`.
4. Verify `A.signature` with the pubkey.

This gives you a tamper-resistant window: entries between the two
anchors are locked down by A₂'s signature; entries before A₁ are
locked by A₁.

## Key management

The Ed25519 master key is the single most sensitive secret in the
ecosystem. Losing it means:

- All anchors prior to the loss remain valid (their signatures still
  verify against the pubkey).
- **No new anchors can be signed** — the chain becomes
  tamper-*evident* again, not resistant, until a new key is
  provisioned.

Rotation procedure (today — manual; automation planned in v1.1):

1. Generate a new Ed25519 keypair (`openssl genpkey -algorithm ed25519`).
2. Publish the new pubkey under a new `pubkey_id` (e.g. `citadel-anchor-2027Q2`).
3. Update `CITADEL_CITADEL_MASTER_KEY` in the secret manager.
4. Roll the CITADEL deployment.
5. **Do not delete the old pubkey** — every anchor signed with it is
   still valid, and auditors need the pubkey to verify them for the
   entire retention period.

Best practice: store the master key in an HSM with a PKCS#11 adapter.
A CITADEL roadmap item for v2.0 is to support key operations via
KMIP/PKCS#11 so the private key never leaves the HSM at all.

## Threat model

| Adversary capability | Covered by | Recovery |
|---|---|---|
| DB-level read attacker | TripleHash — payload changes are detected | Re-issue anchor from the good state; restore from backup |
| DB-level write attacker rewrites single payload | chain_hash — break propagates to all later entries | Verify chain; `break_at` pinpoints the forgery |
| DB-level write attacker rewrites entire chain | Ed25519 anchor — signature won't verify on the forged chain_hash | Public key doesn't verify; chain is void |
| Attacker with the anchor private key | **Not covered.** This is the catastrophic scenario | Rotate key, publish both old and new pubkeys; audit the interval of exposure |

An anchor private-key compromise is the only attack that wholly
defeats the chain. Treat it accordingly: HSM-backed, minimum access,
monitored issuance, rotation runbook rehearsed.

## Performance

Ed25519 sign on modern hardware: ~50-80 µs. At an anchor interval of
100, the per-entry amortised cost is < 1 µs — immaterial against the
4.22 ms WORM append.

Verification is similar: ~50-80 µs per anchor. Auditing a year of
anchors (365 / 0.4 s assuming continuous 100-entry windows) takes
well under a minute.

## Anchor consumption by auditors

External auditors receive:

1. The **pubkey bundle** — one pubkey per rotation period, each with
   a `pubkey_id`.
2. A **time-range query** of anchors covering their audit period.
3. The **WORM entries** in that range.

They independently verify:

- Each anchor's signature against the matching pubkey.
- The linear chain walk between anchors.
- The content of the sampled WORM entries they are investigating.

Neither CITADEL nor the deployer can forge any of this without the
anchor private key.

## Related

- [TripleHash](./triple-hash.md) — per-entry digest
- [WORM log](./worm-log.md) — the chain the anchors seal
- [SECURITY.md § Key management](../SECURITY.md) — rotation runbook in full
- [Auditor walkthrough](./auditor-walkthrough.md) — how an external auditor consumes anchors
