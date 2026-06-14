# Auditor Walkthrough

This document is written **for auditors** — external or internal —
who need to verify CITADEL's evidence claims. It describes what you
will be given, what you should verify, and what conclusions those
checks support.

CITADEL deployments should hand this document to auditors at the
start of an engagement so the expectations are clear.

For the underlying mechanisms, see [worm-log.md](./worm-log.md),
[chain-anchor.md](./chain-anchor.md), and [triple-hash.md](./triple-hash.md).

## What you receive

For a given audit, the deployment team will hand you:

1. **Export bundle** — a tarball or directory containing:
   - `manifest.yaml` (custody record; see [evidence-custody.md § Custody manifest format](./evidence-custody.md#custody-manifest-format))
   - `worm_entries.jsonl` — one WORM entry per line, JSON
   - `chain_anchors.jsonl` — one anchor per line, JSON
   - `pubkeys.yaml` — trusted pubkeys, each with `id`, `pubkey_hex`,
     `issued`, `revoked`, `replaced_by`
   - `bundle.sha256` — hex digest covering the four files above

2. **The `openssl`-like verification script** — a small Go or Python
   tool that automates the verification steps below. Running the
   script should return `"bundle valid"` with all checks green.

3. **A point-of-contact** for questions about the manifest's
   `produced_by` / `authorised_by` identities.

## What you verify

### Step 1 — Bundle integrity

```
bundle_sha256 = SHA-256(
    concat(
      bytes(worm_entries.jsonl),
      bytes(chain_anchors.jsonl),
      bytes(pubkeys.yaml)
    )
)
```

Compare against `bundle.sha256` in the bundle. Any mismatch means
the bundle was modified in transit — reject and request re-export.

### Step 2 — Pubkey registry

Check each pubkey in `pubkeys.yaml`:

- `pubkey_hex` is a valid Ed25519 public key (32 bytes, hex-encoded).
- `issued` / `revoked` dates are plausible (not in the future, no gaps).
- If `revoked` is set, `replaced_by` points at a pubkey that is also
  in the bundle and whose `issued` date is on or after the revocation.
- No pubkey is used for anchors outside its `[issued, revoked)` window.

### Step 3 — Anchor signatures

For each anchor in `chain_anchors.jsonl`:

```
payload = sequence_num + "|" + ts_utc + "|" + chain_hash
digest  = SHA-512(payload)

ed25519.Verify(pubkey_for(anchor.pubkey_id), digest, anchor.signature) == true
```

Every anchor must verify. A single failing anchor voids the chain
integrity claim for the range that anchor covers. Reject the bundle
on any failure.

### Step 4 — Linear chain walk

Iterate entries in `worm_entries.jsonl` sorted by `sequence_num` ASC.
For each entry:

1. **Recompute TripleHash.**
   ```
   expected = hex(SHA-256(payload) ‖ SHA-512(payload) ‖ BLAKE3(payload))
   assert expected == entry.triple_hash
   ```

2. **Recompute chain_hash.**
   ```
   prev_bytes = hex_decode(entry.prev_hash)
   expected   = hex(SHA-256(prev_bytes ‖ entry.payload))
   assert expected == entry.chain_hash
   ```

3. **Check continuity** (for `i > 0` in the range):
   ```
   assert entry[i].prev_hash == entry[i-1].chain_hash
   ```

Any mismatch = reject.

### Step 5 — Anchor-over-chain-walk

Confirm that the first and last entries in the bundle are covered by
anchors that also verify in step 3:

- An anchor covers entries `[A.prev_sequence_num + 1, A.sequence_num]`.
- `chain_hash(A.sequence_num) == A.chain_hash`.

Any chain_hash from the walk that does not appear in the anchors
bundle means the anchor coverage is incomplete — the bundle is valid
as far as the walk proves, but the range between anchors is weaker
evidence than anchor-sealed range.

### Step 6 — Time-range sanity

Confirm the bundle's claimed range (`manifest.evidence.time_range`)
matches:

- `first_sequence_num` ≤ first entry's sequence_num.
- `last_sequence_num` ≥ last entry's sequence_num.
- `from` ≤ first entry's `ts_utc`, `to` ≥ last entry's.

## Claims the bundle supports

A **green** bundle supports these claims:

1. **These specific payloads existed at their timestamps.** The
   chain_hash at each sequence_num encodes the full history up to
   that point; re-deriving it from the payloads and the genesis
   hash yields the same value.

2. **The timestamps are CITADEL-authoritative.** `ts_utc` is set by
   CITADEL's server clock at append time, not by the caller.

3. **The payloads have not been altered since.** TripleHash is
   content-addressable; any mutation would fail step 4.

4. **The chain was not re-ordered or spliced.** Continuity checks
   (step 4.3) detect insertion, deletion, and re-ordering.

5. **The range is cryptographically sealed.** The anchor signatures
   (step 3) bind the chain_hashes to a private key that only CITADEL
   holds; an attacker would need that key to forge anchors.

## Claims the bundle does *not* support

- **The payloads are truthful.** CITADEL only proves that a payload
  was submitted and committed; it does not validate business
  semantics. If IRFlow lied about an incident's severity, the WORM
  entry reflects the lie faithfully.

- **The actor was who they claimed to be.** CITADEL uses whatever
  identity the caller's IdP asserted. Compromised credentials produce
  genuine-looking WORM entries.

- **Actions were carried out.** The WORM records the *decision*. The
  IRFlow-side `incident_actions` table records the decision and the
  execution outcome. Evidence for the action's effect is one layer
  above — you need the downstream system's records too.

## Common findings

### Gaps in sequence_num

Gaps (`... 1234, 1236, ...` with 1235 missing) should not occur in a
healthy chain. The `LOCK TABLE` serialises appends and
`sequence_num` is assigned monotonically. If you see gaps, something
is wrong — either the export missed entries, or the chain has been
tampered with.

### Anchors with identical `sequence_num`

Cannot happen legitimately — each anchor covers a unique range. Two
anchors at the same sequence_num means duplicate entries in the
table, which is itself an incident.

### Payload not UTF-8

Legal — `payload` is `BYTEA`, could be any bytes. In practice it is
always JSON, but the bundle format does not enforce this. If you see
binary data, the chain is still valid; the payload is just opaque to
your analysis.

## Questions to ask the deployer

During the engagement:

- What is the rotation cadence for the anchor key?
- Has the anchor key ever been rotated out of schedule?
- Where does the anchor private key live (HSM / secret manager / etc.)?
- Who has access to the anchor private key's secret-manager path?
- When was the last chain verification run?
- Has the chain ever returned `valid: false` in production?

The answers should match what's in [SECURITY.md](../SECURITY.md) and
[operator-runbook.md](./operator-runbook.md). Discrepancies are
findings in themselves.

## Out of scope for the auditor

- **Business-logic correctness of payloads.** That's a different
  audit.
- **Private-key custody.** You cannot verify this from the bundle
  alone; you interview the deployer instead.
- **DB-level access controls on `worm_entries`.** Those limit who
  can forge, not what forgeries look like. Your integrity checks
  catch forgery attempts regardless of source.

## Related

- [WORM log](./worm-log.md) — what you're verifying
- [Chain anchor](./chain-anchor.md) — signature scheme
- [TripleHash](./triple-hash.md) — per-entry digest
- [Evidence custody](./evidence-custody.md) — bundle format in detail
- [Appeal flow](./appeal-flow.md) — what to do if you find issues
