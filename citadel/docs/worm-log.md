# WORM Log

CITADEL's WORM (Write-Once, Read-Many) log is the tamper-evident
append-only audit chain that every MARSHAL decision and every
cross-platform governance event is recorded into. No entry is ever
mutable; integrity is provable by recomputing hashes from the
payload bytes.

For the composite per-entry digest, see [triple-hash.md](./triple-hash.md).
For the Ed25519 signatures sealing blocks of entries, see
[chain-anchor.md](./chain-anchor.md). For the Go implementation, see
[internal/db/worm.go](../internal/db/worm.go).

## Table shape

```sql
CREATE TABLE worm_entries (
    id           UUID        PRIMARY KEY,
    sequence_num BIGINT      NOT NULL UNIQUE,
    ts_utc       TIMESTAMPTZ NOT NULL,
    source       TEXT        NOT NULL,  -- e.g. "citadel.marshal", "irflow.incident"
    event_type   TEXT        NOT NULL,  -- e.g. "marshal.decision", "incident.created"
    project_id   TEXT        NOT NULL,
    payload      BYTEA       NOT NULL,  -- raw JSON, byte-for-byte
    triple_hash  TEXT        NOT NULL,  -- 256 hex chars
    chain_hash   TEXT        NOT NULL,  -- 64 hex chars
    prev_hash    TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL
);
```

`sequence_num` is monotonic from 1 upward; the 0th entry does not
exist — the chain starts at 1 and its `prev_hash` is the **genesis
hash**.

## Genesis hash

```
genesis = SHA-256("CITADEL-GENESIS-SIN-v1")
       = f0c8e9... (64 hex chars)
```

The first `worm_entries` row stores this fixed hex value in
`prev_hash`. Auditors can independently compute and verify it —
changing the genesis constant would change every downstream hash in
the chain, so the constant is covered by any chain verification.

## Chain-hash formula

```
chain_hash(i) = SHA-256( bytes(prev_hash(i)) ‖ bytes(payload(i)) )
```

Where:

- `bytes(prev_hash(i))` is the decoded 32-byte value of the previous
  chain_hash (or the genesis bytes for entry 1).
- `bytes(payload(i))` is the raw JSON byte stream exactly as stored.
- `‖` is byte concatenation.

**Key invariant:** changing *any* byte of *any* earlier payload
changes every subsequent `chain_hash`. An attacker who wants to
retroactively edit entry N must re-hash N, N+1, N+2, …, — and produce
a new signed anchor over the range that covers them. The anchor
private key is what prevents this; see
[chain-anchor.md](./chain-anchor.md).

## The append operation

```
BEGIN;
LOCK TABLE worm_entries IN EXCLUSIVE MODE;
  SELECT sequence_num, chain_hash FROM worm_entries ORDER BY sequence_num DESC LIMIT 1;
  -- if empty → seq = 0, prev_hash = genesisHash()
  seq  := prev.seq + 1
  th   := TripleHash(payload)
  ch   := SHA-256(prev.chain_hash || payload)
  INSERT INTO worm_entries (id, sequence_num, ts_utc, source, event_type, project_id,
                            payload, triple_hash, chain_hash, prev_hash, created_at)
  VALUES (...)
COMMIT;
```

`LOCK TABLE ... IN EXCLUSIVE MODE` is deliberate and
non-negotiable — the chain is **strictly single-writer**, because
concurrent appenders would produce divergent chains that can't
reconcile. Throughput scales vertically (faster disk) not horizontally
(more writers). The v2.0 sharded-chain-per-project_id design is the
path to horizontal scale.

## Verification

`GET /api/v1/worm/verify?from=...&to=...` runs over the requested
time range and returns:

```json
{
  "valid":            true,
  "entries_verified": 12847,
  "anchor_verified":  true
}
```

Verification steps, per entry in `[from, to]` by `sequence_num` ASC:

1. **Recompute triple_hash.** If `TripleHash(payload) != stored triple_hash`, the payload bytes changed — break here, return `valid: false`.
2. **Recompute chain_hash.** If `SHA-256(prev_hash ‖ payload) != stored chain_hash`, the chain math was tampered — break.
3. **Continuity.** `prev_hash(i) == chain_hash(i-1)` for `i > 1` — otherwise an entry was spliced into a chain it doesn't belong to.

On any failure, the response is:

```json
{
  "valid":            false,
  "entries_verified": 12846,
  "break_at":         "sequence_num=12847: chain_hash mismatch",
  "anchor_verified":  false
}
```

`break_at` points at the **first broken entry**, which is almost
always the first entry an attacker tried to forge.

## Anchor verification

After the linear chain walk passes, verification optionally checks
the Ed25519 anchor signatures covering the range. In v1.0.0 this is
implemented (`AnchorVerified: true`) only when
`CITADEL_ANCHOR_INTERVAL` anchors have been produced within the
queried range.

In v1.0.0 the anchor field in `VerifyResult` is populated but callers
should regard it as advisory — the hard integrity guarantee comes
from the linear walk above.

## Fields and their purposes

| Field | Purpose |
|---|---|
| `id` | Caller-facing UUID — CITADEL returns this as `worm_entry_id` to IRFlow etc. Primary key but **not** used for chain math. |
| `sequence_num` | Monotonic ordinal; the chain walks entries in `sequence_num` order. |
| `ts_utc` | When CITADEL accepted the entry; **not** when the caller built the payload. |
| `source` | Which subsystem or platform emitted this entry, e.g. `citadel.marshal`, `irflow.incident`. |
| `event_type` | Specific event taxonomy, e.g. `marshal.decision`, `incident.created`. Enables per-type queries without payload parsing. |
| `project_id` | Logical partition for auditor queries. |
| `payload` | Raw bytes the caller sent. Never canonicalised, never re-serialised. |
| `triple_hash` | Content-addressable digest; see [triple-hash.md](./triple-hash.md). |
| `chain_hash` | Tamper-evident link to all prior entries. |
| `prev_hash` | The previous chain_hash, or the genesis hash for entry 1. |

## Query patterns

### Retrieve a specific entry for forensics

```sql
SELECT * FROM worm_entries WHERE id = $1;
```

### Time-range query for an audit

```sql
SELECT * FROM worm_entries
 WHERE ts_utc BETWEEN $1 AND $2
 ORDER BY sequence_num ASC;
```

### Incident-specific chain

```sql
SELECT * FROM worm_entries
 WHERE project_id = 'prod' AND event_type = 'marshal.decision'
   AND payload::jsonb -> 'kerkese' -> 'action' ->> 'incident_id' = $1
 ORDER BY sequence_num ASC;
```

## What WORM does *not* do

- **No deletion.** Even under GDPR right-to-be-forgotten, PII must not
  enter the payload in the first place — there is no erasure path.
  Pseudonymise at the caller layer.
- **No compaction.** Entries accumulate forever. For a 10-year
  horizon at 1 MiB/day, expect ~3.7 TB. Archival tiers (cold storage
  for entries > 1 year) are planned for v2.0.
- **No multi-writer.** Two CITADEL primaries appending to the same
  chain produce divergent tails that cannot merge.
- **No conditional append.** Every emission unconditionally appends;
  the gate-level decisions about *whether* an action happens are
  made upstream in MARSHAL.

## Related

- [TripleHash](./triple-hash.md) — per-entry content digest
- [Chain anchor](./chain-anchor.md) — Ed25519-signed block boundaries
- [MARSHAL engine § Gate 5](./marshal-engine.md#gate-5--worm-audit) — the unconditional-commit gate
- [Evidence custody](./evidence-custody.md) — how WORM entries support chain-of-custody claims
