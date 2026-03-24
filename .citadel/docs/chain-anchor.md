# Chain Anchor Algorithm

Chain anchors are the cryptographic proof that the CITADEL WORM log has not been tampered with. Each anchor links to the previous one via SHA-256, forming an immutable chain.

## Model Definition

**Table:** `citadel.chain_anchor`

| Field | Type | Description |
|-------|------|-------------|
| `anchor_id` | integer | Primary key, auto-increment |
| `anchor_hash` | string (SHA-256) | Hash of this anchor |
| `prev_anchor_hash` | string (SHA-256) | Hash of the previous anchor (genesis = all zeros) |
| `rotation_seq` | integer | Monotonically increasing sequence number |
| `rotation_type` | enum | `PLAN` \| `EVENT` \| `INCIDENT` |
| `ts_utc` | timestamp | Authoritative timestamp of anchor creation |
| `pack_hash_sha256` | string | SHA-256 of the citadel.pack (ZIP of all logs since last anchor) |
| `last_log_fingerprint_sha256` | string | SHA-256 of the most recent citadel.log entry |
| `stored_out_of_band_ref` | string | Reference to out-of-band anchor deposit |
| `status` | enum | `ACTIVE` \| `ROTATED` \| `ARCHIVED` |

## Anchor Hash Formula

```
anchor_hash = SHA256(
    prev_anchor_hash
    || rotation_seq
    || ts_utc_authoritative
    || pack_hash_sha256
    || last_log_fingerprint_sha256
)
```

All fields are concatenated as UTF-8 strings with `||` as the separator. The result is a hex-encoded SHA-256 hash.

## Rotation Types

| Type | Trigger | Frequency |
|------|---------|-----------|
| **PLAN** | Scheduled periodic rotation | Every 30 days (cron) |
| **EVENT** | Significant operational event | Month-end accounting, major release, audit completion |
| **INCIDENT** | Security or integrity incident | Immediate on tamper detection, key exposure, custody breach |

## Out-of-Band Anchoring

Every `anchor_hash` must be deposited in an independent medium to prevent undetectable chain rewriting:

| Method | Description |
|--------|-------------|
| Private WORM repository | Separate storage system with independent access controls |
| Notary service | Trusted third-party timestamp and hash deposit |
| Blockchain | Public or private blockchain transaction containing the anchor hash |

The `stored_out_of_band_ref` field records where the anchor was deposited (e.g. transaction hash, notary reference number).

## Verification

An auditor can verify chain integrity by:

1. Start at the genesis anchor (prev_anchor_hash = all zeros)
2. For each anchor, recompute `anchor_hash` from its fields
3. Verify `anchor_hash` matches the stored value
4. Verify `prev_anchor_hash` matches the previous anchor's `anchor_hash`
5. Verify the out-of-band deposit matches `anchor_hash`

If any step fails, the chain has been tampered with → **HARD STOP** + **citadel.incident** created.

## Genesis Anchor

The first anchor in the chain:

```
anchor_id: 1
prev_anchor_hash: "0000000000000000000000000000000000000000000000000000000000000000"
rotation_seq: 0
rotation_type: PLAN
status: ACTIVE
```
