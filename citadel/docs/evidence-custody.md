# Evidence Custody

The WORM chain is evidence. Making it *admissible* evidence — for a
regulator, a court, or an internal audit — requires a chain of custody
that documents who had access to it, when, how integrity was verified
at each handover, and what proof accompanies the data when it leaves
CITADEL.

This document explains how CITADEL supports chain-of-custody claims,
what it records automatically, and what the operator must add
manually.

## What CITADEL records automatically

Every WORM entry carries:

| Field | Custody purpose |
|---|---|
| `id` (UUID) | Unique reference that cannot be re-used |
| `sequence_num` | Position in the chain; gaps are detectable |
| `ts_utc` | CITADEL's server-authoritative time — not the caller's |
| `source` + `event_type` | Provenance — which subsystem produced this evidence |
| `project_id` | Scope — which investigation this evidence belongs to |
| `payload` | The evidence itself, byte-for-byte |
| `triple_hash` | Content-addressable digest — proof the bytes have not changed |
| `chain_hash` | Proof that this entry existed at this sequence position |
| `prev_hash` | Proof that this entry came *after* the prior one |
| `created_at` | DB-level insert timestamp; matches `ts_utc` for integrity cross-check |

Additionally, **chain anchors** sign `(sequence_num, ts_utc, chain_hash)`
with an Ed25519 key held only inside CITADEL. Anchors are what elevate
"internally consistent chain" to "externally attestable chain".

For the anchor mechanism, see [chain-anchor.md](./chain-anchor.md).

## Handover: exporting evidence

When evidence leaves CITADEL — to an auditor, a court, a regulator —
the export bundle must include:

1. **The WORM entries** (the evidence itself).
2. **The Ed25519 public keys** used to sign the anchors covering this
   range, with their key IDs and issuance dates.
3. **The anchors** covering the range.
4. **The chain walk**: cryptographic proof from the first anchor to
   the last covering every entry.
5. **A custody manifest**: who authorised the export, who received
   the bundle, when, and with what bundle-level hash.

CITADEL v1.0.0 produces items 1-4 automatically via the export CLI
(planned — today done via SQL dumps + manual verify). Item 5 is the
operator's responsibility.

## Custody manifest format

Recommended manifest (plain text or YAML):

```yaml
bundle_id:            "citadel-export-2026-04-19-0001"
produced_at:          "2026-04-19T14:32:00Z"
produced_by:
  user_id:            42
  role:               admin
  jwt_sub:            "alice@example.com"
authorised_by:
  user_id:            99
  role:               admin
  jwt_sub:            "bob@example.com"
received_by:
  name:               "EU DG-CONNECT audit team"
  contact:            "audit-lead@dg-connect.europa.eu"
  received_at:        "2026-04-19T14:35:00Z"

evidence:
  time_range:
    from:             "2026-01-01T00:00:00Z"
    to:               "2026-03-31T23:59:59Z"
  entries_count:      12847
  first_sequence_num: 10201
  last_sequence_num:  23047
  anchors_count:      129

integrity:
  bundle_sha256:      "..."
  anchor_pubkeys:
    - id:             "citadel-anchor-2026Q1"
      pubkey_hex:     "..."
      issued:         "2026-01-01"
      revoked:        null
```

The bundle_sha256 covers the concatenated bytes of the exported
entries plus anchors plus pubkey bundle. The auditor can recompute it
to verify nothing was tampered with in transit.

## Export authorisation

Exporting evidence is itself a governance-relevant action and passes
through MARSHAL:

- `action.type`: `DATA_EXPORT` — picked up by AUGUR rule_03, requires
  an `incident_id` (the "reason for export").
- Requires SoD at Gate 3 — two distinct identities must sign off.
- Is WORM-logged with its own entry recording the operator, verifier,
  reason, and the range exported.

This creates the *meta-chain-of-custody*: the custody manifest
references the bundle, and the bundle references a WORM entry
authorising the export. Any future dispute about whether an export
was authorised can be resolved against the chain itself.

## Retention

Per NIS2 Directive Article 21(2)(b), incident-related evidence must
be retained long enough to support authority review. CITADEL's
default retention policy is **indefinite** — WORM entries are never
deleted. For specific deployments:

| Retention window | When to apply |
|---|---|
| 7 years | Default for regulated entities (financial, healthcare, critical infra) |
| 10 years | Where national law requires (defence contractors, classified handling) |
| 30 days | Development / staging only — entirely separate CITADEL instance |

There is no TTL on WORM entries in v1.0.0. Archival tiering (moving
entries > 1 year to cold storage) is planned for v2.0; today, cost
scaling is linear with time.

## Revocation and rotations

**Never delete an anchor pubkey.** Even after an Ed25519 key is
rotated, every anchor signed with it remains valid for the duration of
the evidence retention. The key's custody record shows:

- `issued`: date the key came into use.
- `revoked`: date a replacement was issued (the old key no longer
  signs new anchors, but old signatures still verify).
- `replaced_by`: the new pubkey_id.

Exports for a given time range include all pubkeys that signed
anchors touching that range.

## Integrity verification by the receiver

An auditor receiving the bundle performs:

1. Recompute `bundle_sha256` — matches manifest.
2. Verify each anchor signature with the matching pubkey.
3. Walk the linear chain between anchors, recomputing triple_hash and
   chain_hash for each entry.
4. Confirm chain continuity (`prev_hash(i) == chain_hash(i-1)`).
5. Verify the WORM entry authorising the export is itself in the
   bundle, and its `payload` references this bundle_id.

Any failure at any step = reject the bundle. A legitimate CITADEL
deployment never produces a failing bundle; failures mean either
transit corruption (re-request) or tampering (escalate).

## What to *not* do

- **Do not hand out raw DB dumps.** The manifest + anchor pubkeys
  are what make the evidence attestable. A raw dump has the bytes but
  not the proof.
- **Do not re-sign anchors.** If an auditor requests a "fresh
  signature" over historical entries, that's a yellow flag — the
  whole point of anchors is that the signature is fixed at the time
  the entry range was sealed. Decline and explain.
- **Do not modify the payload**, ever. Redaction happens via
  compensating entries — a new WORM entry that references the old
  one and marks it superseded. The old entry remains in place.

## Related

- [WORM log](./worm-log.md) — the underlying storage
- [Chain anchor](./chain-anchor.md) — Ed25519 signatures making evidence attestable
- [Auditor walkthrough](./auditor-walkthrough.md) — how an auditor consumes a bundle
- [SECURITY.md § Key management](../SECURITY.md) — key rotation runbook
