# VertGuard Data Model

## Database: PostgreSQL 16

VertGuard persists every scan, threat IOC, audit event, and operator
override in a dedicated `vertguard` PostgreSQL database. The schema is
**privacy-by-design** — raw user content (chat prompts, email bodies, image
bytes, identity claims) is **never** stored. Only SHA-256 hashes,
classifications, structured indicator metadata, and CITADEL WORM references
are persisted.

For migration tooling and procedures, see [migrations.md](migrations.md).

---

## Entity-Relationship Overview

```
┌──────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│   prompt_scans   │     │  phishing_scans  │     │   identity_scans    │
└──────────────────┘     └──────────────────┘     └─────────────────────┘
                       (Module 1/2/3/5/6 scan history)

┌──────────────────┐     ┌─────────────────────┐
│ media_verifications │  │     threat_iocs     │──────┐
└──────────────────┘     └─────────────────────┘      │ N:1
                                                       ▼
                                       ┌─────────────────────┐
                                       │   atlas_mappings    │
                                       └─────────────────────┘

┌──────────────────────┐  ┌────────────────────┐  ┌──────────────────────┐
│ webhook_subscribers  │  │   audit_events     │  │   token_denylist     │
└──────────────────────┘  └────────────────────┘  └──────────────────────┘

┌────────────────────────┐
│ rate_limit_overrides   │
└────────────────────────┘
```

All scan tables share the **same five privacy-preserving columns**:
`scan_id`, `classification`, `confidence`, `<input>_hash`, `created_at`.

---

## Tables

### prompt_scans

Module 3 — prompt-injection scan history. Created by `POST /api/v1/scan/prompt`.

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Primary key |
| `scan_id` | TEXT UNIQUE | Caller-supplied or generated scan identifier |
| `classification` | TEXT | `CLEAN` / `SUSPICIOUS` / `BLOCKED` |
| `confidence` | NUMERIC(4,3) | Detector confidence in `[0.000, 1.000]` |
| `input_hash` | TEXT | SHA-256 hex of the original prompt |
| `input_length` | INT | Character count of the input |
| `context` | TEXT | `user_chat_input`, `untrusted_third_party`, etc. |
| `match_count` | INT | Number of pattern matches in `matches` |
| `matches` | JSONB | `[{pattern_id, atlas_technique, position, severity, ...}]` |
| `worm_entry_id` | TEXT | CITADEL WORM reference (nullable in standalone mode) |
| `duration_ms` | NUMERIC(8,3) | Scan latency |
| `created_at` | TIMESTAMPTZ | |

**Indexes**: `(classification)`, `(created_at DESC)`.

### phishing_scans

Module 2 — phishing detection (URL / email / HTML). Same shape as
`prompt_scans`, with these additions:

| Column | Notes |
|--------|-------|
| `kind` | `url` / `email` / `html` |
| `indicator_count` / `indicators` | Replaces `match_count` / `matches` |

### identity_scans

Module 6 — synthetic-identity detection on document or claim payloads.

| Column | Notes |
|--------|-------|
| `claim_hash` | SHA-256 of the canonical claim JSON |
| `claim_type` | `passport_mrz`, `iban_kyc`, etc. |
| `context` | Caller-provided context tag for replay analysis |

Has a non-unique index on `claim_hash` so the future replay-detection
sweep can be added without a table scan.

### media_verifications

Module 1 — C2PA / TripleHash media authenticity verification.

| Column | Notes |
|--------|-------|
| `content_type` | MIME |
| `content_hash` | TripleHash hex (perceptual + cryptographic) |
| `content_size` | Bytes |
| `provenance_chain` | JSONB: ordered list of C2PA assertions |
| `signer` | Cert subject CN of the trust anchor |
| `reason` | Free-text — used when `classification = unknown/unauthentic` |

### threat_iocs

Module 4 — AI threat-feed indicators (prompt-injection patterns,
adversarial-suffix payloads, malicious model artifacts).

| Column | Notes |
|--------|-------|
| `pattern_value` | Canonical pattern ID — UNIQUE with `source` |
| `type` | Default `ai_attack_pattern` |
| `source` | `manual` / feed name |
| `atlas_technique` | MITRE ATLAS `AML.T####` ID — joins `atlas_mappings` |
| `confidence` | NUMERIC(3,2) |
| `severity` | `low` / `medium` / `high` / `critical` |
| `references` | JSONB array of URLs |
| `tags` | TEXT[] — GIN-indexed for fast lookup |
| `deprecated` | Soft-delete flag |
| `first_seen` / `last_seen` | TTL + recency tracking |

**Indexes**: `atlas_technique`, `last_seen DESC`, `confidence DESC`,
GIN on `tags`. `(pattern_value, source)` is UNIQUE so cross-feed
duplicates collapse cleanly on upsert.

### atlas_mappings

MITRE ATLAS technique catalogue. Populated by the threat-feed sync job;
joined into scan responses for human-readable tactic / technique names.

| Column | Notes |
|--------|-------|
| `technique_id` | Primary key — `AML.T####` |
| `tactic_id` / `tactic_name` | `AML.TA####` and label |
| `atlas_url` | Direct deep-link |
| `synced_at` | Last successful sync from upstream |

### webhook_subscribers

Outbound webhook destinations registered by `POST /api/v1/webhooks`. Each
delivery is HMAC-signed with `hmac_secret`.

| Column | Notes |
|--------|-------|
| `url` | Subscriber endpoint |
| `hmac_secret` | Stored encrypted at rest at the application layer |
| `active` | Boolean toggle — partial index `WHERE active = TRUE` |
| `filters` | JSONB array of event-type filters |

### audit_events

Append-only audit trail for every state-changing API call.

| Column | Notes |
|--------|-------|
| `actor` / `role` | JWT `sub` + role at request time |
| `action` | `prompt.scan`, `webhook.create`, `denylist.add`, ... |
| `target_type` / `target_id` | Resource touched |
| `outcome` | `success` / `denied` / `error` |
| `status_code` | HTTP status returned |
| `request_id` / `remote_ip` | Trace correlation |
| `metadata` | JSONB — structured context |

**Indexes**: `ts DESC`, `(actor, ts DESC)`, `(action, ts DESC)`.

### token_denylist

JWT revocation list. Operators revoke individual tokens (`kind='jti'`) or
entire subjects (`kind='sub'`).

| Column | Notes |
|--------|-------|
| `kind` | `jti` or `sub` |
| `value` | The JTI or subject string |
| `reason` / `revoked_by` | Audit metadata |
| `expires_at` | Optional — sweeper can GC after expiry |

UNIQUE on `(kind, value)`. The auth middleware does a denylist lookup on
every request; index is critical-path.

### rate_limit_overrides

Per-subject or per-IP token-bucket overrides — operators tighten or
loosen the global rate limit for specific clients.

| Column | Notes |
|--------|-------|
| `kind` | `sub` or `ip` |
| `value` | Subject or IP |
| `rps` / `burst` | Override values |
| `expires_at` | Optional auto-cleanup |

UNIQUE on `(kind, value)`.

---

## Privacy guarantees enforced by schema

1. **No raw content columns** — every scan stores `*_hash` (SHA-256) and
   structured indicators only. Even an operator with `SELECT *` cannot
   recover the input.
2. **WORM correlation** — every scan links back to a CITADEL WORM entry
   via `worm_entry_id`, providing tamper-evident audit even if the
   VertGuard database is compromised.
3. **No JOIN exposes raw content** — `threat_iocs.pattern_value` is the
   pattern *signature*, not a sample of the malicious input.

---

## See Also

- [migrations.md](migrations.md) — applying / rolling back schema changes
- [architecture.md](architecture.md) — how each module reads/writes these tables
- [security/](security/) — threat model + STRIDE analysis
- [citadel-integration.md](citadel-integration.md) — WORM correlation flow
- [threatflow-integration.md](threatflow-integration.md) — IOC ingest path
