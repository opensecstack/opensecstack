# Evidence Vault Specification

The Evidence Vault (`citadel.evidence`) is the forensic evidence store within CITADEL. It maintains chain of custody for all governance evidence — scan results, compliance documents, incident artefacts, and any material cited in MARSHAL decisions.

## Purpose

Every governance decision must be backed by traceable, tamper-evident evidence. The Evidence Vault ensures:

1. **Immutability** — evidence cannot be modified after submission
2. **Chain of custody** — every access and transfer is logged
3. **Integrity** — SHA-256 fingerprints prove evidence has not been altered
4. **Separation of duties** — custody owner and data steward must be different people

## Model Definition

**Table:** `citadel.evidence`

| Field | Type | Description |
|-------|------|-------------|
| `evidence_id` | UUID | Primary key, auto-generated |
| `ts_utc` | timestamp | Time evidence was submitted (NTP-synced) |
| `evidence_type` | enum | `SCAN_RESULT` \| `COMPLIANCE_DOC` \| `INCIDENT_ARTEFACT` \| `FINANCIAL_RECORD` \| `HR_RECORD` \| `EXTERNAL` |
| `source_platform` | string | Platform that produced the evidence (e.g. `apiguard`, `nis2compass`, `irflow`) |
| `source_model` | string | Odoo model or external reference |
| `source_record_id` | integer | Record ID in source system |
| `title` | string | Human-readable description of the evidence |
| `content_hash_sha256` | string | SHA-256 hash of the raw evidence content |
| `content_ref` | string | Storage reference (file path, S3 key, or inline JSON reference) |
| `content_size_bytes` | integer | Size of the raw evidence |
| `custody_owner_id` | integer (FK → res.users) | Person responsible for the evidence |
| `data_steward_id` | integer (FK → res.users) | Person responsible for data integrity |
| `classification` | enum | `PUBLIC` \| `INTERNAL` \| `CONFIDENTIAL` \| `RESTRICTED` |
| `retention_until` | date | Earliest date evidence may be archived (minimum 7 years for compliance) |
| `chain_anchor_id` | integer (FK) | Link to chain anchor at time of submission |
| `status` | enum | `ACTIVE` \| `ARCHIVED` \| `UNDER_REVIEW` |

## Separation of Duties

The Evidence Vault enforces SoD at the model level:

| Rule | Enforcement |
|------|-------------|
| `custody_owner_id ≠ data_steward_id` | Database constraint. Any attempt to set them equal is blocked. |
| Custody owner cannot modify evidence | Custody owner can view and transfer custody, not alter content. |
| Data steward cannot transfer custody | Data steward verifies integrity, not manage custody chain. |

## Content Fingerprint Algorithm

Every evidence record is fingerprinted at submission:

1. Read the raw evidence content (file bytes or JSON payload)
2. Compute `SHA-256(raw_bytes)`
3. Store the hex-encoded hash in `content_hash_sha256`
4. Log the fingerprint to `citadel.log`

**Verification:** At any point, an auditor can recompute the hash from the stored content and compare with `content_hash_sha256`. A mismatch triggers a PATROL `INVALID` verdict and automatic escalation.

## Custody Chain

Every custody event is recorded in `citadel.evidence_custody_log`:

| Field | Type | Description |
|-------|------|-------------|
| `custody_event_id` | UUID | Primary key |
| `evidence_id` | UUID (FK) | Evidence record |
| `ts_utc` | timestamp | Time of custody event |
| `event_type` | enum | `SUBMITTED` \| `TRANSFERRED` \| `ACCESSED` \| `VERIFIED` \| `ARCHIVED` |
| `from_user_id` | integer | Previous custodian (null for initial submission) |
| `to_user_id` | integer | New custodian |
| `reason` | string | Reason for custody event |
| `log_id` | UUID (FK) | Link to citadel.log entry |

**Rule:** The custody log is INSERT-only (same WORM enforcement as `citadel.log`).

## Evidence Lifecycle

```
Evidence created (scan, document, artefact)
    │
    ▼
SUBMITTED to Evidence Vault
    │  custody_owner_id assigned
    │  data_steward_id assigned (must be different person)
    │  content_hash_sha256 computed
    │  Logged to citadel.log
    │
    ▼
ACTIVE — available for citation
    │  MARSHAL decisions cite evidence_id
    │  BEACON advisories reference evidence_ids
    │  PATROL audits verify fingerprints
    │
    ├── TRANSFERRED (custody changes) ──► New custody_owner_id, logged
    ├── ACCESSED (viewed) ──────────────► Access logged to custody chain
    ├── VERIFIED (integrity check) ─────► Hash recomputed, result logged
    │
    ▼
ARCHIVED (after retention_until date)
    │  Content moved to cold storage
    │  Metadata and fingerprint retained permanently
    │  Custody log retained permanently
```

## Integration with opensecstack Platforms

| Platform | Evidence Type | Trigger |
|----------|--------------|---------|
| APIGuard | `SCAN_RESULT` | Scan completion — findings stored as evidence |
| NIS2 Compass | `COMPLIANCE_DOC` | Assessment completion — compliance evidence stored |
| IRFlow | `INCIDENT_ARTEFACT` | Incident creation — artefacts stored with custody chain |
| CyberPath | `EXTERNAL` | Training completion — certificates stored as evidence |
| ThreatFlow | `EXTERNAL` | IOC correlation results stored as evidence |

## Storage

Evidence content is stored separately from metadata:

| Classification | Storage | Encryption |
|---------------|---------|------------|
| PUBLIC / INTERNAL | Object storage (S3-compatible) | AES-256 at rest |
| CONFIDENTIAL | Object storage with restricted access | AES-256 at rest + envelope encryption |
| RESTRICTED | Encrypted volume with hardware key | AES-256 + HSM-managed keys |

**Rule:** The `content_ref` field points to the storage location. The raw content is never stored in the PostgreSQL database — only the metadata and fingerprint.

## Retention

- Minimum retention: 7 years (NIS2 compliance requirement)
- Evidence cannot be deleted before `retention_until` date
- After retention period: content may be moved to cold storage, metadata retained permanently
- Deletion requires MARSHAL `EXECUTE` decision with explicit authority
