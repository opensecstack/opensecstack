# NIS2 Compass — Database Schema Reference

This document describes the complete PostgreSQL 16 schema used by NIS2 Compass. The canonical source is `schema.sql`. The schema is applied and versioned through Alembic migrations — do not run `schema.sql` directly against a live database; use `alembic upgrade head` instead.

The `pgcrypto` extension is required and is enabled automatically by the first migration (`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`).

---

## ENUM Types

Seven custom ENUM types are declared before any table is created. PostgreSQL enforces that only the listed values can be stored in columns of each type.

### `org_size`

Organisation headcount classification for NIS2 entity categorisation.

| Value | Meaning |
|---|---|
| `micro` | Fewer than 10 employees |
| `small` | 10–49 employees |
| `medium` | 50–249 employees |
| `large` | 250 or more employees |

### `entity_type`

NIS2 Directive entity classification under Article 3.

| Value | Meaning |
|---|---|
| `essential` | Essential entity (stricter supervisory obligations) |
| `important` | Important entity |

### `assessment_status`

Lifecycle state of a NIS2 compliance assessment.

| Value | Meaning |
|---|---|
| `draft` | Assessment created but not yet started |
| `in_progress` | Active assessment work underway |
| `under_review` | All controls assessed; pending reviewer sign-off |
| `completed` | Review complete and accepted |
| `archived` | Retired from active view; read-only |

### `control_status`

Compliance determination for a single Article 21(2) measure.

| Value | Meaning |
|---|---|
| `not_assessed` | No evaluation has been performed yet |
| `compliant` | Measure is fully implemented and evidenced |
| `partially_compliant` | Measure is partially implemented; gaps identified |
| `non_compliant` | Measure is not implemented |
| `not_applicable` | Measure does not apply to this organisation's scope |

### `artifact_type`

Classification of an uploaded evidence artifact.

| Value |
|---|
| `policy` |
| `procedure` |
| `evidence` |
| `report` |
| `screenshot` |
| `log` |
| `certificate` |
| `contract` |

### `nist_category`

NIST Cybersecurity Framework function that the control maps to.

| Value | NIST CSF Function |
|---|---|
| `identify` | Identify |
| `protect` | Protect |
| `detect` | Detect |
| `respond` | Respond |
| `recover` | Recover |

### `audit_risk_class`

Severity classification for audit log entries.

| Value | Meaning |
|---|---|
| `INFO` | Routine state change or read event |
| `WARNING` | Potentially significant action requiring attention |
| `CRITICAL` | High-impact action (deletion, privilege change, etc.) |

---

## Tables

### `organisations`

Stores the entities (companies, agencies, operators) being assessed for NIS2 compliance. Each organisation may have many assessments across multiple assessment cycles.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `UUID` | No | `gen_random_uuid()` | Primary key |
| `name` | `VARCHAR(255)` | No | — | Legal name of the organisation |
| `industry` | `VARCHAR(100)` | No | — | NIS2 sector (e.g. `energy`, `transport`, `banking`, `health`, `digital_infra`) |
| `country` | `CHAR(2)` | No | — | ISO 3166-1 alpha-2 country code (e.g. `DE`, `FR`, `NL`) |
| `size` | `org_size` | No | `medium` | Headcount classification |
| `entity_type` | `entity_type` | No | `important` | NIS2 entity classification: `essential` or `important` |
| `registration_number` | `VARCHAR(100)` | Yes | `NULL` | Company registration or trade number |
| `contact_email` | `VARCHAR(255)` | Yes | `NULL` | Primary compliance contact email address |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp (UTC) |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Last modification timestamp (UTC); auto-updated by trigger |

**Indexes**

| Index name | Columns | Notes |
|---|---|---|
| `idx_organisations_country` | `country` | Supports filtering by country for multi-jurisdiction reporting |
| `idx_organisations_industry` | `industry` | Supports sector-level dashboards and aggregations |

**Triggers**

| Trigger name | Event | Function | Description |
|---|---|---|---|
| `trg_organisations_updated_at` | `BEFORE UPDATE` | `set_updated_at()` | Automatically sets `updated_at = NOW()` on every row update |

---

### `assessments`

Represents a single NIS2 Article 21(2) compliance assessment for an organisation. One organisation may have multiple assessments (e.g. annual cycles, mid-cycle reassessments).

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `UUID` | No | `gen_random_uuid()` | Primary key |
| `org_id` | `UUID` | No | — | Foreign key to `organisations.id` — CASCADE DELETE |
| `title` | `VARCHAR(255)` | No | — | Human-readable assessment title |
| `status` | `assessment_status` | No | `draft` | Current lifecycle state |
| `framework_version` | `VARCHAR(20)` | No | `NIS2-2022/0383` | Version identifier of the NIS2 framework being assessed against |
| `scope` | `TEXT` | Yes | `NULL` | Narrative description of the systems and processes in scope |
| `assessor` | `VARCHAR(255)` | Yes | `NULL` | Name or identifier of the lead assessor |
| `due_date` | `DATE` | Yes | `NULL` | Target completion date |
| `completed_at` | `TIMESTAMPTZ` | Yes | `NULL` | Timestamp set when status transitions to `completed` |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp (UTC) |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Last modification timestamp (UTC); auto-updated by trigger |

**Foreign keys**

| Column | References | On delete |
|---|---|---|
| `org_id` | `organisations(id)` | `CASCADE` |

**Indexes**

| Index name | Columns | Notes |
|---|---|---|
| `idx_assessments_org_id` | `org_id` | Supports listing all assessments for a given organisation |
| `idx_assessments_status` | `status` | Supports filtering by lifecycle state across all organisations |

**Triggers**

| Trigger name | Event | Function | Description |
|---|---|---|---|
| `trg_assessments_updated_at` | `BEFORE UPDATE` | `set_updated_at()` | Automatically sets `updated_at = NOW()` on every row update |

---

### `controls`

One row per Article 21(2) measure per assessment. The ten measures (a–j) covering areas such as risk analysis, incident handling, business continuity, supply chain security, and cryptography are tracked here with their compliance status, evidence, and remediation plans.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `UUID` | No | `gen_random_uuid()` | Primary key |
| `assessment_id` | `UUID` | No | — | Foreign key to `assessments.id` — CASCADE DELETE |
| `article_ref` | `VARCHAR(20)` | No | — | Article reference string, e.g. `Art.21(2)(a)` |
| `measure_ref` | `CHAR(1)` | No | — | Single letter `a`–`j` identifying the Article 21(2) sub-measure. Constrained by CHECK. |
| `nist_category` | `nist_category` | No | — | Mapping to NIST CSF function |
| `title` | `VARCHAR(255)` | No | — | Short title of the measure |
| `description` | `TEXT` | Yes | `NULL` | Detailed description of the measure requirement |
| `status` | `control_status` | No | `not_assessed` | Current compliance determination |
| `evidence` | `JSONB` | No | `'{}'` | Structured evidence references (document IDs, URLs, timestamps) |
| `gap_description` | `TEXT` | Yes | `NULL` | Description of identified compliance gaps |
| `remediation_plan` | `TEXT` | Yes | `NULL` | Planned remediation steps to address gaps |
| `remediation_due` | `DATE` | Yes | `NULL` | Target date for remediation completion |
| `risk_score` | `NUMERIC(3,1)` | Yes | `NULL` | Risk score from 0.0 to 10.0. Constrained by CHECK. |
| `notes` | `TEXT` | Yes | `NULL` | Free-text reviewer notes |
| `assessed_by` | `VARCHAR(255)` | Yes | `NULL` | Name or identifier of the person who assessed this control |
| `assessed_at` | `TIMESTAMPTZ` | Yes | `NULL` | Timestamp of the assessment determination |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Row creation timestamp (UTC) |
| `updated_at` | `TIMESTAMPTZ` | No | `NOW()` | Last modification timestamp (UTC); auto-updated by trigger |

**Constraints**

| Constraint | Expression | Description |
|---|---|---|
| `CHECK` | `measure_ref IN ('a','b','c','d','e','f','g','h','i','j')` | Restricts measure_ref to valid Article 21(2) sub-measure letters |
| `CHECK` | `risk_score >= 0.0 AND risk_score <= 10.0` | Restricts risk score to the 0–10 range |

**Foreign keys**

| Column | References | On delete |
|---|---|---|
| `assessment_id` | `assessments(id)` | `CASCADE` |

**Indexes**

| Index name | Columns | Notes |
|---|---|---|
| `idx_controls_assessment_id` | `assessment_id` | Supports listing all controls for a given assessment |
| `idx_controls_status` | `status` | Supports aggregating compliance status across assessments |
| `idx_controls_measure_ref` | `measure_ref` | Supports querying a specific Article 21(2) sub-measure across all assessments |
| `idx_controls_nist_category` | `nist_category` | Supports NIST CSF function-level reporting |

**Triggers**

| Trigger name | Event | Function | Description |
|---|---|---|---|
| `trg_controls_updated_at` | `BEFORE UPDATE` | `set_updated_at()` | Automatically sets `updated_at = NOW()` on every row update |

---

### `artifacts`

Stores metadata for evidence files uploaded against an assessment or a specific control. File content is stored on disk or object storage; only the metadata and content hash are persisted in the database.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `UUID` | No | `gen_random_uuid()` | Primary key |
| `assessment_id` | `UUID` | No | — | Foreign key to `assessments.id` — CASCADE DELETE |
| `control_id` | `UUID` | Yes | `NULL` | Foreign key to `controls.id` — SET NULL on delete. NULL means the artifact is attached to the assessment but not a specific control. |
| `type` | `artifact_type` | No | — | Classification of the artifact |
| `filename` | `VARCHAR(255)` | No | — | Original filename as uploaded by the user |
| `file_path` | `VARCHAR(1024)` | No | — | Storage path or object key where the file content is persisted |
| `hash` | `CHAR(64)` | No | — | SHA-256 hex digest of the file content at upload time |
| `size_bytes` | `BIGINT` | Yes | `NULL` | File size in bytes |
| `mime_type` | `VARCHAR(100)` | Yes | `NULL` | MIME type detected or declared at upload time |
| `description` | `TEXT` | Yes | `NULL` | Human-readable description of what the artifact demonstrates |
| `created_by` | `VARCHAR(255)` | No | — | Name or identifier of the user who uploaded the artifact |
| `created_at` | `TIMESTAMPTZ` | No | `NOW()` | Upload timestamp (UTC) |

Artifacts have no `updated_at` column and no update trigger. Once written, an artifact record is not modified; a new upload replaces it.

**Foreign keys**

| Column | References | On delete |
|---|---|---|
| `assessment_id` | `assessments(id)` | `CASCADE` |
| `control_id` | `controls(id)` | `SET NULL` |

**Indexes**

| Index name | Columns | Notes |
|---|---|---|
| `idx_artifacts_assessment_id` | `assessment_id` | Supports listing all artifacts for a given assessment |
| `idx_artifacts_control_id` | `control_id` | Supports listing all artifacts for a specific control |
| `idx_artifacts_hash` | `hash` | Supports deduplication detection by content hash |

---

### `audit_log`

Immutable append-only evidence ledger. Every state change and user action performed by the API is recorded here. No row may be updated or deleted after insertion. The table implements the CITADEL WORM log pattern using a PostgreSQL trigger and a SHA-256 hash chain.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `UUID` | No | `gen_random_uuid()` | Primary key |
| `action` | `VARCHAR(100)` | No | — | Verb describing the event, e.g. `assessment_created`, `control_updated`, `artifact_uploaded` |
| `actor` | `VARCHAR(255)` | No | — | Identity of the user or service that performed the action |
| `resource_type` | `VARCHAR(100)` | No | — | Type of the affected resource, e.g. `assessment`, `control`, `artifact` |
| `resource_id` | `UUID` | Yes | `NULL` | UUID of the affected resource. NULL for actions that do not target a specific row. |
| `risk_class` | `audit_risk_class` | No | `INFO` | Severity classification of the event |
| `metadata` | `JSONB` | No | `'{}'` | Arbitrary structured context for the event (e.g. before/after field values) |
| `object_fingerprint` | `CHAR(64)` | Yes | `NULL` | SHA-256 hex digest of the canonical JSON representation of the affected object at the time of the action |
| `prev_hash` | `CHAR(64)` | Yes | `NULL` | `chain_hash` of the immediately preceding audit log entry. NULL for the genesis (first) entry. |
| `chain_hash` | `CHAR(64)` | No | — | SHA-256 anchor hash for this entry. See chain construction below. |
| `timestamp` | `TIMESTAMPTZ` | No | `NOW()` | Event timestamp (UTC) |

**Chain hash construction**

```
chain_hash = SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)
```

Field values are concatenated as their string representations. The resulting chain allows any entry's integrity to be verified by recomputing its hash and confirming that the `prev_hash` it records matches the `chain_hash` of the entry that precedes it in timestamp order.

**Indexes**

| Index name | Columns | Notes |
|---|---|---|
| `idx_audit_log_actor` | `actor` | Supports auditing actions by a specific user or service |
| `idx_audit_log_action` | `action` | Supports filtering by event type |
| `idx_audit_log_resource_id` | `resource_id` | Supports retrieving the full audit history of a specific resource |
| `idx_audit_log_timestamp` | `timestamp DESC` | Supports chronological retrieval in reverse order (most recent first) |

**Triggers**

| Trigger name | Event | Function | Description |
|---|---|---|---|
| `enforce_audit_log_immutability` | `BEFORE UPDATE OR DELETE` | `audit_log_immutable()` | Raises an exception and aborts any UPDATE or DELETE attempt. No application privilege level can bypass this. |

---

### `control_templates`

Reference library of the ten NIS2 Article 21(2) measures. This table is not organisation-specific; it holds the canonical measure definitions that seed scripts copy into `controls` rows when a new assessment is initialised. Created by `seeds/01_nis2_controls.py`.

| Column | Type | Nullable | Default | Description |
|---|---|---|---|---|
| `id` | `SERIAL` | No | auto-increment | Surrogate primary key |
| `measure_ref` | `CHAR(1)` | No | — | Article 21(2) sub-measure letter (`a`–`j`). Unique. |
| `article_ref` | `VARCHAR(20)` | No | — | Full article reference, e.g. `Art.21(2)(a)` |
| `title` | `VARCHAR(255)` | No | — | Short title of the measure |
| `description` | `TEXT` | Yes | `NULL` | Full description of the measure requirement derived from the directive text |
| `nist_category` | `nist_category` | No | — | NIST CSF function mapping |
| `guidance` | `TEXT` | Yes | `NULL` | Implementation guidance notes |

**Constraints**

| Constraint | Column | Description |
|---|---|---|
| `UNIQUE` | `measure_ref` | Each sub-measure letter appears exactly once in the template library |

---

## Entity-Relationship Diagram

```
┌─────────────────────┐
│  control_templates  │
│─────────────────────│
│ id (PK, SERIAL)     │
│ measure_ref (UNIQUE)│
│ article_ref         │
│ title               │
│ description         │
│ nist_category       │
│ guidance            │
└─────────────────────┘
         (reference only — no FK to organisations)

┌─────────────────────┐         ┌─────────────────────────┐
│    organisations    │  1   *  │       assessments        │
│─────────────────────│─────────│─────────────────────────│
│ id (PK)             │         │ id (PK)                  │
│ name                │         │ org_id (FK → org)        │
│ industry            │         │ title                    │
│ country             │         │ status                   │
│ size                │         │ framework_version        │
│ entity_type         │         │ scope                    │
│ registration_number │         │ assessor                 │
│ contact_email       │         │ due_date                 │
│ created_at          │         │ completed_at             │
│ updated_at          │         │ created_at               │
└─────────────────────┘         │ updated_at               │
                                └────────────┬────────────┘
                                             │ 1
                              ┌──────────────┴──────────────────┐
                              │                                  │
                           *  │                               *  │
               ┌─────────────────────┐         ┌───────────────────────┐
               │       controls      │         │        artifacts       │
               │─────────────────────│         │───────────────────────│
               │ id (PK)             │◄────────│ control_id (FK, NULL) │
               │ assessment_id (FK)  │         │ id (PK)               │
               │ article_ref         │         │ assessment_id (FK)    │
               │ measure_ref         │         │ type                  │
               │ nist_category       │         │ filename              │
               │ title               │         │ file_path             │
               │ description         │         │ hash (SHA-256)        │
               │ status              │         │ size_bytes            │
               │ evidence (JSONB)    │         │ mime_type             │
               │ gap_description     │         │ description           │
               │ remediation_plan    │         │ created_by            │
               │ remediation_due     │         │ created_at            │
               │ risk_score          │         └───────────────────────┘
               │ notes               │
               │ assessed_by         │
               │ assessed_at         │
               │ created_at          │
               │ updated_at          │
               └─────────────────────┘

┌──────────────────────────────────────────────────────────┐
│                        audit_log                         │
│──────────────────────────────────────────────────────────│
│ id (PK)                                                  │
│ action                                                   │
│ actor                                                    │
│ resource_type                                            │
│ resource_id  ─────────────────────────────── (no FK;    │
│ risk_class                                    soft ref)  │
│ metadata (JSONB)                                         │
│ object_fingerprint (SHA-256)                             │
│ prev_hash ──────────────────────────► chain_hash of     │
│ chain_hash                            previous row       │
│ timestamp                                                │
│                                                          │
│  IMMUTABLE — trigger blocks UPDATE and DELETE            │
└──────────────────────────────────────────────────────────┘
```

`audit_log.resource_id` is a soft reference — it records the UUID of the affected resource but does not declare a formal PostgreSQL foreign key constraint. This is intentional: audit entries must remain readable even after the resource they reference has been deleted.

---

## Immutability Triggers

### `audit_log_immutable()`

```sql
CREATE OR REPLACE FUNCTION audit_log_immutable()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is immutable: % operations are not permitted', TG_OP;
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER enforce_audit_log_immutability
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_immutable();
```

This trigger fires before any `UPDATE` or `DELETE` statement on `audit_log`, for every affected row. It raises an exception that aborts the statement. Because it is a `BEFORE` trigger that raises an exception rather than returning `NULL`, the operation is blocked regardless of the caller's PostgreSQL role or privileges. Superuser connections are subject to the same restriction.

The only way to remove or alter audit entries is to drop and recreate the trigger, which itself generates a database-level event visible in the PostgreSQL system logs — providing a second layer of tamper evidence.

### `set_updated_at()`

```sql
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
```

This function is attached to `organisations`, `assessments`, and `controls` via individual `BEFORE UPDATE` triggers (`trg_organisations_updated_at`, `trg_assessments_updated_at`, `trg_controls_updated_at`). It intercepts every update and sets `updated_at` to the current timestamp before the row is written. Application code does not need to supply this value; the database maintains it automatically.

The `artifacts` and `audit_log` tables do not have `updated_at` columns and do not use this trigger. Artifacts are write-once by convention; `audit_log` is write-once by trigger enforcement.
