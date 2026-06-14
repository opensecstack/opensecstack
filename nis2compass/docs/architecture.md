# NIS2 Compass — Architecture

## System Overview

NIS2 Compass is a compliance management platform within the OpenSecStack ecosystem. Its purpose is to help organisations subject to the EU NIS2 Directive (Directive 2022/2555) assess, track, and demonstrate adherence to the ten cybersecurity risk-management measures defined in Article 21(2).

The platform exposes a REST API on **port 8090**, backed by a Python/Flask application, a PostgreSQL 16 primary data store, and Redis 7 for caching and session state. Schema migrations are managed by Alembic and applied automatically at container startup. An audit subsystem implements the CITADEL WORM append-only log pattern to produce tamper-evident evidence chains suitable for regulatory inspection.

---

## Components

| Component | Technology | Responsibility |
|---|---|---|
| REST API | Python / Flask | Assessment CRUD, control status updates, artifact upload, audit writes |
| Database | PostgreSQL 16 | Primary data store — organisations, assessments, controls, artifacts, audit_log |
| Cache / Sessions | Redis 7 | Rate limiting, session state, background job queuing |
| Migration runner | Alembic (Python) | Schema versioning, applied automatically on startup |
| Seed scripts | Python / psycopg2 | Control template library and sample data (development only) |

---

## Data Flow

```
                        ┌─────────────────────────────────┐
                        │           PostgreSQL 16          │
                        │                                  │
                        │  organisations   assessments     │
                        │  controls        artifacts       │
                        │  audit_log       control_templates│
                        └──────────────┬───────────────────┘
                                       │
             ┌─────────────┐           │  reads / writes
             │   Client    │           │
             │ (HTTP/HTTPS)│           │
             └──────┬──────┘           │
                    │ REST (port 8090) │
                    ▼                  │
             ┌─────────────────┐       │
             │  Flask REST API ├───────┘
             │                │
             │                │──── every write ──► audit_log
             │                │                    (CITADEL WORM
             └────────┬────────┘                    append-only)
                      │
                      │ rate limiting / sessions
                      ▼
             ┌─────────────────┐
             │    Redis 7      │
             └─────────────────┘

  ── startup only ──────────────────────────────────────
             ┌─────────────────┐
             │ Alembic migrate │──► PostgreSQL 16
             │    service      │    (alembic upgrade head)
             └─────────────────┘
```

---

## Service Startup Order

The following startup sequence is enforced by the `depends_on` conditions in both `docker-compose.yml` and `docker-compose.dev.yml`.

```
postgres (healthy)
    └── migrate (completed_successfully)
            └── nis2compass-api (starts)
                    └── seed (dev only, after migrate)
```

1. **postgres** — PostgreSQL 16 must pass its healthcheck (`pg_isready -U postgres`) before any dependent service starts.
2. **migrate** — Runs `alembic upgrade head` against the healthy database. Exits with status 0 on success. The API will not start until this service completes successfully.
3. **nis2compass-api** — Starts after migrations are confirmed complete and Redis is healthy.
4. **seed** (development only) — Runs after `migrate` completes. Inserts the canonical control template library (`01_nis2_controls.py`) and sample organisation data (`02_sample_org.py`). Seeds are idempotent.

---

## Database Schema Overview

Six tables form the core data model. Five are created by Alembic migrations; `control_templates` is populated by the seed scripts.

| Table | Purpose |
|---|---|
| `control_templates` | Reference library of the 10 NIS2 Article 21(2) measures. Not organisation-specific. Populated by `seeds/01_nis2_controls.py`. |
| `organisations` | Registered entities undergoing NIS2 assessment. Stores sector, country, size, and entity classification (essential / important). |
| `assessments` | One assessment record per organisation per assessment cycle. Tracks framework version, assessor identity, lifecycle status, and due date. |
| `controls` | Per-assessment control entries — one row per Article 21(2) measure (a–j). Stores compliance status, JSONB evidence, risk score, and reviewer notes. |
| `artifacts` | Evidence files uploaded against an assessment or a specific control. Content-addressed by SHA-256 hash. |
| `audit_log` | Immutable append-only ledger of all state changes and user actions. Enforced at the database layer via a trigger that blocks UPDATE and DELETE. |

Full column-level documentation is in [schema-reference.md](schema-reference.md).

---

## CITADEL WORM Audit Chain

Every write operation performed by the API appends a row to `audit_log`. The table is designed to function as a WORM (Write Once, Read Many) log: once written, rows cannot be modified or removed.

### Chain hash construction

Each audit entry records a cryptographic chain hash computed as:

```
chain_hash = SHA-256(
    id           ||
    action       ||
    actor        ||
    resource_type||
    resource_id  ||
    prev_hash    ||
    timestamp
)
```

The `prev_hash` column holds the `chain_hash` of the immediately preceding row. The first row in the table (the genesis entry) has `prev_hash = NULL`. This linked structure means that any retroactive alteration of a row — or deletion of a row from the middle of the sequence — produces a detectable break in the chain, because the hashes will no longer verify correctly when traversed from any point back to genesis.

Each row also stores an `object_fingerprint`: a SHA-256 hash of the canonical JSON representation of the affected object at the moment the action was recorded. This allows auditors to verify that the object state captured in the log matches the current database state, or to detect silent divergence.

### Database-level immutability

A PostgreSQL trigger enforces immutability at the storage layer:

```sql
CREATE TRIGGER enforce_audit_log_immutability
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW
    EXECUTE FUNCTION audit_log_immutable();
```

The trigger function raises an exception for any UPDATE or DELETE attempt, regardless of the caller's privileges. Application-level access controls are therefore not the sole safeguard; the database itself refuses modifications.

### Relevance to NIS2 Article 21

NIS2 Article 21 requires that organisations implement appropriate and proportionate technical and organisational measures to manage cybersecurity risks, and Article 23 requires incident notification with supporting evidence. Competent authorities and audit bodies expect that organisations can produce a verifiable, unaltered history of their compliance posture changes. The CITADEL WORM audit chain satisfies this requirement by producing a tamper-evident record where any gap or alteration in the hash sequence is detectable without requiring access to external systems.

---

## Assessment Lifecycle State Machine

An assessment moves through the following states. Only the transitions listed below are valid; the API enforces them.

```
draft ──► in_progress ──► under_review ──► completed ──► archived
  ▲              │               │
  └──────────────┘               │  (returned for rework)
     (scope change)              │
                    ◄────────────┘
```

| From | To | Condition |
|---|---|---|
| `draft` | `in_progress` | Assessor assigned and scope defined |
| `in_progress` | `draft` | Scope or assessor change requires restart |
| `in_progress` | `under_review` | All controls have been assessed (no `not_assessed` status remaining) |
| `under_review` | `in_progress` | Reviewer returns for additional evidence or corrections |
| `under_review` | `completed` | Review passed; `completed_at` timestamp is set |
| `completed` | `archived` | Assessment is retired from active view |

Archived assessments are read-only. The audit log retains the full state history for every transition.

---

## Key Design Decisions

**UUID primary keys** — All primary keys use `gen_random_uuid()` (provided by the `pgcrypto` extension). UUIDs avoid sequential enumeration of resource IDs through the API and are safe to distribute to client applications.

**PostgreSQL ENUM types** — Compliance-critical fields (assessment status, control status, entity type, NIST category, audit risk class) are declared as PostgreSQL ENUM types rather than unconstrained strings. The database itself rejects invalid values without requiring application-layer validation.

**JSONB evidence column on controls** — The `controls.evidence` column is JSONB, allowing structured but flexible storage of evidence references (URLs, document identifiers, timestamps) without requiring schema changes as evidence formats evolve across assessment cycles.

**NIST CSF category mapping** — Each control row records a `nist_category` (identify, protect, detect, respond, recover). This maps the ten NIS2 Article 21(2) measures onto the NIST Cybersecurity Framework function taxonomy, enabling cross-framework reporting and gap analysis against NIST CSF profiles.

**Content-addressed artifact hashing** — The `artifacts.hash` column stores a SHA-256 hex digest of the uploaded file's content. Artifacts with identical content share the same hash, enabling deduplication detection. The hash also provides integrity verification: re-hashing the stored file and comparing against the recorded digest confirms the artifact has not been altered since upload.
