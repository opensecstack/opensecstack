# ADR-001: PostgreSQL as Primary Data Store

Date: 2026-03-25
Status: Accepted
Deciders: OpenSecStack core team

---

## Context

NIS2 Compass stores several categories of data with different structural requirements:

- **Relational compliance data**: organisations, assessments, and controls are tightly related through foreign keys. Referential integrity must be enforced at the storage layer, not just the application layer.
- **Flexible evidence payloads**: controls carry an `evidence` column whose schema varies by control type and assessor. A rigid columnar structure would require frequent schema changes as evidence formats evolve.
- **Immutable audit log**: the CITADEL WORM pattern requires a table that physically cannot be modified after insertion. This must be enforced at the database level, not in application code, because a compromised API or a direct database connection would otherwise be able to circumvent application-level guards.
- **Validated categorical fields**: compliance status, entity type, NIST category, and risk class are finite, controlled vocabularies. Invalid values must be rejected by the storage engine.
- **Compliance context**: the platform is itself a compliance tool. Its data store must provide strong ACID guarantees and a reliable, verifiable backup and restore path.

The team evaluated database options against these requirements before beginning schema design.

---

## Decision

Use **PostgreSQL 16** as the sole primary data store for NIS2 Compass.

---

## Reasons

**JSONB for evidence payloads**: PostgreSQL's `JSONB` type stores semi-structured data efficiently with full indexing support. The `evidence` column on the `controls` table accepts any valid JSON without requiring a schema change when evidence formats evolve. This avoids the need for a separate document store.

**Native UUID generation via pgcrypto**: The `pgcrypto` extension provides `gen_random_uuid()`, used as the default primary key generator across all tables. This produces collision-resistant UUIDs without requiring application-layer UUID generation, simplifying the migration and seed scripts.

**Trigger-based WORM immutability**: PostgreSQL's `PL/pgSQL` trigger system allows enforcement of write constraints at the storage engine level. The `BEFORE UPDATE OR DELETE` trigger on `audit_log` raises an exception unconditionally, making it impossible to modify audit rows through any SQL path. This level of enforcement is not achievable equivalently in SQLite (which has limited trigger DDL) or standard MySQL (which lacks the same trigger flexibility for exception raising).

**ENUM types for categorical fields**: PostgreSQL native ENUMs enforce domain validity at the column level without requiring a separate lookup table join or application-layer validation. The schema defines `org_size`, `entity_type`, `assessment_status`, `control_status`, `artifact_type`, `nist_category`, and `audit_risk_class` as ENUMs, all of which are enforced on every write.

**ACID guarantees for compliance data**: Compliance records must be consistent. PostgreSQL's multi-version concurrency control provides serializable isolation levels when required and full transactional atomicity for multi-table writes (e.g., creating an assessment and its associated controls in one transaction).

**`pg_dump` for reliable backups**: `pg_dump` is a well-tested, portable backup tool that produces SQL or binary dumps restorable to any compatible PostgreSQL instance. This is the backup mechanism documented in the runbook.

**Ecosystem maturity**: PostgreSQL 16 has wide support in Docker, Kubernetes, and cloud-managed offerings. Alembic (selected in ADR-002) has first-class PostgreSQL dialect support. The tooling ecosystem (pgAdmin, `psql`, monitoring exporters) is comprehensive.

---

## Alternatives Considered

**SQLite**: Rejected. SQLite does not support the trigger-based immutability pattern equivalently (trigger semantics differ; no `RAISE EXCEPTION` equivalent in standard SQLite triggers). SQLite is not designed for concurrent multi-user production access. It would be unsuitable for any deployment beyond a single developer's local machine.

**MongoDB**: Rejected. MongoDB does not enforce foreign key relationships between collections. Referential integrity between organisations, assessments, controls, and artifacts would need to be enforced entirely in the application layer, making it easier to create orphaned records. MongoDB's document model also makes the hash-chain audit log pattern more complex to implement correctly.

**MySQL / MariaDB**: Rejected. MySQL's ENUM semantics differ from PostgreSQL's in important ways (MySQL ENUMs are stored as integers with string labels, which affects comparison and sorting behaviour). MySQL trigger DDL is more verbose for the WORM pattern. MySQL does not have a native `JSONB` equivalent with full index support (MySQL's `JSON` type is not as performant or feature-complete as PostgreSQL's `JSONB`). The `pgcrypto` UUID generation function has no direct MySQL equivalent.

---

## Consequences

- PostgreSQL 16 is required in all environments (development, staging, production). The Docker Compose files use `postgres:16-alpine`.
- Alembic migrations contain PostgreSQL-specific DDL (ENUM creation syntax, `gen_random_uuid()`, `PL/pgSQL` trigger bodies). Migrating to a different database engine would require rewriting all migration files and the trigger logic.
- The `pgcrypto` extension must be enabled in the database. The first migration (`001`) creates it.
- Operations staff must be familiar with PostgreSQL administration tools (`psql`, `pg_dump`, `pg_restore`, `VACUUM ANALYZE`).
- The immutability guarantee of the audit log depends on the PostgreSQL trigger remaining in place and superuser access to the database being strictly controlled.
