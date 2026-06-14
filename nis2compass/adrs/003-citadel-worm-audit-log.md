# ADR-003: CITADEL WORM Pattern for Audit Log Immutability

Date: 2026-03-25
Status: Accepted
Deciders: OpenSecStack core team

---

## Context

The NIS2 Directive, Article 21, requires organisations subject to it to implement measures to manage cybersecurity risks and to be able to demonstrate their compliance to national competent authorities (NCAs). NIS2 Compass is the tool used to record and track that compliance work.

For NIS2 Compass to be trusted as a compliance record — by auditors, by NCAs, and by the organisations themselves — its own audit trail must be tamper-evident. Specifically:

- A compromised API must not be able to silently alter or delete audit entries to conceal activity.
- A database administrator with direct `psql` access must not be able to silently modify the audit history.
- Gaps in the audit trail (missing entries) must be detectable.
- The platform must meet the evidence preservation expectations consistent with the CITADEL evidence chain specification used across the OpenSecStack toolchain.

A naive implementation — an `audit_log` table where the application simply "never calls DELETE" — provides no real guarantee. Any code path that reaches the database (including direct psql connections, compromised API processes, or future developers who do not know the convention) can issue a DELETE or UPDATE.

---

## Decision

Implement the **CITADEL WORM (Write-Once Read-Many) log pattern** for the `audit_log` table:

1. A PostgreSQL `PL/pgSQL` trigger (`audit_log_immutable`) fires `BEFORE UPDATE OR DELETE` on `audit_log` and unconditionally raises an exception, making it physically impossible to modify or remove any row through any SQL path while the trigger is in place.

2. A SHA-256 **hash chain** links each audit log entry to its predecessor: `chain_hash = SHA-256(id || action || actor || resource_type || resource_id || prev_hash || timestamp)`. The first entry (genesis) has `prev_hash = NULL`. Any insertion, deletion, or reordering of rows breaks the chain and is detectable by recomputing hashes in timestamp order.

The schema implementing this decision is:

```sql
CREATE TABLE audit_log (
    id                  UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    action              VARCHAR(100)    NOT NULL,
    actor               VARCHAR(255)    NOT NULL,
    resource_type       VARCHAR(100)    NOT NULL,
    resource_id         UUID,
    risk_class          audit_risk_class NOT NULL DEFAULT 'INFO',
    metadata            JSONB           NOT NULL DEFAULT '{}',
    object_fingerprint  CHAR(64),
    prev_hash           CHAR(64),
    chain_hash          CHAR(64)        NOT NULL,
    timestamp           TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

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

---

## Reasons

**Application-level enforcement is insufficient**: Relying on the application to "not call DELETE" is bypassable by any of: a bug in the application, a compromised API process, a future developer unaware of the convention, or direct database access by an operator. The trigger operates at the storage engine level and is invoked regardless of which SQL client issues the statement.

**The hash chain detects what the trigger cannot prevent**: A PostgreSQL superuser can disable triggers (`ALTER TABLE audit_log DISABLE TRIGGER ALL`). If this happens, the trigger no longer protects the table. The hash chain provides a second layer of tamper detection: even if a superuser deletes or modifies rows after disabling the trigger, the hash chain will fail verification when the next periodic check runs. The two mechanisms together provide defence in depth.

**`object_fingerprint` for evidence integrity**: Each entry can optionally carry a SHA-256 fingerprint of the canonical JSON representation of the object at the time of the action. This allows auditors to verify not just that an action was recorded, but that the recorded state matches the current object state.

**Consistency with CITADEL specification**: The OpenSecStack toolchain uses the CITADEL evidence chain pattern across platforms. Implementing it consistently in NIS2 Compass allows cross-platform audit trail correlation and verification tooling to be shared.

**`risk_class` for triage**: The `audit_risk_class` ENUM (`INFO`, `WARNING`, `CRITICAL`) allows SIEM integrations and dashboards to filter and prioritise audit events without parsing the `action` field. This classification is set by the API at event creation time and cannot be altered after the fact.

---

## Alternatives Considered

**Application-level append-only enforcement only**: Rejected. As described above, application-level enforcement provides no guarantee against bypass. It is appropriate as a defence-in-depth layer on top of trigger enforcement, but not as a standalone mechanism.

**Immutable object storage (e.g., AWS S3 Object Lock, Azure Immutable Blob Storage)**: Considered. Object storage with WORM policies is a strong external immutability mechanism. It was not chosen as the primary mechanism because: (a) it introduces an external cloud dependency that is not available in all deployment contexts; (b) it makes querying the audit log (for SIEM export, chain verification, reporting) significantly more complex; (c) it does not support the hash chain pattern natively. An archival export to S3 Object Lock is a valid complement for long-term retention and is described in the runbook, but it is not the primary enforcement mechanism.

**PostgreSQL Row-Level Security (RLS)**: Considered as a complement to the trigger approach. RLS can prevent non-superuser roles from issuing DELETE or UPDATE on `audit_log`. It was not chosen as the primary mechanism because RLS can be overridden by superusers (`BYPASSRLS` privilege or superuser role). The trigger-based approach raises an exception even for superuser connections (short of explicitly disabling the trigger). RLS is a valid additional layer and is under consideration for a future enhancement.

---

## Consequences

**Storage growth**: `audit_log` rows are never deleted. The table will grow indefinitely as the platform records compliance activity. Archival to a cold storage export is required for entries older than 2 years. The archival procedure copies rows to a separate table or external storage — it does not delete from `audit_log`. See the runbook for the archival procedure.

**Migration 003 is irreversible in production**: The `downgrade()` function for migration 003 cannot complete if `audit_log` contains rows, because the table cannot be cleared (the trigger blocks DELETE). In any environment where audit events have been generated, do not attempt `alembic downgrade` past revision 003. Roll forward with a corrective migration instead.

**Periodic hash chain verification is required**: The hash chain does not verify itself. A scheduled process must periodically recompute the chain from genesis and confirm it matches the stored `chain_hash` values. Chain verification failure is a security incident and must trigger the escalation procedure described in the runbook.

**Trigger must not be disabled**: Disabling the `enforce_audit_log_immutability` trigger removes the storage-level immutability guarantee. Disabling it requires superuser access and is not part of any normal operational procedure. Any trigger disable event on `audit_log` should itself be treated as a security event.

**Superuser access must be strictly controlled**: The `postgres` superuser can disable triggers. Access to the `postgres` superuser credentials must be restricted to a small number of trusted operators and must be logged through an external audit mechanism (the NIS2 Compass `audit_log` itself cannot record events that occur via the superuser at the database level, since those events bypass the application).
