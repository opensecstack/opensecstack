# NIS2 Compass — CITADEL WORM Audit Log

This document covers the design, implementation, and operational use of the `audit_log` table in NIS2 Compass. It is intended for security engineers, compliance officers, and system administrators who need to understand, verify, or present the audit record to auditors or national competent authorities.

---

## Purpose

The `audit_log` table implements the CITADEL WORM (Write-Once Read-Many) log pattern. It provides a tamper-evident, append-only record of all changes to compliance data within NIS2 Compass.

The log serves three distinct purposes:

1. **Operational accountability.** Every change to an organisation record, assessment, control status, or uploaded artifact is attributed to a specific actor (API key identity) and timestamped. This answers the question "who changed what and when" for any resource in the system.

2. **Tamper evidence.** The cryptographic chain structure means that any post-insertion modification to an audit record — including deletion — is detectable by recomputing the chain. This is not just a policy control; it is enforced at the database engine level by a PostgreSQL trigger that cannot be bypassed by the application.

3. **Regulatory evidence.** NIS2 Article 21 requires essential and important entities to implement appropriate technical measures. NIS2 Article 23 requires incident reporting with a reconstructed timeline. The CITADEL WORM log provides the timestamped, tamper-evident evidence base needed to satisfy both requirements and to demonstrate compliance to national competent authorities during audits or incident investigations.

---

## How It Works

### Chain Structure

Each row in `audit_log` anchors to its predecessor via the `prev_hash` field, forming a forward-only linked list. The `chain_hash` field is a SHA-256 digest computed from the content of the current row plus the `prev_hash` of the preceding row. Because the hash of row _n_ depends on the hash of row _n-1_, any modification to any row invalidates the chain from that point forward.

**Genesis entry** (the first row ever inserted into the table):

```
prev_hash  = NULL
chain_hash = SHA-256(
    id || action || actor || resource_type || resource_id || "NULL" || timestamp
)
```

**All subsequent entries:**

```
prev_hash  = chain_hash of the immediately preceding entry (ordered by timestamp ASC)
chain_hash = SHA-256(
    id || action || actor || resource_type || resource_id || prev_hash || timestamp
)
```

All fields are concatenated as their canonical string representations. UUIDs are lowercase hyphenated (RFC 4122). Timestamps are ISO 8601 UTC with microsecond precision. The literal string `"NULL"` is used in place of a null `prev_hash` for the genesis entry to ensure the genesis hash is non-trivial.

### Object Fingerprint

In addition to the chain hash, each entry carries an `object_fingerprint`:

```
object_fingerprint = SHA-256(canonical_json(full_object_state))
```

`canonical_json` is defined as: all keys sorted alphabetically, no insignificant whitespace, timestamps in ISO 8601 UTC. The `metadata` JSONB column stores the full before and after state of the resource (both `before` and `after` keys). The `object_fingerprint` covers the content of the resource at the moment of the action, independently of the chain. This allows verification that the state recorded in `metadata` has not been altered even if the chain hash is verified separately.

### Table Schema

```sql
CREATE TABLE audit_log (
    id                  UUID             PRIMARY KEY DEFAULT gen_random_uuid(),
    action              VARCHAR(100)     NOT NULL,
    actor               VARCHAR(255)     NOT NULL,
    resource_type       VARCHAR(100)     NOT NULL,
    resource_id         UUID,
    risk_class          audit_risk_class NOT NULL DEFAULT 'INFO',
    metadata            JSONB            NOT NULL DEFAULT '{}',
    object_fingerprint  CHAR(64),
    prev_hash           CHAR(64),
    chain_hash          CHAR(64)         NOT NULL,
    timestamp           TIMESTAMPTZ      NOT NULL DEFAULT NOW()
);
```

---

## Immutability Enforcement

The trigger `enforce_audit_log_immutability` is installed by migration `003`. Its definition:

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

The trigger fires `BEFORE UPDATE OR DELETE` for every row. Because it raises an exception unconditionally, the operation is aborted before any change reaches the table. This is not a constraint that can be deferred or bypassed by setting a session variable — it is a `BEFORE` row-level trigger that executes within the same transaction as the attempted modification.

**Scope of protection.** The trigger protects against:

- Application code that issues an `UPDATE` or `DELETE` against `audit_log`, whether intentional or through a bug.
- A compromised API process operating under the `nis2compass` database role.
- Direct database connections from a client operating as the `nis2compass` role.

**What the trigger does not protect against.** A database superuser (`postgres` role) can drop or disable the trigger with a DDL statement before issuing a `DELETE`. However:

- The `nis2compass` application role does not have superuser privileges and cannot execute `DROP TRIGGER` or `ALTER TABLE ... DISABLE TRIGGER`.
- Any DDL operation executed by a superuser is captured in PostgreSQL's server log (`log_min_duration_statement`, `log_ddl`) and in the PostgreSQL event trigger mechanism, providing a separate forensic record.
- A dropped trigger is itself a detectable event: the chain verification procedure (below) will detect any rows that were deleted, because the `prev_hash` chain will have a gap.

---

## Audit Events

The following `action` values are written by the application. All entries include the `actor` (the API key identity or the string `system` for automated operations), the `resource_type`, and a `risk_class` that reflects the security significance of the event.

| Action | resource_type | risk_class | Triggered by |
|---|---|---|---|
| `organisation_created` | `organisation` | INFO | POST /api/v1/organisations |
| `organisation_updated` | `organisation` | INFO | PATCH /api/v1/organisations/{id} |
| `organisation_deleted` | `organisation` | WARNING | DELETE /api/v1/organisations/{id} |
| `assessment_created` | `assessment` | INFO | POST /api/v1/organisations/{id}/assessments |
| `assessment_status_changed` | `assessment` | WARNING | PATCH /api/v1/assessments/{id} (status field changed) |
| `assessment_deleted` | `assessment` | WARNING | DELETE /api/v1/assessments/{id} |
| `control_status_changed` | `control` | INFO / WARNING / CRITICAL | PATCH control; WARNING when status becomes `non_compliant`; CRITICAL when `risk_score` >= 7 |
| `control_evidence_updated` | `control` | INFO | PATCH control (evidence field updated) |
| `artifact_uploaded` | `artifact` | INFO | POST artifact upload |
| `artifact_deleted` | `artifact` | WARNING | DELETE /api/v1/artifacts/{id} |
| `auth_token_issued` | `api_key` | INFO | POST /api/v1/auth/token (successful authentication) |
| `auth_failed` | `api_key` | WARNING | POST /api/v1/auth/token (authentication failure) |

`risk_class` rules for `control_status_changed`:

- `INFO` — status changes to `compliant`, `partially_compliant`, or `not_applicable`.
- `WARNING` — status changes to `non_compliant`.
- `CRITICAL` — any status change where `risk_score` is present and >= 7.0.

---

## Chain Verification Procedure

The following Python script fetches all `audit_log` entries and verifies the chain integrity. Run it from any host with network access to the PostgreSQL instance.

```python
#!/usr/bin/env python3
"""
audit_chain_verify.py — Verify the integrity of the NIS2 Compass CITADEL WORM audit chain.

Usage:
    NIS2_DB_URL=postgresql://nis2compass:<password>@<host>:5432/nis2compass \
        python audit_chain_verify.py

Exit codes:
    0 — chain is intact
    1 — one or more integrity violations detected
"""

import hashlib
import os
import sys

import psycopg2
import psycopg2.extras


def compute_chain_hash(row: dict, prev_hash: str | None) -> str:
    prev = prev_hash if prev_hash is not None else "NULL"
    # Timestamp must be ISO 8601 UTC with microseconds, matching the insertion format.
    ts = row["timestamp"].strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")
    payload = (
        str(row["id"])
        + row["action"]
        + row["actor"]
        + row["resource_type"]
        + (str(row["resource_id"]) if row["resource_id"] is not None else "NULL")
        + prev
        + ts
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main() -> int:
    db_url = os.environ.get("NIS2_DB_URL")
    if not db_url:
        print("ERROR: NIS2_DB_URL environment variable is not set.", file=sys.stderr)
        return 1

    conn = psycopg2.connect(db_url, cursor_factory=psycopg2.extras.RealDictCursor)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, action, actor, resource_type, resource_id, "
        "       prev_hash, chain_hash, timestamp "
        "FROM audit_log "
        "ORDER BY timestamp ASC, id ASC"
    )
    rows = cur.fetchall()
    cur.close()
    conn.close()

    if not rows:
        print("audit_log is empty — nothing to verify.")
        return 0

    violations = 0
    running_prev_hash: str | None = None

    for i, row in enumerate(rows):
        expected = compute_chain_hash(row, running_prev_hash)
        stored = row["chain_hash"]

        if expected != stored:
            print(
                f"VIOLATION at entry {i} (id={row['id']}, timestamp={row['timestamp']}): "
                f"expected chain_hash={expected}, stored={stored}"
            )
            violations += 1

        if row["prev_hash"] != running_prev_hash:
            print(
                f"CHAIN BREAK at entry {i} (id={row['id']}): "
                f"prev_hash mismatch — expected {running_prev_hash}, stored {row['prev_hash']}"
            )
            violations += 1

        running_prev_hash = stored

    if violations == 0:
        print(f"OK: {len(rows)} entries verified, chain intact.")
        return 0
    else:
        print(f"FAILED: {violations} violation(s) detected in {len(rows)} entries.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
```

Install the dependency and run:

```bash
pip install psycopg2-binary

NIS2_DB_URL="postgresql://nis2compass:<password>@<host>:5432/nis2compass" \
    python audit_chain_verify.py
```

A clean chain produces:

```
OK: 1247 entries verified, chain intact.
```

Any violation produces output identifying the row index, UUID, timestamp, and the nature of the discrepancy. Run this script as part of your regular compliance verification schedule — monthly at minimum, and immediately after any suspected security incident.

---

## Querying the Audit Log

The REST API exposes the audit log for read access. All queries require a valid JWT. The following examples use `curl` with a token stored in the `TOKEN` shell variable.

### All actions by a specific actor

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://nis2compass.example.com/api/v1/audit?actor=analyst%40example.com"
```

### All status changes for a specific assessment

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://nis2compass.example.com/api/v1/audit?resource_id=<assessment-uuid>&action=assessment_status_changed"
```

### All CRITICAL-class events

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://nis2compass.example.com/api/v1/audit?risk_class=CRITICAL"
```

### All events for a specific resource

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://nis2compass.example.com/api/v1/audit?resource_id=<uuid>"
```

### Direct SQL queries (for DBA or forensic use)

When the REST API is unavailable or when performing forensic analysis, query the table directly. The indexes on `actor`, `action`, `resource_id`, and `timestamp` ensure efficient access.

```sql
-- All events for an actor, most recent first.
SELECT timestamp, action, resource_type, resource_id, risk_class, metadata
FROM audit_log
WHERE actor = 'analyst@example.com'
ORDER BY timestamp DESC;

-- All CRITICAL events in the last 30 days.
SELECT timestamp, action, actor, resource_type, resource_id, metadata
FROM audit_log
WHERE risk_class = 'CRITICAL'
  AND timestamp >= NOW() - INTERVAL '30 days'
ORDER BY timestamp ASC;

-- Reconstruct the full history of a specific assessment.
SELECT timestamp, action, actor, risk_class, metadata
FROM audit_log
WHERE resource_id = '<assessment-uuid>'
ORDER BY timestamp ASC;
```

---

## Retention Policy

NIS2 does not specify a mandatory minimum retention period for audit logs. ENISA guidelines and prevailing interpretations of NIS2 Article 21 recommend a minimum of five years for essential entities and three years for important entities. In practice, aligning with the maximum limitation period for administrative enforcement actions in your jurisdiction (typically five to seven years) is the safest approach.

### Archival Without Violating Immutability

The immutability trigger prevents `DELETE` operations on `audit_log`. Archival must therefore be accomplished by copying rows to a separate medium rather than removing them from the live table.

**Option 1: Logical export to cold storage.**

```bash
# Export entries older than 2 years to a compressed file.
docker exec nis2compass-postgres-1 \
  psql -U postgres -d nis2compass -c \
  "\COPY (SELECT * FROM audit_log WHERE timestamp < NOW() - INTERVAL '2 years') TO '/tmp/audit_archive.csv' CSV HEADER"

docker cp nis2compass-postgres-1:/tmp/audit_archive.csv ./archive/

# Upload to write-once object storage (AWS example).
aws s3 cp ./archive/audit_archive.csv \
  s3://your-compliance-archive-bucket/nis2compass/audit_archive_$(date +%Y%m%d).csv \
  --storage-class GLACIER
```

After confirming the archive is intact (verify SHA-256 of the file), old rows remain in the live `audit_log` table. They cannot be deleted via the application — they will simply be queried less frequently. If table size becomes a concern at very high volumes, consult your DBA about PostgreSQL table partitioning by timestamp range.

**Option 2: PostgreSQL partition and detach.**

Partition `audit_log` by timestamp range (e.g., yearly partitions). When a partition ages out of the retention window, `DETACH` it from the parent table (which does not delete data), `pg_dump` the detached partition, upload the dump to cold storage, and then `DROP` the detached partition table. Because the partition is detached before being dropped, it is no longer subject to the trigger on the parent table. Note that detaching and dropping a historical partition is a deliberate DBA action requiring superuser privileges and should be gated by your change management process.

**Archival integrity.** Regardless of the method, apply a write-once lock to archive files in your storage system. For AWS S3, enable S3 Object Lock with Compliance mode and a retention period matching your policy. For Azure Blob Storage, enable immutable storage with a time-based retention policy. The goal is that the archive itself is as tamper-evident as the live table.

---

## Regulatory Context

### NIS2 Article 21(1): Appropriate and Proportionate Technical Measures

Article 21(1) requires essential and important entities to take "appropriate and proportionate technical and operational measures to manage the risks posed to the security of network and information systems." The CITADEL WORM audit chain contributes to this requirement in two ways:

First, it demonstrates that the platform managing compliance evidence is itself subject to rigorous controls. An organisation that can show a cryptographically linked, database-enforced immutable record of all changes to its compliance assessments is in a materially stronger position than one that relies on application-layer logging alone.

Second, it protects the integrity of the compliance record itself. If a control is erroneously or fraudulently marked `compliant`, the audit chain records who changed it, when, and from what prior state. This cannot be undone without detection.

### NIS2 Article 23: Incident Reporting

Article 23 requires entities to notify their national competent authority of significant incidents. The notification must include an initial assessment of the incident, including its cause and impact, within 72 hours of becoming aware of it. A subsequent detailed report is due within one month.

The `audit_log` provides the timestamped evidence base for reconstructing an incident timeline. By querying the log for events in the relevant time window — filtered by `resource_id`, `actor`, or `risk_class = 'CRITICAL'` — the incident responder can establish the sequence of operations that preceded, coincided with, and followed the incident. The `metadata` JSONB column records the full before/after state of each modified resource, providing the factual basis for assessing impact.

Because the chain is tamper-evident, the incident timeline derived from the audit log can be presented to the competent authority with confidence that it has not been retroactively altered.

### ENISA Guidelines on Audit Trails for Essential Entities

ENISA's technical guidelines for the implementation of NIS2 (published under the mandate of Article 21(5)) identify audit logging as a baseline measure for all entity categories. The guidelines specify that audit logs should:

- Record all access to and modifications of sensitive data.
- Be protected against modification and unauthorised deletion.
- Be retained for a period sufficient to support incident investigation and regulatory review.

The CITADEL WORM pattern addresses all three points: it logs all write operations against compliance data, enforces immutability at the database engine level, and supports configurable retention with archival guidance. The chain verification procedure provides an auditable means of demonstrating to the competent authority that the log has not been tampered with since the time of the incident or assessment being reviewed.
