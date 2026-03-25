# NIS2 Compass Database Migration Guide

NIS2 Compass uses Alembic for all schema changes. This document covers the migration chain, standard procedures, best practices, rolling upgrades, and emergency procedures.

**Rule**: Never make schema changes directly in `psql`. Every schema change must go through an Alembic migration file. Direct DDL changes leave the `alembic_version` table out of sync and are untraceable.

---

## Migration Chain

Three migrations constitute the complete schema as of this writing. Each migration corresponds to a logical layer of the data model.

### Migration 001 — Organisations and Assessments

Creates the foundation tables and supporting infrastructure:

- `pgcrypto` extension (provides `gen_random_uuid()`).
- ENUM types: `org_size`, `entity_type`, `assessment_status`.
- `organisations` table with indexes on `country` and `industry`.
- `assessments` table with indexes on `org_id` and `status`.
- `set_updated_at()` trigger function and triggers on `organisations` and `assessments`.

### Migration 002 — Controls and Artifacts

Adds the compliance control layer:

- ENUM types: `control_status`, `artifact_type`, `nist_category`.
- `controls` table with JSONB `evidence` column, NUMERIC `risk_score` constraint, and indexes on `assessment_id`, `status`, `measure_ref`, and `nist_category`.
- `artifacts` table with SHA-256 `hash` column and indexes on `assessment_id`, `control_id`, and `hash`.
- `set_updated_at` trigger on `controls`.

### Migration 003 — Audit Log (CITADEL WORM)

Adds the immutable evidence ledger:

- ENUM type: `audit_risk_class`.
- `audit_log` table with `chain_hash`, `prev_hash`, and `object_fingerprint` columns.
- Indexes on `actor`, `action`, `resource_id`, and `timestamp DESC`.
- `audit_log_immutable()` trigger function.
- `enforce_audit_log_immutability` trigger (BEFORE UPDATE OR DELETE on `audit_log`).

---

## Running Migrations

### Apply All Pending Migrations

```bash
alembic upgrade head
```

This is the standard command. It applies all migrations from the current revision up to the latest. The `migrate` service in `docker-compose.yml` runs this command automatically on startup.

### Check Current Revision

```bash
alembic current
```

### View Full Migration History

```bash
alembic history
```

With verbose output:

```bash
alembic history -v
```

### Roll Back One Revision

```bash
alembic downgrade -1
```

### Roll Back to Base (empty schema)

```bash
alembic downgrade base
```

This undoes all migrations. It will fail if `audit_log` contains rows because the `audit_log_immutable` trigger prevents the table from being cleared, which Alembic requires before dropping it. See the Downgrade Procedures section.

---

## Creating a New Migration

Follow this sequence for every schema change:

```bash
# 1. Generate a new migration file.
alembic revision -m "describe_the_change"

# 2. Edit the generated file in migrations/versions/.
#    Implement both upgrade() and downgrade() completely.

# 3. Test the upgrade.
alembic upgrade head

# 4. Test the downgrade.
alembic downgrade -1

# 5. Test the upgrade again to confirm idempotency.
alembic upgrade head
```

The generated file will be placed in `migrations/versions/` with a hex revision ID. Open it and fill in the `upgrade()` and `downgrade()` functions before committing.

---

## Migration Best Practices

### Always Implement Both upgrade() and downgrade()

A migration without a `downgrade()` is not deployable safely. If you cannot write a safe `downgrade()` (see the audit log constraint below), document why in the migration file and implement a no-op with a clear comment rather than leaving it empty.

### Never Modify a Migration That Has Been Applied to Production

Once a migration file has been applied to any non-development environment, it is frozen. Create a new migration to correct it. Modifying an existing migration that others have already applied will cause revision hash mismatches and divergent schema states.

### ENUM Types

Adding new values to an existing ENUM is safe in PostgreSQL 12 and later. Alembic supports this via `op.execute("ALTER TYPE my_enum ADD VALUE 'new_value'")`.

Removing values from an ENUM requires:
1. Creating a new ENUM without the removed value.
2. Altering the column to use the new ENUM (with a USING cast).
3. Dropping the old ENUM.

This is a table rewrite operation on large tables. Plan accordingly.

### Data Migrations

Keep data migrations in separate files from schema migrations. A single migration file should do one of: change schema, or move data — not both. This makes rollbacks cleaner and failure diagnosis easier.

### Large Table Migrations

Never issue a single `UPDATE` statement across a table with millions of rows inside a migration. This holds a table-level lock for the duration and will block all reads and writes. Instead, use batched updates:

```python
# In upgrade():
op.execute("""
    DO $$
    DECLARE batch_size INT := 10000;
    DECLARE offset_val INT := 0;
    BEGIN
      LOOP
        UPDATE controls
        SET some_column = new_value
        WHERE id IN (
          SELECT id FROM controls WHERE some_column IS NULL
          LIMIT batch_size
        );
        EXIT WHEN NOT FOUND;
      END LOOP;
    END $$;
""")
```

### The Audit Log Constraint on Downgrade

Migration 003 creates the `audit_log` table and its WORM trigger. If any rows have been inserted into `audit_log` after migration 003 was applied, the `downgrade()` for migration 003 cannot truncate or drop the table — the trigger will reject any attempt to delete rows, and PostgreSQL will refuse to drop a non-empty table in many contexts.

This means: in any environment where the application has run and generated audit events, **migration 003 is effectively irreversible**. Document this in any migration notes. If a corrective change is needed to the `audit_log` schema, write migration 004 as an additive change (new columns are nullable, new indexes only) or roll forward with a corrective migration.

---

## Rolling Upgrades (Zero-Downtime Migration)

For production deployments that require continuous availability, use the following procedure. This applies only to additive (backwards-compatible) migrations.

**What counts as backwards-compatible:**
- Adding new nullable columns to existing tables.
- Adding new tables.
- Adding new indexes (best done `CONCURRENTLY` — see below).

**What is NOT backwards-compatible (requires a maintenance window):**
- Dropping columns or tables that the current API version still reads.
- Changing column types.
- Adding NOT NULL columns without a default.
- Renaming columns or tables.

### Procedure

1. Ensure the migration is backwards-compatible (additive only, as described above).
2. Deploy the new API container image. It will start and run correctly against the current schema because it tolerates the absence of the new columns.
3. Run `alembic upgrade head`. The migrate service handles this automatically on Compose restart; for a zero-downtime deploy, run it manually:
   ```bash
   docker compose run --rm migrate
   ```
4. No API restart is required for additive column additions. The API will begin using new columns on the next request after the migration completes.

### Adding Indexes Concurrently

Standard `CREATE INDEX` takes an `ACCESS SHARE` lock that blocks writes. For large tables, create indexes concurrently:

```python
# In upgrade() — note: cannot be run inside a transaction.
op.execute("CREATE INDEX CONCURRENTLY idx_controls_risk_score ON controls(risk_score);")
```

To run outside a transaction in Alembic, set `transactional_ddl = False` on the migration or use raw `connection.execute` outside the implicit transaction. Consult Alembic documentation for the correct approach with your version.

---

## Downgrade Procedures

### When to Downgrade vs When to Roll Forward

In most cases, rolling forward with a corrective migration is preferable to downgrading. Downgrading carries risk because:

- If migration 003 has been applied and audit_log contains rows, downgrade will fail at that step.
- Downgrades on tables with foreign key dependencies require careful ordering.
- Any data written by the new schema version may be incompatible with the downgraded schema.

**Downgrade if:**
- The migration was applied to a non-production environment and the schema change itself is incorrect.
- No application writes have occurred against the new schema.

**Roll forward if:**
- The migration has been applied to production.
- Any `audit_log` rows exist (migration 003 or later).
- Data written by the new API version exists in new columns.

### Executing a Downgrade

```bash
alembic downgrade -1
```

Monitor for errors. If the downgrade fails at migration 003 due to the audit log constraint, stop immediately and roll forward instead.

---

## Emergency Schema Fix

If a production migration fails mid-way through execution (e.g., the migrate service is killed, or a DDL statement fails after partial completion):

### Step 1: Assess the State

Check what Alembic believes the current revision is:

```bash
docker compose exec postgres psql -U postgres -d nis2compass -c \
  "SELECT * FROM alembic_version;"
```

Check which tables and types exist in the database:

```sql
SELECT tablename FROM pg_tables WHERE schemaname = 'public';
SELECT typname FROM pg_type WHERE typnamespace = 'public'::regnamespace;
```

### Step 2: Choose a Resolution Path

**Option A — Complete manually and stamp**: If you can safely complete the remaining DDL steps by hand (because the partial failure is well-understood), do so in `psql`, then stamp Alembic to the correct revision without re-running the migration:

```bash
alembic stamp <revision_id>
```

Verify with `alembic current` that the revision is correct, then continue with the deployment.

**Option B — Restore from backup and fix the migration file**: If the partial state is unclear or complex, restore the pre-migration database backup (see the runbook for restore procedure), correct the migration file to handle the failure case, and re-run.

### Step 3: Verify

After any emergency fix, run the full verification sequence:

```bash
alembic current
alembic history
```

Check that all expected tables and types exist:

```sql
SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;
```

Run seed scripts if needed to confirm the schema is functional:

```bash
python seeds/01_nis2_controls.py
```
