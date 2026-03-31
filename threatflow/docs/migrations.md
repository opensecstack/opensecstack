# ThreatFlow Database Migrations

## Overview

ThreatFlow uses [golang-migrate](https://github.com/golang-migrate/migrate) for
database schema management. Migrations are sequential SQL files stored in
`internal/db/migrations/`. Each migration is a pair of up/down files that can be
applied or rolled back independently.

For the current schema, see [data-model.md](data-model.md).

---

## Migration File Naming

Migration files follow a strict naming convention:

```
NNN_description.up.sql
NNN_description.down.sql
```

- **NNN** -- three-digit zero-padded sequential number (e.g. `001`, `002`, `015`)
- **description** -- lowercase, underscore-separated summary of the change
- **.up.sql** -- applies the migration (forward)
- **.down.sql** -- reverts the migration (backward)

### Examples

```
001_create_feeds_table.up.sql
001_create_feeds_table.down.sql
002_create_iocs_table.up.sql
002_create_iocs_table.down.sql
003_create_ttp_tags_table.up.sql
003_create_ttp_tags_table.down.sql
004_create_sightings_table.up.sql
004_create_sightings_table.down.sql
005_create_stix_tables.up.sql
005_create_stix_tables.down.sql
```

---

## Running Migrations

### Apply All Pending Migrations

```bash
# Via the ThreatFlow CLI
go run ./cmd/threatflow migrate

# Or with the compiled binary
./threatflow migrate
```

The `migrate` command reads `THREATFLOW_DB_URL` and applies all unapplied
migrations in order.

### Apply to a Specific Version

```bash
# Migrate up to version 3
./threatflow migrate --target 3
```

### Check Current Version

```bash
./threatflow migrate --status
```

Output:

```
Current version: 5
Pending migrations: 0
Database: threatflow (postgres://localhost:5432)
```

---

## Schema Versioning Table

golang-migrate tracks applied migrations in a `schema_migrations` table:

| Column    | Type    | Description                          |
|-----------|---------|--------------------------------------|
| `version` | BIGINT  | Migration number (e.g. 5)            |
| `dirty`   | BOOLEAN | True if the last migration failed    |

If `dirty` is `true`, the migration failed partway through and manual
intervention is required. See [Handling Dirty State](#handling-dirty-state) below.

---

## Upgrade Path Procedures

### Standard Upgrade

For routine releases with schema changes:

1. Pull the latest code
2. Review migration files in `internal/db/migrations/`
3. Back up the database: `pg_dump -Fc threatflow > backup_$(date +%Y%m%d).dump`
4. Apply migrations: `./threatflow migrate`
5. Verify: `./threatflow migrate --status`
6. Restart the ThreatFlow service

### Multi-version Upgrade

When upgrading across multiple versions (e.g. v0.2.0 to v0.4.0):

1. Read the CHANGELOG for each intermediate version
2. Back up the database
3. Apply all migrations at once -- golang-migrate handles ordering
4. Verify the schema version matches the target release
5. Run integration tests against the upgraded database

---

## Rollback Procedures

### Roll Back One Migration

```bash
./threatflow migrate --rollback 1
```

### Roll Back to a Specific Version

```bash
./threatflow migrate --target 3
```

This rolls back from the current version down to version 3 (exclusive --
version 3 remains applied).

### Emergency Rollback

If a migration causes production issues:

```bash
# 1. Stop the ThreatFlow service
systemctl stop threatflow

# 2. Roll back the last migration
./threatflow migrate --rollback 1

# 3. Deploy the previous binary
cp /opt/threatflow/threatflow.bak /opt/threatflow/threatflow

# 4. Restart
systemctl start threatflow
```

### Handling Dirty State

If a migration fails partway through, the `schema_migrations` table is marked
dirty. To recover:

```bash
# 1. Check current state
./threatflow migrate --status
# Current version: 6 (DIRTY)

# 2. Manually inspect and fix the database
psql -d threatflow

# 3. Force the version to the last known good state
./threatflow migrate --force 5

# 4. Re-attempt the migration
./threatflow migrate
```

---

## Writing Migrations

### Example: Adding a New Table

**`006_create_enrichments_table.up.sql`**

```sql
CREATE TABLE enrichments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ioc_id      UUID NOT NULL REFERENCES iocs(id) ON DELETE CASCADE,
    source      VARCHAR(100) NOT NULL,
    enrichment  JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_enrichments_ioc ON enrichments(ioc_id);
CREATE INDEX idx_enrichments_source ON enrichments(source);
```

**`006_create_enrichments_table.down.sql`**

```sql
DROP TABLE IF EXISTS enrichments;
```

### Example: Adding a Column with Default Value

Use the zero-downtime pattern: add nullable first, backfill, then constrain.

**`007_add_severity_to_iocs.up.sql`**

```sql
-- Step 1: Add the column as nullable
ALTER TABLE iocs ADD COLUMN severity VARCHAR(20);

-- Step 2: Backfill existing rows with a default
UPDATE iocs SET severity = 'unknown' WHERE severity IS NULL;

-- Step 3: Add the NOT NULL constraint
ALTER TABLE iocs ALTER COLUMN severity SET NOT NULL;
ALTER TABLE iocs ALTER COLUMN severity SET DEFAULT 'unknown';
```

**`007_add_severity_to_iocs.down.sql`**

```sql
ALTER TABLE iocs DROP COLUMN IF EXISTS severity;
```

---

## Zero-Downtime Migration Guidelines

For production deployments where ThreatFlow must remain available during
schema changes, follow these rules:

### Safe Operations (No Lock Contention)

- `CREATE TABLE` -- new tables do not affect existing queries
- `CREATE INDEX CONCURRENTLY` -- non-blocking index creation (use this instead
  of `CREATE INDEX`)
- `ADD COLUMN` with no default and nullable -- instant metadata change in PostgreSQL 16
- `DROP COLUMN` -- safe if no active queries reference it (but prefer a two-phase approach)

### Operations Requiring Care

- **Adding a NOT NULL column with default** -- split into three steps as shown above:
  1. Add column as nullable
  2. Backfill in batches
  3. Add NOT NULL constraint
- **Renaming a column** -- never rename directly. Instead:
  1. Add the new column
  2. Write to both columns during transition
  3. Migrate reads to the new column
  4. Drop the old column in a later migration
- **Changing a column type** -- create a new column, migrate data, drop old column

### Backfilling Large Tables

For tables with millions of rows, backfill in batches to avoid long-running
transactions:

```sql
-- Backfill in batches of 10,000
DO $$
DECLARE
    batch_size INT := 10000;
    affected INT;
BEGIN
    LOOP
        UPDATE iocs
        SET severity = 'unknown'
        WHERE severity IS NULL
        AND id IN (
            SELECT id FROM iocs WHERE severity IS NULL LIMIT batch_size
        );
        GET DIAGNOSTICS affected = ROW_COUNT;
        EXIT WHEN affected = 0;
        COMMIT;
    END LOOP;
END $$;
```

### Index Creation

Always use `CONCURRENTLY` for index creation on existing tables:

```sql
-- Correct: non-blocking
CREATE INDEX CONCURRENTLY idx_iocs_severity ON iocs(severity);

-- Incorrect: locks the table
CREATE INDEX idx_iocs_severity ON iocs(severity);
```

Note: `CREATE INDEX CONCURRENTLY` cannot run inside a transaction block.
Place it in its own migration file with no other statements.

---

## Testing Migrations

### Apply to a Fresh Database

CI runs every migration from scratch on each build:

```bash
# Create a fresh test database
createdb threatflow_migration_test

# Apply all migrations
THREATFLOW_DB_URL="postgres://localhost:5432/threatflow_migration_test?sslmode=disable" \
  ./threatflow migrate

# Verify schema matches expected state
pg_dump -s threatflow_migration_test > actual_schema.sql
diff expected_schema.sql actual_schema.sql

# Clean up
dropdb threatflow_migration_test
```

### Apply to an Existing Database

Test that migrations apply cleanly to a database at the previous version:

```bash
# Restore a backup from the previous version
pg_restore -d threatflow_upgrade_test previous_version.dump

# Apply new migrations only
THREATFLOW_DB_URL="postgres://localhost:5432/threatflow_upgrade_test?sslmode=disable" \
  ./threatflow migrate

# Run the full test suite against the upgraded database
THREATFLOW_DB_URL="postgres://localhost:5432/threatflow_upgrade_test?sslmode=disable" \
  go test -tags integration ./...
```

### Rollback Testing

Every migration must have a working down file. CI verifies this:

```bash
# Apply all migrations
./threatflow migrate

# Roll back all migrations
./threatflow migrate --target 0

# Re-apply all migrations (proves round-trip works)
./threatflow migrate
```

---

## Migration Checklist

Before submitting a PR with a migration:

- [ ] Migration number is sequential (no gaps, no duplicates)
- [ ] Both `.up.sql` and `.down.sql` files are present
- [ ] Down migration fully reverts the up migration
- [ ] Large table changes use zero-downtime patterns
- [ ] Index creation uses `CONCURRENTLY` on existing tables
- [ ] `data-model.md` updated to reflect the new schema
- [ ] Integration tests pass on both fresh and upgraded databases
- [ ] Backfill queries use batching for tables with >100K rows

---

## Further Reading

- [Data Model](data-model.md) -- current schema reference
- [Contributing](contributing.md) -- development setup and PR process
- [Deployment](deployment.md) -- production deployment procedures
- [golang-migrate documentation](https://github.com/golang-migrate/migrate)
