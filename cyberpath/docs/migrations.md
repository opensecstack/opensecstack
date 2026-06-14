# CyberPath Database Migrations

## Tooling

CyberPath uses [`golang-migrate`](https://github.com/golang-migrate/migrate)
for schema migrations, matching the VertGuard / APIGuard pattern.
Migrations live in `internal/db/migrations/` as paired up/down SQL
files.

The runner is invoked via the project Makefile and the
`cyberpath-cli migrate` subcommand (the CLI lands with v1.0.0). For
the current schema, see [data-model.md](data-model.md).

---

## File naming

```
NNNN_description.up.sql
NNNN_description.down.sql
```

- `NNNN` — **four-digit zero-padded** sequential number
  (`0001`, `0002`, …). Four digits, not three, because the eight
  modules and two release cycles are projected to land ~30
  migrations through v1.0.0.
- `description` — lowercase, underscore-separated change summary.
- Every up has a paired down. The down is best-effort and is only
  expected to run cleanly in development.

### Initial migration list (placeholder)

Concrete migrations land as code populates `internal/db/migrations/`.
Projected v1.0.0 set:

| Version | File | What it adds |
|---|---|---|
| 0001 | `0001_initial.sql` | `tenants`, `roles`, `users`, `tracks`, `modules`, `lessons`, `content_versions` |
| 0002 | `0002_quizzes.sql` | `quizzes`, `quiz_questions` |
| 0003 | `0003_progress_completions.sql` | `progress`, `completions` |
| 0004 | `0004_audit_events.sql` | append-only audit trail |
| 0005 | `0005_webhooks.sql` | outbound webhook subscribers |
| 0006 | `0006_lab_definitions_docker.sql` | `lab_definitions` (docker runtime), `lab_sessions` |

Projected v1.0.0 additions:

| Version | File | What it adds |
|---|---|---|
| 0007 | `0007_certifications.sql` | per-track signed certificates |
| 0008 | `0008_outbox_citadel.sql` | CITADEL submission outbox |
| 0009 | `0009_lab_wasmtime_fields.sql` | `cosign_signature_ref`, `image_digest` for wasmtime runtime |
| 0010 | `0010_cohorts.sql` | `cohorts`, `cohort_enrollments` |
| 0011 | `0011_completions_indexes.sql` | reconciliation index on `(citadel_ledger_id) WHERE NULL` |
| 0012 | `0012_partition_completions.sql` | range-partition `completions` by year |

The list is updated per-release in this file.

---

## Rules

### Forward-only

The production runbook is forward-only. `down.sql` files exist for
local development; they are not invoked in production deploys.
Rolling a schema back in production happens via a *new forward
migration* that reverses the change.

### No DROP COLUMN in the same release as the replacement

When renaming or replacing a column:

1. Release N: add the new column nullable, dual-write from
   application code.
2. Release N+1 (one minor version later): backfill, switch reads to
   the new column.
3. Release N+2: drop the old column.

This keeps rolling deploys safe — the previous binary still works
against the new schema.

### Deprecation cycle

One minor-version deprecation cycle for any column or table
rename. Document the deprecation in `docs/migration-guide.md` (lands
with v1.0.0) and emit a startup log warning when the deprecated
column is still being read.

### `CONCURRENTLY` for big indexes

Indexes on tables that have crossed ~100k rows must be created
`CONCURRENTLY`. `CONCURRENTLY` cannot run inside a transaction, so
those statements live in their own migration file with no other
DDL.

```sql
-- 0011_completions_indexes.up.sql
-- Reconciliation index for unsubmitted CITADEL events.
-- CONCURRENTLY: cannot be in a transaction; this file contains only this statement.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_completions_unsubmitted
    ON completions (citadel_ledger_id)
    WHERE citadel_ledger_id IS NULL;
```

```sql
-- 0011_completions_indexes.down.sql
DROP INDEX CONCURRENTLY IF EXISTS idx_completions_unsubmitted;
```

---

## Apply

```bash
# Apply all pending migrations
make migrate-up

# Show current version + pending list
make migrate-status

# Roll back one step (development only — never run in production)
make migrate-down
```

Behind the Make targets:

```bash
# migrate-up
migrate -path internal/db/migrations \
        -database "$CYBERPATH_DB_URL" up

# migrate-status
migrate -path internal/db/migrations \
        -database "$CYBERPATH_DB_URL" version

# migrate-down (single step)
migrate -path internal/db/migrations \
        -database "$CYBERPATH_DB_URL" down 1
```

`CYBERPATH_DB_URL` is the same env var the API server reads, e.g.
`postgres://cyberpath:cyberpath@127.0.0.1:5432/cyberpath?sslmode=disable`.

In CI, the integration-test runner applies migrations against an
ephemeral Postgres before the test suite runs. See
[testing.md](testing.md).

---

## Pre-flight: backups

**Always** take a `pg_dump -Fc` before applying a migration in
production:

```bash
ts=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump -Fc "$CYBERPATH_DB_URL" \
    > "/var/backups/cyberpath/pre-migrate-${ts}.dump"
```

Keep the dump for at least 30 days. The disaster-recovery doc
(lands with v1.0.0 alongside the operator handbook) describes the
restore procedure end-to-end.

---

## Writing a new migration

Required structure for the up file:

```sql
-- CP-NNNN: short summary
--
-- Idempotent. Audit-by-schema: never DROP a table or column that
-- backs an audit chain (completions, content_versions,
-- certifications, audit_events, outbox).

CREATE TABLE IF NOT EXISTS my_new_table (
    id         UUID         PRIMARY KEY,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_my_new_table_created
    ON my_new_table (created_at DESC);
```

Required structure for the down file:

```sql
-- Reverse of CP-NNNN. Development use only.
DROP INDEX IF EXISTS idx_my_new_table_created;
DROP TABLE IF EXISTS my_new_table;
```

### Audit-chain checklist

Before merging a migration:

- [ ] Does this DROP a column or table in `completions`,
      `content_versions`, `certifications`, `audit_events`, or
      `outbox`? If yes, **stop** — audit-chain tables follow the
      multi-release deprecation cycle, never an in-place DROP.
- [ ] Does this add a column to `completions`? If yes, the
      CITADEL evidence schema in
      [citadel-integration.md](citadel-integration.md) and the
      evidence-hash canonicalisation may need updating.
- [ ] Does this add a column with PII? Document the GDPR
      classification in [data-model.md](data-model.md) and confirm
      retention policy.
- [ ] [data-model.md](data-model.md) updated to reflect the new schema.
- [ ] `make test-integration` passes locally.

---

## Rollback (production emergency)

CyberPath's production rollback procedure mirrors VertGuard's:

```bash
# 1. Stop CyberPath
systemctl stop cyberpath

# 2. Restore PostgreSQL backup taken before the deploy
pg_restore --clean -d cyberpath \
    /var/backups/cyberpath/pre-migrate-YYYYMMDDTHHMMSSZ.dump

# 3. Deploy the previous binary
cp /opt/cyberpath/cyberpath.bak /opt/cyberpath/cyberpath

# 4. Restart
systemctl start cyberpath
```

The CITADEL outbox is best-effort: in-flight events that were not
yet drained at the moment of restore are replayed by the next
`internal/citadel/` reconciliation pass (see
[citadel-integration.md](citadel-integration.md)).

---

## See also

- [data-model.md](data-model.md) — current schema reference
- [testing.md](testing.md) — DB integration test setup
- [secrets-management.md](secrets-management.md) — DB credential rotation
- [citadel-integration.md](citadel-integration.md) — outbox semantics
