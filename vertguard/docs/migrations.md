# VertGuard Database Migrations

## Overview

VertGuard ships a custom in-process migrator (`internal/db/migrate.go`)
that applies plain `.sql` files in version order. The runner is
**idempotent** — every migration begins with `CREATE TABLE IF NOT EXISTS` /
`CREATE INDEX IF NOT EXISTS` and ends with an `INSERT … ON CONFLICT DO
NOTHING` into `schema_migrations`.

For the current schema, see [data-model.md](data-model.md).

---

## File Naming

```
NNN_description.sql
```

- `NNN` — three-digit sequential number (`001`, `002`, …)
- `description` — lowercase, underscore-separated change summary
- Single file per migration (no separate `up`/`down`); the file must be
  idempotent and reversible-by-replacement.

### Current migrations

| Version | File | What it adds |
|---------|------|--------------|
| 001 | `001_initial.sql` | `prompt_scans`, `threat_iocs`, `atlas_mappings`, `media_verifications` |
| 002 | `002_webhook_subscribers.sql` | Outbound webhook destinations |
| 003 | `003_audit_events.sql` | Immutable audit trail |
| 004 | `004_phishing_scans.sql` | Module 2 scan history |
| 005 | `005_token_denylist.sql` | JWT revocation |
| 006 | `006_rate_limit_overrides.sql` | Per-subject rate limit |
| 007 | `007_identity_scans.sql` | Module 6 scan history |

---

## Running Migrations

### Apply All Pending Migrations

```bash
# Via the VertGuard CLI
vertguard migrate up

# Or directly
go run ./cmd/vertguard migrate up
```

The runner reads `VERTGUARD_DB_URL` (or the `database.url` config key) and
applies every migration not already present in `schema_migrations`.

### Check Current Version

```bash
vertguard migrate status
```

Output:

```
Applied migrations:
  001 — 001_initial            (2026-04-01T10:14:22Z)
  002 — 002_webhook_subscribers (2026-04-01T10:14:22Z)
  …
Pending: 0
```

### Apply to a Specific Version

```bash
vertguard migrate up --target 4
```

---

## Schema Versioning Table

```
schema_migrations(version INT PRIMARY KEY, name TEXT, applied_at TIMESTAMPTZ)
```

Because every `INSERT` uses `ON CONFLICT DO NOTHING`, the table is safe
to replay against a fully-migrated database. Non-idempotent statements
(e.g. raw `CREATE TABLE` without `IF NOT EXISTS`) will fail loudly — by
design — so operators notice schema drift.

---

## Writing a New Migration

### Required structure

```sql
-- VG-NNN: short summary
--
-- Idempotent. Privacy-by-schema: never reference raw user content.

CREATE TABLE IF NOT EXISTS my_new_table (
    id         UUID         PRIMARY KEY,
    -- columns…
    created_at TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_my_new_table_created
    ON my_new_table (created_at DESC);

INSERT INTO schema_migrations (version, name)
VALUES (NNN, 'NNN_description')
ON CONFLICT (version) DO NOTHING;
```

### Privacy checklist (mandatory)

Before merging a migration that adds columns to any scan table:

- [ ] No column stores raw user input (text, image bytes, identity payload).
      Use `*_hash` (SHA-256 hex) or structured indicator JSON.
- [ ] No column stores HMAC secrets, API keys, or JWT contents in
      cleartext. Use envelope encryption at the application layer.
- [ ] PII fields (email, IP) appear only in `audit_events` and follow the
      retention policy in [secrets-management.md](secrets-management.md).

### Adding a column safely

For zero-downtime migrations:

```sql
-- Phase 1: add nullable column (instant in PG 16)
ALTER TABLE prompt_scans ADD COLUMN IF NOT EXISTS severity TEXT;

-- Phase 2 (later release): backfill in batches
UPDATE prompt_scans SET severity = 'medium'
 WHERE severity IS NULL AND id IN (
   SELECT id FROM prompt_scans WHERE severity IS NULL LIMIT 10000
 );

-- Phase 3 (later release): apply NOT NULL once backfill is complete
ALTER TABLE prompt_scans ALTER COLUMN severity SET NOT NULL;
```

### Index creation on large tables

```sql
-- Always use CONCURRENTLY for indexes on tables with >100k rows.
-- CONCURRENTLY cannot run inside a transaction; place it in its own
-- migration file with no other statements.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_threat_iocs_severity
    ON threat_iocs (severity);
```

---

## Rollback Strategy

VertGuard does not ship per-migration `down.sql` files. The forward-only
philosophy is intentional:

- Every migration is **idempotent** — re-running is safe.
- Rollbacks happen via a *new* migration that drops or reverts the
  previous change. This keeps `schema_migrations` linear and auditable.
- For dev environments, drop the database and re-apply from `001`.

For emergency production rollback:

```bash
# 1. Stop VertGuard
systemctl stop vertguard

# 2. Restore PostgreSQL backup taken before deploy
pg_restore --clean -d vertguard backup_pre_NNN.dump

# 3. Deploy the previous binary
cp /opt/vertguard/vertguard.bak /opt/vertguard/vertguard

# 4. Restart
systemctl start vertguard
```

Take a `pg_dump -Fc vertguard > backup.dump` immediately before every
production migration.

---

## Testing Migrations

Migration files are exercised in CI by:

```bash
# Spin up an empty PostgreSQL, apply every migration, run the schema
# integration tests against the result.
make test-integration
```

This confirms:

- Each migration applies cleanly to an empty DB
- Re-running every migration produces no errors (idempotency)
- All `*_store.go` queries in `internal/db/` resolve against the schema

See [testing.md](testing.md) for the complete test pyramid.

---

## Migration Checklist (PR review)

- [ ] Filename matches `NNN_description.sql` and uses the next free `NNN`
- [ ] First-line comment summarises the change and notes it is idempotent
- [ ] Every `CREATE` uses `IF NOT EXISTS`
- [ ] Every `INSERT INTO schema_migrations` uses `ON CONFLICT DO NOTHING`
- [ ] No raw user content columns added
- [ ] `data-model.md` updated to reflect the new schema
- [ ] `make test-integration` passes locally

---

## Further Reading

- [data-model.md](data-model.md) — current schema reference
- [testing.md](testing.md) — DB integration test setup
- [deployment.md](deployment.md) — production migration procedure
- [secrets-management.md](secrets-management.md) — secret-handling policy
