# OpenCSIRT Migrations

> v1.0.0. Schema lives under [`migrations/`](../migrations/) as
> paired `up.sql` / `down.sql` files, applied with
> [`golang-migrate`](https://github.com/golang-migrate/migrate). For
> the schema itself see [data-model.md](data-model.md).

---

## Tooling

The runner is `migrate` from `golang-migrate`. The
[Makefile](../Makefile) does not yet wrap it; the canonical
invocation is:

```bash
migrate -path migrations \
        -database "$OPENCSIRT_DB_URL" \
        up
```

`OPENCSIRT_DB_URL` is the same env var the API server reads, e.g.
`postgres://opencsirt:opencsirt@127.0.0.1:5432/opencsirt?sslmode=disable`.

In the docker-compose dev stack ([`deploy/docker-compose.yml`](../deploy/docker-compose.yml))
operators run `migrate up` manually against `OPENCSIRT_DB_URL` after
`docker compose up`. A dedicated init container is tracked on the
roadmap.

---

## File naming

```
NNNN_description.up.sql
NNNN_description.down.sql
```

- `NNNN` — four-digit zero-padded sequential number, starting at
  `0001`. Four digits because the v1.x roadmap (advisory revisions,
  IOC partitioning, peer-CSIRT trust scopes) is expected to land
  10–20 migrations.
- `description` — lowercase, underscore-separated change summary.
- **Every up has a paired down.** The down is best-effort and is
  expected to run cleanly only in development — production
  rollbacks restore from a `pg_basebackup` instead.

### Migration list

| Version | File | What it adds |
|---|---|---|
| 0001 | [`0001_init.up.sql`](../migrations/0001_init.up.sql) | All eight v1.0.0 tables + indexes; enables `uuid-ossp` |

Subsequent migrations land here per-release. As of v1.0.0 only
0001 exists.

---

## Idempotence rules

Every `up.sql` must be safe to re-apply on a partially-migrated
database:

- Use `CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`,
  and `ADD COLUMN IF NOT EXISTS` where appropriate.
- Avoid raw `INSERT` of seed data unless it is keyed off a
  natural-key `ON CONFLICT … DO NOTHING`.
- Backfills should be split: a forward-compatible schema change in
  one migration, the data backfill in the next, the constraint
  tightening in the third. This is the canonical "expand /
  migrate / contract" rhythm and it lets the upgrade window
  tolerate either schema.

`down.sql` is allowed to assume the up ran cleanly (it does not
need to be idempotent).

---

## Schema upgrade-window safety

OpenCSIRT API replicas are rolled, not stop-the-world. The
contract is:

> The API tolerates either the old or the new schema during a
> deployment window of up to 60 seconds.

Concrete consequences:

- New columns are `NOT NULL DEFAULT …` (or nullable). No
  application code is allowed to depend on a new column existing
  until the migration that adds it has been live in production for
  at least one release.
- Removed columns are dropped only after the application has been
  released in a state that no longer reads them (one full release
  cycle of forward-compatibility).
- Renames are forbidden. Add the new column, dual-write, switch
  reads, drop the old. Three migrations, three releases.

This mirrors the OpenScrub
[migrations.md](../../openscrub/docs/migrations.md) discipline.

---

## Rollback story

Every up has a real down. Rollback in dev:

```bash
migrate -path migrations -database "$OPENCSIRT_DB_URL" down 1
```

Rollback in production: do not. Restore from
`pg_basebackup` + WAL replay, then re-apply forward migrations up
to the desired version. This is the only path that recovers
referential integrity across `ON DELETE SET NULL` evidence-
preservation FKs without losing the snapshot semantics described in
[data-model.md](data-model.md#on-delete-semantics-summary).

---

## CITADEL audit emission

Schema changes are themselves a privileged operation. v1.0.0 does
**not** emit a CITADEL event for `migrate up` — operators are
expected to run migrations through their change-management process
(ticket + 4-eyes review). v1.1 will add an `opencsirt.schema_change`
event sourced from a tiny audit shim that wraps `migrate`. Tracked
on ROADMAP.

In the meantime, the [`audit_log`](data-model.md#audit_log) table
captures the post-migration state via the regular API path: every
operator login after the migration writes an `audit_log` row whose
`metadata` includes the build's `migration_version` (read from
`schema_migrations` at startup).

---

## See also

- [data-model.md](data-model.md)
- [deployment.md](deployment.md)
- [`migrations/`](../migrations/)
