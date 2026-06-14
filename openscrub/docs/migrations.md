# OpenScrub Database Migrations

OpenScrub stores its control-plane state in PostgreSQL 16. The
schema lives under [`migrations/`](../migrations/) as paired
`up.sql` / `down.sql` files, applied with
[`golang-migrate`](https://github.com/golang-migrate/migrate).
For the schema itself see [data-model.md](data-model.md).

---

## Tooling

The runner is `migrate` from `golang-migrate`. The
[Makefile](../Makefile) does not yet wrap it (the only DB-touching
target today is `test-integration` via the docker-compose stack);
the canonical invocation is:

```bash
migrate -path migrations \
        -database "$OPENSCRUB_DB_URL" \
        up
```

`OPENSCRUB_DB_URL` is the same env var the API server reads, e.g.
`postgres://openscrub:openscrub@127.0.0.1:5432/openscrub?sslmode=disable`.

In the docker-compose dev stack ([`deploy/docker-compose.yml`](../deploy/docker-compose.yml))
the API container expects the schema to already exist on the
`postgres:16-alpine` service. There is **no** dedicated migration
init container in v1.0.0 — operators run `migrate up` manually
against `OPENSCRUB_DB_URL` after `docker compose up`. Wiring the
init container is tracked on the roadmap.

---

## File naming

```
NNNN_description.up.sql
NNNN_description.down.sql
```

- `NNNN` — four-digit zero-padded sequential number, starting at
  `0001`. Four digits because the projected v1.x roadmap (IPv6
  ratelimit, per-flow tracking, evidence partitioning) is expected
  to land 10–20 migrations.
- `description` — lowercase, underscore-separated change summary.
- **Every up has a paired down.** The down is best-effort and is
  expected to run cleanly only in development (see Rollback below).

### Migration list

| Version | File | What it adds |
|---|---|---|
| 0001 | [`0001_init.up.sql`](../migrations/0001_init.up.sql) | `rules`, `mitigations`, `ioc_ingest_log` + indexes; enables `pgcrypto` |

Subsequent migrations land here per-release.

---

## Idempotence

Up migrations should use `CREATE TABLE` / `CREATE INDEX` (without
`IF NOT EXISTS`) — `golang-migrate`'s schema-version table
(`schema_migrations`) already guarantees each file runs at most
once per database. Defensive `IF NOT EXISTS` clauses are a smell;
they hide drift.

The current `0001_init.up.sql` follows this convention except for
`CREATE EXTENSION IF NOT EXISTS pgcrypto` — extensions are
explicitly idempotent because they may have been installed by the
DBA out-of-band.

Down migrations **do** use `DROP TABLE IF EXISTS` /
`DROP INDEX IF EXISTS` so a partially-applied up can be reversed
cleanly. Compare [`0001_init.down.sql`](../migrations/0001_init.down.sql):

```sql
DROP TABLE IF EXISTS mitigations;
DROP TABLE IF EXISTS ioc_ingest_log;
DROP TABLE IF EXISTS rules;
```

The order matters — `mitigations` references `rules` via FK, so it
must drop first.

---

## Rollback story

Every up file in the tree has a paired down file. The down for
`0001_init` has been verified to fully reverse the up:
the three table drops in dependency order remove every object
created (the indexes go with their tables, the FK with `mitigations`,
and the `pgcrypto` extension is intentionally left alone — other
schemas may rely on it).

### Production policy: forward-only

In production, schema rollback happens via a **new forward
migration** that reverses the change, not by running `down.sql`.
The `down.sql` files exist for:

1. Local developer iteration (`migrate down 1` while writing a
   feature branch).
2. CI tear-down when the test database is reused across runs.

Production runbook (mirrors VertGuard / CyberPath):

```bash
# Before applying the migration
ts=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump -Fc "$OPENSCRUB_DB_URL" \
    > "/var/backups/openscrub/pre-migrate-${ts}.dump"

# Apply
migrate -path migrations -database "$OPENSCRUB_DB_URL" up

# If something goes wrong — restore the dump, redeploy the previous
# binary. Do NOT run `migrate down` against a populated production DB.
```

Keep the dump for at least 30 days.

---

## Backwards-compatibility window

OpenScrub mitigations **continue dropping traffic during a deploy.**
The XDP program runs in the kernel and is not restarted by an API
deploy or a schema migration; the BPF maps survive the
control-plane process restart and are repopulated by the next
reconciliation pass.

This means schema migrations must be **backwards-compatible with
the running API binary** during the upgrade window:

- **Adding a column**: must be NULLable or have a default. The
  running binary keeps reading the old shape until it is replaced.
- **Renaming a column**: forbidden in a single release. Use the
  three-step pattern: (N) add new column nullable, dual-write;
  (N+1) backfill, switch reads; (N+2) drop the old column.
- **Renaming a table**: same three-step pattern, via a view alias
  in the intermediate release.
- **Tightening a CHECK constraint**: must run after the API
  binary that produces only conforming rows is deployed.
- **Adding an index `CONCURRENTLY`**: cannot run inside a
  transaction, so the migration file must contain only the
  `CREATE INDEX CONCURRENTLY` statement and no other DDL.

The data plane never reads Postgres directly — it reads BPF maps
populated by the control plane. So a schema migration cannot
desync from kernel state by itself; it can only desync the Go API
from the row shape, which the rules above prevent.

---

## CITADEL audit emission for schema changes

OpenScrub does **not** auto-emit a CITADEL event for schema
migrations themselves. The `openscrub.rule_change` event family
covers per-rule lifecycle, not DDL. Operators wanting an audit
trail for schema changes should:

1. Capture the `schema_migrations.version` row before and after
   `migrate up` and include both in the deploy ticket.
2. Attach the pre-migration `pg_dump` artifact reference to the
   change record.
3. If the migration alters the shape of a CITADEL-bound payload
   (e.g. a new column included in `rule_change.rule`), bump the
   payload version in
   [`citadel-integration.md`](citadel-integration.md) and emit a
   one-shot `openscrub.schema_change` event from the deployment
   tooling.

A future migration may add a `schema_change_log` table to
formalise step 3; until then it is a release-checklist item.

---

## Writing a new migration — checklist

Before merging a migration PR:

- [ ] Paired up and down files; down compiles to the inverse of up.
- [ ] Constraint names are explicit (no anonymous CHECKs) so the
      down can drop them by name if needed.
- [ ] Index names follow `idx_<table>_<column[_qualifier]>` (matches
      the pattern in `0001_init.up.sql`).
- [ ] FK cascade behaviour considered — see
      [data-model.md](data-model.md#mitigations) for why
      `mitigations.rule_id` is `ON DELETE CASCADE`.
- [ ] `make test-integration` passes against a fresh DB seeded with
      this migration.
- [ ] [data-model.md](data-model.md) updated to reflect the new
      schema.
- [ ] If touching `rules` or `mitigations`, audit
      [`internal/rules/service.go`](../internal/rules/service.go)
      and the relevant `*_store.go` for column-list drift.

---

## See also

- [data-model.md](data-model.md) — current schema reference
- [testing.md](testing.md) — DB setup in integration tests
- [architecture.md](architecture.md) — control-plane / data-plane split
- [citadel-integration.md](citadel-integration.md) — event payloads coupled to schema
