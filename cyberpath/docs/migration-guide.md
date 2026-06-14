# CyberPath Migration Guide

Version-to-version upgrade guide for CyberPath operators. This document
covers breaking changes per release series, data migration procedures,
the deprecation cycle, rollback strategy, and pre/post-migration
verification.

For the low-level schema migration tooling (golang-migrate, file naming
rules, CONCURRENTLY index creation), see [migrations.md](migrations.md).
For the full schema reference, see [data-model.md](data-model.md).

---

## Versioning contract

CyberPath follows semantic versioning. The compatibility guarantees are:

| Bump | Schema | API | Config env vars |
|---|---|---|---|
| Patch (0.1.x) | Forward-compatible additive only | Non-breaking | Non-breaking |
| Minor (0.x.0) | Forward-compatible; deprecation notices emitted | Additive; old fields stay one cycle | Old vars honoured one cycle |
| Major (x.0.0) | May require offline migration | Breaking changes with migration path | Old vars removed after announced deprecation |

Rolling deploys (old binary reading new schema) are safe for patch and
minor releases. Major bumps require a coordinated stop-migrate-start
procedure unless the release notes say otherwise.

---

## Pre-migration checklist

Run this checklist before any production migration, regardless of bump
level.

- [ ] Take a `pg_dump -Fc` of the `cyberpath` database (see
      [Backup](#backup-before-migration) below).
- [ ] Record the current migration version:
      ```bash
      make migrate-status
      # or directly:
      migrate -path internal/db/migrations -database "$CYBERPATH_DB_URL" version
      ```
- [ ] Confirm no in-flight CITADEL outbox messages are queued:
      ```bash
      psql "$CYBERPATH_DB_URL" -c \
        "SELECT count(*) FROM outbox WHERE submitted_at IS NULL;"
      ```
      If count > 0, wait for the drain or confirm the outbox will replay
      cleanly after restore. See [citadel-integration.md](citadel-integration.md).
- [ ] Check active lab sessions — migrations that touch `lab_sessions`
      or `lab_definitions` should be applied during a maintenance window
      when no labs are running:
      ```bash
      cyberpath-cli sandbox sessions list --state active
      ```
- [ ] Verify disk space: `pg_dump -Fc` on the database host needs at
      least 2x the current database size free on the backup destination.
- [ ] Read the release changelog for any manual steps required before
      the schema migration runs.
- [ ] Pin the target image tag in `docker-compose.prod.yml` or your Helm
      `values.yaml` but do not deploy yet.

---

## Backup before migration

```bash
ts=$(date -u +%Y%m%dT%H%M%SZ)
pg_dump -Fc "$CYBERPATH_DB_URL" \
    > "/var/backups/cyberpath/pre-migrate-${ts}.dump"
```

Verify the dump is not zero-length before proceeding:

```bash
ls -lh "/var/backups/cyberpath/pre-migrate-${ts}.dump"
```

Keep the dump for a minimum of 30 days. The dump file name includes the
timestamp so you can correlate it with the migration version log.

---

## Applying the migration

### Single-host Docker Compose

```bash
# 1. Stop the running service
docker compose -f docker-compose.yml -f docker-compose.prod.yml stop api

# 2. Apply migrations with the new image (entrypoint runs migrate-up by default)
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    run --rm api cyberpath-cli migrate up

# 3. Verify migration version
docker compose -f docker-compose.yml -f docker-compose.prod.yml \
    run --rm api cyberpath-cli migrate status

# 4. Start the service
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api
```

If `CYBERPATH_DB_MIGRATE_ON_BOOT=true` (the default), step 2 is
implicit in step 4. Run step 3 after startup to confirm.

### Helm / Kubernetes

```bash
# 1. Scale down the API deployment
kubectl scale deployment cyberpath-api --replicas=0 -n cyberpath

# 2. Run the migration job (shipped as a Helm hook)
helm upgrade cyberpath ./charts/cyberpath \
    --namespace cyberpath \
    --set image.tag=<target-version> \
    --wait

# 3. Confirm migration version
kubectl exec -n cyberpath deploy/cyberpath-api -- \
    cyberpath-cli migrate status

# 4. Scale back up
kubectl scale deployment cyberpath-api --replicas=3 -n cyberpath
```

The Helm chart ships a `pre-upgrade` hook Job that runs
`cyberpath-cli migrate up`. If the Job fails the upgrade is blocked and
the previous revision remains active.

---

## Version-specific breaking changes

### v1.0.0 — initial release

No migration from a prior version; this is the first production schema.

Initial migration set applied on first boot:

| Migration | Tables created |
|---|---|
| 0001 | `tenants`, `roles`, `users`, `tracks`, `modules`, `lessons`, `content_versions` |
| 0002 | `quizzes`, `quiz_questions` |
| 0003 | `progress`, `completions` |
| 0004 | `audit_events` |
| 0005 | `webhooks` |
| 0006 | `lab_definitions` (docker runtime), `lab_sessions` |

### v1.0.0 — wasmtime runtime, certifications, CITADEL outbox

Breaking changes relative to v1.0.0:

1. **`lab_sessions.runtime` column** — v1.0.0 records used the implicit
   `docker` runtime; v1.0.0 adds `cosign_signature_ref` and
   `image_digest` to `lab_definitions` (migration 0009). No existing row
   is modified; new columns are nullable. No operator action required
   beyond applying the migration.

2. **`CYBERPATH_LAB_RUNTIME` env var** — must be set to `wasmtime` for
   v1.0.0+ deployments. `docker` continues to work but is outside the
   v1.0.0 security-audit scope. Update your env file or Helm values
   before deployment.

3. **`CYBERPATH_CERT_SIGNING_KEY`** — required for the `cert` module.
   Must be a KMS-backed reference. Set this before starting v1.0.0 or
   the certification feature will fail startup validation. See
   [operator-handbook.md](operator-handbook.md) for key provisioning.

4. **Completions partitioning (migration 0012)** — this migration runs
   `ALTER TABLE completions PARTITION BY RANGE (completed_at)` and
   creates annual partitions. It requires an `ACCESS EXCLUSIVE` lock on
   the `completions` table for the duration of the DDL. Apply during a
   maintenance window if the table has crossed ~1M rows. For tables with
   less data the lock is typically under 5 seconds.

   Pre-migration check:
   ```bash
   psql "$CYBERPATH_DB_URL" -c "SELECT count(*) FROM completions;"
   ```
   If count > 500k, schedule a low-activity window.

5. **Cohorts (migration 0010)** — adds `cohorts` and
   `cohort_enrollments`. No existing data affected.

Migration sequence for v1.0.0 → v1.0.0:

```
0007_certifications
0008_outbox_citadel
0009_lab_wasmtime_fields
0010_cohorts
0011_completions_indexes   (CONCURRENTLY — no transaction wrapper)
0012_partition_completions (maintenance window if completions > 500k)
```

All six run in sequence with `make migrate-up`. If you need to stop
after a specific migration:

```bash
migrate -path internal/db/migrations \
        -database "$CYBERPATH_DB_URL" goto 0010
```

### v1.1+ — tenant-level GDPR erase (planned)

The `tenants.deleted_at` soft-delete and the orchestrated erase
procedure described in [data-model.md](data-model.md) land in v1.1.
Breaking change: the `DELETE FROM tenants` path is disabled; all tenant
removal must go through `cyberpath-cli tenant offboard`. Details will be
published in the v1.1 release notes.

---

## Deprecation cycle

CyberPath follows a one minor-version deprecation cycle for column and
table renames:

1. **Release N** — new column added (nullable). Application writes both
   old and new. Startup log emits:
   ```
   WARN column "old_col" on table "t" is deprecated; will be removed in vN+2
   ```
2. **Release N+1** — backfill script runs on deploy; reads switch to new
   column.
3. **Release N+2** — `DROP COLUMN old_col` migration ships.

Deprecation notices are recorded in this file under the relevant version
heading. Operators should treat any startup-log `WARN … deprecated`
message as a signal to plan for the next minor upgrade.

---

## Data migration scripts

For non-schema data migrations (backfilling calculated fields, re-hashing
content, etc.), scripts live under `internal/db/scripts/` and are run
via the CLI:

```bash
cyberpath-cli admin run-script <script-name> [--dry-run]
```

Always run with `--dry-run` first. Scripts emit a row-count estimate and
a list of affected table+column pairs before making any changes.

### Content hash backfill (v1.0.0)

If you operated a v1.0.0 instance and `content_versions.content_hash`
was not populated for older revisions, run:

```bash
cyberpath-cli admin run-script backfill-content-hashes --dry-run
cyberpath-cli admin run-script backfill-content-hashes
```

The script reads each `content_versions` row that has a NULL or empty
`content_hash`, computes BLAKE3 over the canonicalised body, and writes
the result. It does not touch rows that already have a hash. Idempotent.

### Evidence hash backfill (v1.0.0)

`completions.evidence_hash` was added in v1.0.0 migration 0003
(retroactively populated). If any row has a NULL `evidence_hash`:

```bash
cyberpath-cli admin run-script backfill-evidence-hashes --dry-run
cyberpath-cli admin run-script backfill-evidence-hashes
```

Each backfilled row is also resubmitted as a `cyberpath.correction` event
to CITADEL so the ledger reflects the updated canonical body.

---

## Rollback procedure

Production rollback is a forward-only operation: apply a new migration
that reverses the change. The `down.sql` files are for development only
and are not invoked in production.

Emergency rollback (when the new binary cannot start):

```bash
# 1. Stop CyberPath
systemctl stop cyberpath
# or for Docker Compose:
docker compose -f docker-compose.yml -f docker-compose.prod.yml stop api

# 2. Restore the pre-migration database dump
pg_restore --clean --if-exists -d cyberpath \
    /var/backups/cyberpath/pre-migrate-YYYYMMDDTHHMMSSZ.dump

# 3. Revert to the previous image tag
# Edit docker-compose.prod.yml: image: ghcr.io/opensecstack/cyberpath:<previous-tag>

# 4. Start
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api

# 5. Verify
curl -sf https://cyberpath.internal:8086/api/v1/health | jq .
make migrate-status
```

After a database restore, the CITADEL outbox is replayed by the next
reconciliation pass. In-flight events that were drained between the backup
timestamp and the restore point are re-emitted; CITADEL deduplicates on
`correlation_id` so replays are safe. See
[citadel-integration.md](citadel-integration.md).

---

## Post-migration verification

Run these checks immediately after every migration in production:

```bash
# 1. API health
curl -sf https://cyberpath.internal:8086/api/v1/health | jq .

# 2. Integration status
curl -sf https://cyberpath.internal:8086/api/v1/health | jq '.integrations'
# Expected: { "citadel": "connected", "nis2compass": "connected", "irflow": "connected" }

# 3. Migration version matches expected
make migrate-status

# 4. No content hash mismatches
psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM content_versions WHERE content_hash IS NULL OR content_hash = '';"
# Expected: 0

# 5. No unsubmitted completions blocked in outbox for > 10 minutes
psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM outbox
     WHERE submitted_at IS NULL
       AND created_at < now() - interval '10 minutes';"
# Expected: 0 (or draining)

# 6. Prometheus metric — content version mismatch
curl -sf https://cyberpath.internal:8086/metrics \
    | grep cyberpath_content_version_mismatch_total
# Expected: 0

# 7. Run integration test suite against staging (if available)
make test-integration
```

For v1.0.0+ deployments, also verify certification signing:

```bash
cyberpath-cli cert verify --sample 5
# Spot-checks 5 random certifications against the published Ed25519 public key.
```

---

## See also

- [migrations.md](migrations.md) — schema migration tooling reference
- [data-model.md](data-model.md) — full schema with GDPR/retention notes
- [disaster-recovery.md](disaster-recovery.md) — backup restore procedure
- [operator-handbook.md](operator-handbook.md) — key rotation and daily ops
- [citadel-integration.md](citadel-integration.md) — outbox replay semantics
- [deployment.md](deployment.md) — image upgrade procedure
