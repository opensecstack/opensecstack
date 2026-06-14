# CyberPath Disaster Recovery

Operational runbook for recovering CyberPath from data-loss or
infrastructure failure events. For routine backup verification cadence, see
[operator-handbook.md](operator-handbook.md). For the schema migration
context of a post-restore forward-migration, see
[migration-guide.md](migration-guide.md).

> Status: design intent for v1.0.0. Targets and procedures are validated
> against the Docker Compose (single-host) and Helm / Kubernetes
> topologies described in [deployment.md](deployment.md).

---

## Recovery targets

| Target | Value | Notes |
|---|---|---|
| RPO (Recovery Point Objective) | 24 hours | Daily automated `pg_dump` retained 30 days |
| RTO (Recovery Time Objective) | 4 hours | Restore + verify + restart for a single-host deploy; 2 hours for pre-provisioned standby |
| Certification key RPO | 0 (KMS-resident) | Ed25519 signing key is KMS-backed; not in the database backup |
| CITADEL completion ledger | Best-effort replay | Completions drained to CITADEL before the failure are recoverable from the CITADEL WORM; unsubmitted outbox entries replay on startup |

If your deployment has stricter RPO requirements, supplement the daily
logical backup with PostgreSQL WAL shipping (continuous archiving) to
achieve near-zero RPO. CyberPath itself imposes no constraint on WAL
archiving — it is a database-layer concern.

---

## What is the source of truth

| Asset | Where it lives | Backed up how |
|---|---|---|
| User identities, completions, certifications, audit events | PostgreSQL `cyberpath` database | `pg_dump -Fc`, daily |
| Lab content (lesson bodies, quiz banks) | `/var/lib/cyberpath/content/` (bind-mounted) | rsync to versioned object-store bucket, daily |
| CITADEL WAL (local outbox buffer) | `CYBERPATH_CITADEL_WAL_PATH` (default `/var/lib/cyberpath/citadel-wal`) | Flushed on startup; back up with content directory |
| Ed25519 certification signing key | KMS (not on disk) | KMS disaster recovery per your KMS provider's documentation |
| CITADEL WORM ledger | CITADEL (external, immutable) | Upstream; reconcile from it post-restore via `make reconcile-citadel` |
| Lab container images | OCI registry (content-addressed) | External; images are pinned by digest in `lab_definitions.image_digest` |

The PostgreSQL database is the primary source of truth. Everything else is
either reproducible, externally retained, or cached.

---

## Backup strategy

### PostgreSQL — logical backup

```bash
#!/usr/bin/env bash
# /etc/cron.daily/cyberpath-backup
set -euo pipefail

TS=$(date -u +%Y%m%dT%H%M%SZ)
DEST="/var/backups/cyberpath"
DUMP="${DEST}/cyberpath-${TS}.dump"

mkdir -p "$DEST"

pg_dump -Fc \
    --host "${CYBERPATH_DB_HOST}" \
    --username cyberpath \
    --no-password \
    cyberpath \
    > "$DUMP"

# Verify the dump is non-empty
test -s "$DUMP" || { echo "ERROR: dump is empty" >&2; exit 1; }

# Encrypt at rest (GPG symmetric; key from secret manager)
gpg --batch --yes --symmetric --passphrase-file /run/secrets/backup-passphrase \
    --output "${DUMP}.gpg" "$DUMP"
rm -f "$DUMP"

# Rotate: keep 30 days
find "$DEST" -name "cyberpath-*.dump.gpg" -mtime +30 -delete

echo "Backup complete: ${DUMP}.gpg"
```

Set `PGPASSWORD` or use `.pgpass`; never pass the password on the command
line. Store the backup passphrase in your secret manager, not in the
script.

### Content directory backup

```bash
# Daily rsync to a versioned object-store bucket (S3-compatible)
aws s3 sync /var/lib/cyberpath/content/ \
    s3://your-bucket/cyberpath-content/ \
    --delete \
    --storage-class STANDARD_IA
```

Content is append-only by platform convention (Module 8 —
`content_versions` rows are never updated or deleted). Incremental rsync
diffs are therefore small. Keep at least 30 days of versions.

### CITADEL WAL backup

The local WAL at `CYBERPATH_CITADEL_WAL_PATH` is a durable write-ahead
buffer. If it is lost, in-flight events not yet acknowledged by CITADEL
are re-emitted from the `outbox` table on the next startup. Back up the
WAL directory as part of the content directory rsync:

```bash
aws s3 sync "${CYBERPATH_CITADEL_WAL_PATH}" \
    s3://your-bucket/cyberpath-citadel-wal/ \
    --storage-class STANDARD_IA
```

### Certification signing key

The Ed25519 signing key is KMS-resident. CyberPath holds only the KMS
reference string in `CYBERPATH_CERT_SIGNING_KEY`. Key recovery follows
your KMS provider's disaster-recovery procedure. Document the emergency
unwrap procedure separately in your secure runbook and test it quarterly.

---

## Restore procedures

### Full database restore (single-host)

Use this when the primary database is unrecoverable (host failure,
accidental DROP, corruption).

```bash
# Step 1 — Stop CyberPath
docker compose -f docker-compose.yml -f docker-compose.prod.yml stop api

# Step 2 — Identify the latest good backup
ls -lt /var/backups/cyberpath/cyberpath-*.dump.gpg | head -5

# Step 3 — Decrypt the backup
gpg --batch --yes --decrypt \
    --passphrase-file /run/secrets/backup-passphrase \
    --output /tmp/cyberpath-restore.dump \
    /var/backups/cyberpath/cyberpath-YYYYMMDDTHHMMSSZ.dump.gpg

# Step 4 — Drop and recreate the database
psql "postgres://admin:***@db.internal:5432/postgres" <<SQL
  SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
  WHERE datname = 'cyberpath' AND pid <> pg_backend_pid();
  DROP DATABASE IF EXISTS cyberpath;
  CREATE DATABASE cyberpath OWNER cyberpath;
SQL

# Step 5 — Restore
pg_restore \
    --host db.internal --username cyberpath \
    --dbname cyberpath \
    --no-acl --no-owner \
    /tmp/cyberpath-restore.dump

# Step 6 — Apply any forward migrations that postdate the backup
# (if the backup predates the current application version)
make migrate-up

# Step 7 — Restore content directory from object store
aws s3 sync s3://your-bucket/cyberpath-content/ \
    /var/lib/cyberpath/content/

# Step 8 — Start CyberPath
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d api

# Step 9 — Verify (see Post-restore validation below)
```

Shred the decrypted dump after restore:

```bash
shred -u /tmp/cyberpath-restore.dump
```

### Database restore — Kubernetes

```bash
# Step 1 — Scale down
kubectl scale deployment cyberpath-api --replicas=0 -n cyberpath

# Step 2 — Run a restore job
kubectl run cyberpath-restore \
    --image=ghcr.io/opensecstack/cyberpath:<version> \
    --restart=Never -n cyberpath \
    --env="CYBERPATH_DB_URL=${CYBERPATH_DB_URL}" \
    -- sh -c "
        gpg --batch --yes --decrypt \
            --passphrase-file /run/secrets/backup-passphrase \
            --output /tmp/restore.dump \
            /backups/cyberpath-YYYYMMDDTHHMMSSZ.dump.gpg && \
        pg_restore --clean --if-exists --dbname \$CYBERPATH_DB_URL \
            /tmp/restore.dump && \
        rm -f /tmp/restore.dump
    "

kubectl wait --for=condition=Succeeded pod/cyberpath-restore -n cyberpath

# Step 3 — Run migrations
kubectl run cyberpath-migrate \
    --image=ghcr.io/opensecstack/cyberpath:<version> \
    --restart=Never -n cyberpath \
    --env="CYBERPATH_DB_URL=${CYBERPATH_DB_URL}" \
    -- cyberpath-cli migrate up

kubectl wait --for=condition=Succeeded pod/cyberpath-migrate -n cyberpath

# Step 4 — Scale up
kubectl scale deployment cyberpath-api --replicas=3 -n cyberpath
```

### Partial restore — single table

Use when only one table is corrupt or accidentally truncated. The
`completions` and `content_versions` tables are append-only; a partial
restore is additive (insert missing rows, never overwrite).

```bash
# Extract a single table from the dump
pg_restore \
    --data-only \
    --table=completions \
    --host db.internal --username cyberpath \
    --dbname cyberpath \
    /tmp/cyberpath-restore.dump
```

After a partial completions restore, run the CITADEL reconciliation sweep
to ensure no events are missing from the ledger:

```bash
make reconcile-citadel
```

---

## Failover runbook

Use this when the primary host or database primary is unavailable and you
have a warm standby.

### Promote a PostgreSQL streaming replica

```bash
# On the replica host — promote to primary
pg_ctl promote -D /var/lib/postgresql/16/main

# Confirm promotion
psql "postgres://cyberpath:***@standby.internal:5432/cyberpath" \
    -c "SELECT pg_is_in_recovery();"
# Expected: f (false — no longer a replica)

# Update CyberPath config to point at the new primary
# Edit CYBERPATH_DB_URL in /etc/cyberpath/cyberpath.env:
# CYBERPATH_DB_URL=postgres://cyberpath:***@standby.internal:5432/cyberpath?sslmode=verify-full

# Restart CyberPath
docker compose -f docker-compose.yml -f docker-compose.prod.yml restart api
```

Replication lag at the moment of failover determines how much data was
not yet applied to the replica. This gap is your effective RPO for the
failover event. If WAL archiving is enabled, you can replay archived WAL
segments to close the gap before promoting.

### DNS/load-balancer cutover

If your deployment uses a virtual IP or DNS-based failover (Keepalived,
Route 53 health checks), update the DNS record or virtual IP to point at
the standby host. CyberPath connects to Postgres via the URL in
`CYBERPATH_DB_URL` — update this env var and restart if the DB hostname
changes.

---

## CITADEL reconciliation after restore

After any restore, run the reconciliation sweep to re-emit completions
that were in the `outbox` but not yet acknowledged by CITADEL at the
time of the backup:

```bash
make reconcile-citadel
```

This command queries:

```sql
SELECT * FROM outbox
WHERE submitted_at IS NULL
ORDER BY next_attempt_at;
```

and retries each unsubmitted event. CITADEL deduplicates on
`correlation_id`; events that were already received before the failure
are silently acknowledged. Events that were genuinely lost are
re-submitted and assigned a new `ledger_id`.

Monitor progress:

```bash
watch -n 10 'psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM outbox WHERE submitted_at IS NULL;"'
```

The queue should drain to zero within a few minutes under normal
CITADEL connectivity.

---

## Post-restore data validation

Run all of the following after every restore before re-opening traffic:

```bash
# 1. API health
curl -sf https://cyberpath.internal:8086/api/v1/health | jq .
# All fields should show status: "ok"

# 2. Integration connectivity
curl -sf https://cyberpath.internal:8086/api/v1/health | jq '.integrations'
# Expected: { "citadel": "connected", "nis2compass": "connected", "irflow": "connected" }

# 3. Migration version matches expected release
make migrate-status

# 4. Content hash integrity — no NULL or blank hashes
psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM content_versions
     WHERE content_hash IS NULL OR content_hash = '';"
# Expected: 0

# 5. Completion count sanity — cross-check against CITADEL ledger count
psql "$CYBERPATH_DB_URL" -c "SELECT count(*) FROM completions;"
cyberpath-cli admin citadel-count  # queries CITADEL project completion count
# These should agree within the expected replication lag window.

# 6. Spot-check 5 random certifications against published Ed25519 key
cyberpath-cli cert verify --sample 5

# 7. Confirm no content mismatch metric
curl -sf https://cyberpath.internal:8086/metrics \
    | grep cyberpath_content_version_mismatch_total
# Expected value: 0

# 8. Confirm CITADEL queue is draining
psql "$CYBERPATH_DB_URL" -c \
    "SELECT count(*) FROM outbox WHERE submitted_at IS NULL;"
# Should decrease toward 0 within 5 minutes

# 9. Run a smoke-test lesson completion end-to-end (staging only)
# cyberpath-cli smoketest --lesson <lesson-id> --user <test-user-id>
```

Do not re-open learner traffic until all nine checks pass.

---

## DR test schedule

| Frequency | Test | Responsible |
|---|---|---|
| Weekly | Verify most recent `pg_dump` is non-empty and non-corrupt: `pg_restore --list` against the dump file | Operator (automated script) |
| Monthly | Full restore into a dedicated staging cluster; run post-restore validation checklist; spot-check 5 completions against CITADEL ledger | Operator |
| Quarterly | Full DR rehearsal: simulate primary host loss, promote replica, restore content, run all validations, measure actual RTO | Operator + on-call lead |
| Annually | Test KMS key emergency unwrap procedure; verify backup passphrase is current and accessible from the secret manager | Security lead |

Record the date, measured RTO, and any deviation from this runbook after
each quarterly rehearsal. Track deviations as issues against the
`opensecstack/cyberpath` repository.

---

## Escalation contacts

| Situation | First contact | Escalate to |
|---|---|---|
| Database host failure / unavailable | Operator on-call | Infrastructure lead |
| KMS unavailable (cert signing broken) | Operator on-call | Security lead + KMS vendor support |
| CITADEL unreachable > 30 minutes | Operator on-call | CITADEL team |
| Backup missing / corrupt for > 24h | Operator on-call | Infrastructure lead + security lead |
| Suspected data tampering | Security lead | CISO; file `security.cyberpath.integrity` event in CITADEL |
| Sandbox escape confirmed | Security lead | CISO; see [../SECURITY.md](../SECURITY.md) |

Escalation paths and pager-duty configuration are maintained in the
internal runbook. This document specifies roles, not individuals, to
remain stable across personnel changes.

---

## See also

- [operator-handbook.md](operator-handbook.md) — backup verification cadence, key rotation
- [migration-guide.md](migration-guide.md) — applying forward migrations after restore
- [deployment.md](deployment.md) — host provisioning, Compose and Helm topology
- [citadel-integration.md](citadel-integration.md) — outbox semantics, reconciliation
- [data-model.md](data-model.md) — which tables are audit-chain protected (RESTRICT cascades)
- [../SECURITY.md](../SECURITY.md) — incident disclosure SLA
