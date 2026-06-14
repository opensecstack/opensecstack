# CITADEL Operator Runbook

Day-to-day procedures for running CITADEL in production. For incident
response (unplanned operations), see [sop-012-incident.md](./sop-012-incident.md).
For HARD_STOP handling, see [hard-stop-playbook.md](./hard-stop-playbook.md).

## Morning checks (5 minutes)

Every on-call shift starts with:

```bash
# 1. Health
curl -sf https://citadel.internal/api/v1/health | jq .

# 2. Chain integrity for the last 24 h
curl -sf "https://citadel.internal/api/v1/worm/verify?from=$(date -u -d '1 day ago' +%FT%TZ)&to=$(date -u +%FT%TZ)" | jq .

# 3. Anchor production rate (should match configured interval)
curl -sf https://citadel.internal/metrics | grep citadel_anchors_created_total

# 4. WORM append latency p95 (should be < 10 ms)
curl -sf https://citadel.internal/metrics | grep 'citadel_worm_append_seconds{quantile="0.95"}'
```

All four must be green. If any is red, start triage with [sop-012-incident.md](./sop-012-incident.md).

## Weekly

### Full chain verification

Every Monday, verify the entire chain from the previous week's last
verified point to now. Takes 1-10 min depending on volume.

```bash
last_verified=$(cat /var/cache/citadel/last-verified-seq)
now=$(date -u +%FT%TZ)
curl -sf "https://citadel.internal/api/v1/worm/verify?from_seq=${last_verified}&to=${now}" | jq .
```

On `"valid": true`, update the cache with the latest sequence_num.
On `"valid": false`, **stop** and follow [SOP-012A](./sop-012-incident.md#sop-012a--worm-chain-verification-failure).

### Metrics review

Spend 10 minutes with the CITADEL Grafana dashboard looking at:

- MARSHAL decision mix (`citadel_marshal_decisions_total{outcome}`).
  A sudden rise in REFUSE or HARD_STOP is worth investigating even if
  no alert fired.
- Gate-3 NDS failure rate — should be near zero in a healthy
  deployment. Any non-zero rate means either colluding clients or
  misconfigured SoD.
- WORM append latency trend — month-over-month drift points at
  disk I/O degradation before it becomes an incident.

## Monthly

### Anchor key custody check

Confirm:

- `CITADEL_CITADEL_MASTER_KEY` is loaded from the secret manager (not
  hard-coded).
- The secret-manager version matches the expected `pubkey_id` in
  `chain_anchors`.
- Nobody unexpected has read access to the secret manager path.
- Last rotation date is within the rotation cadence from [SECURITY.md](../SECURITY.md).

### Session TTL sanity

```sql
-- Expired sessions still in the table
SELECT count(*) FROM sessions WHERE expires_at < now();

-- Should be ~0 if the GC worker is running
```

If > 1000 expired sessions are sitting around, the GC worker is
broken. Check its logs; restart if needed.

## Quarterly

### Rotation drill

Rehearse the anchor-key rotation runbook without deploying (dry-run):

1. Generate a test keypair.
2. Walk through the config-update steps on a staging cluster.
3. Verify the test anchors signed by the new key verify correctly.
4. Time the whole thing — target < 30 min including verification.

Document the rehearsal date in the on-call log. An anchor-key
rotation that *hasn't* been rehearsed is not a rotation runbook,
it's a prayer.

### NIS2 evidence check

If your deployment is NIS2-in-scope:

- Confirm the retention window (default indefinite; verify if you
  deploy-configured anything else).
- Sample 10 random WORM entries, produce a signed export bundle,
  verify the signatures.
- Check the bundle's size — it should be reasonable; surprising
  bloat indicates payload drift that deserves investigation.

## Operational knobs

### Dry-run mode

```bash
# Set on the engine; every Kerkese's dry_run is coerced to true
CITADEL_DRY_RUN=true
```

See [dry-run.md](./dry-run.md). **Never** in production.

### WORM read-only

```bash
CITADEL_WORM_READONLY=true
```

Used during incident investigation — MARSHAL evaluates but Gate 5
refuses to append. Callers receive 503 on mutating operations.

### Anchor interval

```bash
CITADEL_CITADEL_ANCHOR_INTERVAL=100   # default
```

Lowering increases anchor count and crypto work; raising widens the
window an attacker could retrospectively tamper inside. 100 is the
sweet spot for most deployments.

## Deployment

### Rolling out a new version

CITADEL is stateless with respect to process state; all persistence
is in Postgres. A rolling update with 2+ replicas is zero-downtime.

```bash
# New image
kubectl set image deployment/citadel citadel=ghcr.io/opensecstack/citadel:1.1.0

# Watch the rollout
kubectl rollout status deployment/citadel
```

The WORM lock in `AppendWORM` (`LOCK TABLE ... EXCLUSIVE MODE`)
serialises writes across replicas automatically — rolling update does
not produce split-brain.

### Database migrations

```bash
# Run as a one-shot job, never in-place
make migrate
```

Migrations are idempotent. Running against an up-to-date DB exits 0
with a single info log.

### Secret rotation

See [SECURITY.md § Key management](../SECURITY.md).

## Scaling

### Vertical

PostgreSQL 16 is the bottleneck at Gate 5. Scale the DB:

- Faster disk (provisioned IOPS).
- More memory for shared_buffers.
- More CPU helps throughput proportionally until disk saturates.

### Horizontal

CITADEL itself is stateless and horizontally scalable. The chain
itself is **not** — multi-writer is a v2.0 feature.

For v1.x, horizontal scale means more read replicas (serving
`/verify` queries) + active/passive CITADEL primaries (only one
writes at a time, via Consul leader lock or Kubernetes Lease).

## Backup and restore

### Backup

- Daily `pg_dump` of the CITADEL database.
- Weekly full PITR checkpoint.
- **Backups must include `worm_entries` and `chain_anchors` consistently**
  — snapshot-based backups (pg_basebackup with WAL archiving) are the
  safe default.

Keep backups for the full retention window. A 6-month backup is
useless for 7-year evidence retention.

### Restore

1. Provision a fresh Postgres cluster.
2. Restore from the latest consistent backup.
3. Start CITADEL pointed at it.
4. Run `GET /api/v1/worm/verify?from=...&to=...` covering the full
   backed-up range — must return `"valid": true`.
5. If `"valid": false`, the backup was inconsistent — try the next
   earliest backup.

Document the restore rehearsal quarterly.

## Escalation matrix

| Symptom | Page |
|---|---|
| `/health` down for > 2 min | CITADEL on-call (P1) |
| `/worm/verify` returns `valid: false` | CITADEL on-call + security lead (P1) |
| Anchor-key compromise suspected | Security lead + CITADEL on-call (P1) |
| Append latency p95 > 50 ms sustained | CITADEL on-call (P2) |
| GC worker not running | CITADEL on-call (P3) |

## Related

- [SOP-012 CITADEL incident runbook](./sop-012-incident.md)
- [HARD_STOP playbook](./hard-stop-playbook.md)
- [Pre-freeze checklist](./pre-freeze-checklist.md)
- [SECURITY.md](../SECURITY.md)
