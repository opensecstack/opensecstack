# Disaster Recovery

Backup, restore and rollback procedures for VertGuard v1.0.0.
This is the operator-facing companion to
[`operator-runbook.md`](operator-runbook.md): the runbook is for
"the service is unhealthy right now"; this doc is for "the service
or its data is gone or corrupted".

Scope: a single VertGuard installation (Postgres + ML sidecar +
trust-store + secrets + chart overlays). **Out of scope**: full
datacenter loss, ecosystem-wide governance failover (deferred to
the OpenSecStack-level DR plan once it lands; track via the
`docs/` directory at the root of the monorepo).

## What to back up

| Asset | Source of truth | Backup target | Notes |
|---|---|---|---|
| Postgres logical dumps | `pg_dump` from the chart's primary | Encrypted object store (S3 + SSE-KMS) | Tables: see [`internal/db/migrations/`](../internal/db/migrations/) — `prompt_scans`, `phishing_scans`, `identity_scans`, `audit_events`, `webhook_subscribers`, `token_denylist`, `rate_limit_overrides`, `threat_iocs`. |
| CITADEL chain anchor signing keys | HSM (production) / sealed in cluster (dev) | Offline HSM backup OR sealed-secrets-controller key bundle | Loss of these keys means the WORM chain cannot be re-anchored. Treat as Tier-0 secret. |
| JWT signing secret (`auth-secret`) | K8s Secret (sealed-secrets / ESO) | Same as cluster secret backups | Rotation cadence is 90 days — see [`secrets-management.md`](secrets-management.md). |
| Outbound-integration secrets (`citadel-hmac-secret`, `threatflow-webhook-secret`, `db-password`) | K8s Secret | Same | Rotation cadence per the catalogue in [`secrets-management.md`](secrets-management.md). |
| Model artefacts (`distilbert-prompt`, `distilbert-phishing`) | S3 model registry bucket with **versioning enabled** | Cross-region replica bucket | See [`ml-model-registry.md`](ml-model-registry.md). Bucket-level versioning means deletion is recoverable. |
| C2PA trust-store PEM bundle | Git (public roots) + Secret (private CA material) | Backed up with secrets | See [`c2pa-trust-store.md`](c2pa-trust-store.md) and [`c2pa-deployment.md`](c2pa-deployment.md). |
| Helm values overlays | Git (the deployment repo) | Off-site git mirror | Should already follow your SCM DR policy. |
| Pattern registry contents (`/etc/vertguard/patterns/`) | Mounted from a ConfigMap or PVC | Logical export of the ConfigMap, or PVC snapshot | Static for v1.0.0; bundled with the chart. |

## Backup cadence (RPO targets)

| Asset class | RPO | Cadence | Retention |
|---|---|---|---|
| Detection rows (`prompt_scans`, `phishing_scans`, ...) | **1 h** | Hourly logical dumps | 30 days hot, 1 year cold |
| Audit events (`audit_events`) | **1 h** (same dump) | Hourly | 7 years (NIS2 evidence) |
| Threat IOC catalogue (`threat_iocs`) | 24 h | Daily | 90 days; can be re-derived from ThreatFlow |
| Cluster secrets | 24 h | Daily | 90 days, encrypted at rest |
| Model artefacts | **Indefinite** | Per-promotion (see registry) | Forever — never delete a model that was ever served |
| Trust-store PEM | 24 h | Daily | 90 days |
| Helm overlays | Continuous (git push) | Per commit | Forever |

Postgres hourly logical dump example (run from a backup pod
inside the cluster, credentials from the same Secret the
Deployment uses):

```bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
PGPASSWORD="${VERTGUARD_DB_PASSWORD}" pg_dump \
    --host vertguard-postgresql \
    --username vertguard \
    --dbname vertguard \
    --format=custom \
    --no-owner \
    --file "/tmp/vertguard-${TS}.dump"

aws s3 cp "/tmp/vertguard-${TS}.dump" \
    "s3://vg-backups/postgres/$(date -u +%Y/%m/%d)/vertguard-${TS}.dump" \
    --sse aws:kms

# Sanity-check after upload.
aws s3 ls "s3://vg-backups/postgres/$(date -u +%Y/%m/%d)/" --human-readable
```

Wire this as a `CronJob` (every hour at minute 5; stagger 5
minutes from CITADEL backups to avoid IO contention).

## RTO targets

| Scenario | RTO | Procedure |
|---|---|---|
| Single API pod crash | < 30 s | k8s self-heals; no human action |
| ML sidecar crash | < 60 s | `select_backend()` re-runs on restart; Go side has a circuit breaker |
| Bad model release | **< 5 min** | [Model rollback](#model-rollback) — env var swap |
| Postgres primary loss with hot standby | **< 15 min** | Failover to replica; chart points at the new primary |
| Full Postgres restore from backup | **< 4 h** | [Postgres restore](#postgres-restore) below |
| Cluster-level loss (rebuild from chart + backups) | < 4 h | Re-deploy chart, restore secrets, restore DB, verify |

## Restore procedures

### Postgres restore

```bash
# 0. Stop writes. Either scale the API to 0 or set the chart's
#    networkPolicy to deny ingress while restoring.
kubectl -n vertguard scale deploy/vertguard --replicas=0

# 1. Provision a new empty database (or drop+recreate the existing one).
kubectl -n vertguard exec -it sts/vertguard-postgresql -- \
    psql -U postgres -c "DROP DATABASE IF EXISTS vertguard;"
kubectl -n vertguard exec -it sts/vertguard-postgresql -- \
    psql -U postgres -c "CREATE DATABASE vertguard OWNER vertguard;"

# 2. Pull the dump locally.
aws s3 cp s3://vg-backups/postgres/2026/04/26/vertguard-20260426T0405Z.dump ./restore.dump

# 3. Stream into the cluster pod and restore.
kubectl -n vertguard cp ./restore.dump vertguard-postgresql-0:/tmp/restore.dump
kubectl -n vertguard exec -it sts/vertguard-postgresql-0 -- \
    pg_restore -U vertguard -d vertguard --no-owner --clean --if-exists \
    /tmp/restore.dump

# 4. Sanity-check schema_migrations and a recent table.
kubectl -n vertguard exec sts/vertguard-postgresql-0 -- \
    psql -U vertguard -d vertguard -c \
    "SELECT version, name, applied_at FROM schema_migrations ORDER BY version;"
kubectl -n vertguard exec sts/vertguard-postgresql-0 -- \
    psql -U vertguard -d vertguard -c \
    "SELECT count(*), max(created_at) FROM prompt_scans;"

# 5. Re-run any pending migrations against the restored DB.
#    (Only needed if you restored a dump from before the current chart's migration set.)
kubectl -n vertguard exec deploy/vertguard -- /vertguard migrate up

# 6. Scale the API back up.
kubectl -n vertguard scale deploy/vertguard --replicas=2

# 7. Confirm health.
kubectl -n vertguard exec deploy/vertguard -- \
    wget -qO- http://localhost:8091/api/v1/health
```

### CITADEL chain re-anchor

The CITADEL WORM chain is append-only and signed; VertGuard's
detections reference WORM entries by `worm_entry_id`. After a
VertGuard restore the chain itself is unaffected (it lives in
CITADEL, not VertGuard) — but if VertGuard's outbound HMAC key
or its CITADEL `key_id` changed during the incident, downstream
verifiers must be told.

The rule: **re-anchoring requires republishing the latest signed
anchor, plus a grace period during which both the old and new
key are accepted by downstream verifiers.** Skipping the grace
period strands consumers that pull on a slower cadence.

```bash
# 1. Confirm the current key state in the chart.
kubectl -n vertguard get secret vertguard-secrets -o jsonpath='{.data.citadel-hmac-secret}' \
    | base64 -d | sha256sum

# 2. Mint and seal the new key (sealed-secrets path; ESO equivalent
#    is documented in secrets-management.md).
NEW_KEY=$(openssl rand -base64 48)
kubectl -n vertguard create secret generic vertguard-secrets-rotated \
    --from-literal=citadel-hmac-secret="${NEW_KEY}" \
    --dry-run=client -o yaml | kubeseal -o yaml > sealed-rotated.yaml

# 3. Notify CITADEL of the new key_id BEFORE switching VertGuard over.
#    CITADEL accepts both old and new key_id during the grace window.
curl -sS -X POST https://citadel.internal:8099/api/v1/keys/register \
    -H 'Content-Type: application/json' \
    -d '{"actor":"vertguard","key_id":"vg-2026-04","grace_seconds":3600}'

# 4. Apply the rotated Secret and roll the Deployment.
kubectl apply -f sealed-rotated.yaml
kubectl -n vertguard rollout restart deploy/vertguard

# 5. After the grace window, decommission the old key in CITADEL.
curl -sS -X POST https://citadel.internal:8099/api/v1/keys/retire \
    -H 'Content-Type: application/json' \
    -d '{"actor":"vertguard","key_id":"vg-2025-q4"}'
```

For chain semantics (signing envelope, anchor cadence, MARSHAL
gate) see [`citadel-integration.md`](citadel-integration.md).

### Model rollback

Covered in detail in [`model-deployment.md`](model-deployment.md).
Summary: one env-var swap (`VERTGUARD_ML_MODEL_DIR`) plus an ML
sidecar restart. No data migration. Old `prompt_scans` rows keep
their original `model_version` field and remain valid.

### Secret rotation post-incident

Assume an HSM compromise or leaked secret. Rotate **all four**
sensitive values catalogued in
[`secrets-management.md`](secrets-management.md), in this order
to minimise downtime:

1. `db-password` — rotate the Postgres role first (operator can
   do this online with `ALTER USER ... PASSWORD`); then update
   the Secret and roll the Deployment.
2. `citadel-hmac-secret` — follow the [chain re-anchor](#citadel-chain-re-anchor)
   grace-period procedure.
3. `threatflow-webhook-secret` — rotate via ThreatFlow's webhook
   admin endpoint, then update VertGuard's Secret.
4. `auth-secret` — rotate last. **All in-flight tokens are
   invalidated**; clients must re-authenticate. Coordinate with
   API consumers before doing this in production.

After every step, confirm `/api/v1/health` returns 200 and the
Prometheus alerts in [`operator-runbook.md`](operator-runbook.md)
§1 are clean.

## Test cadence

| Drill | Cadence | Expected output |
|---|---|---|
| Postgres restore from yesterday's dump into a scratch DB | **Quarterly** | `schema_migrations` matches HEAD; `count(*)` on `prompt_scans` matches a sampled hourly metric within ±1 row |
| Model rollback (swap env var, restart, smoke test) | Quarterly | `ModelInfo.version` reverts; canonical bad/clean prompts classify correctly |
| CITADEL chain re-anchor with synthetic key | Annually | New `key_id` accepted; old `key_id` retired; no `worm_emit_total{result="fail"}` increase during grace window |
| Full chart re-deploy into an empty namespace | Annually | API reaches `Ready` within RTO; smoke tests pass; backup CronJobs schedule correctly |

Document each drill's outcome in
`docs/runbook-drills/<YYYY-QQ>.md` (create as needed). Failed
drills must produce a follow-up issue tagged `dr` before the
quarter closes.

## Cross-platform considerations

VertGuard depends on two upstream platforms:

- **CITADEL** (`:8099` per [`../../docs/deployment-topology.md`](../../docs/deployment-topology.md))
  — WORM evidence and MARSHAL gate. Without CITADEL, VertGuard
  detections still complete but the `worm_entry_id` field is
  null and audit-trail completeness suffers.
- **ThreatFlow** (`:8084`) — IOC consumption and pushes.
  VertGuard caches IOCs locally, so a short ThreatFlow outage
  is invisible.

**Recovery order** during a wider ecosystem outage:

1. **CITADEL first.** Without it, every VertGuard detection
   fails its WORM-emit and the audit trail is broken.
2. **VertGuard.** Once CITADEL is healthy, restore VertGuard
   per the procedures above.
3. **ThreatFlow consumers.** ThreatFlow can come back last; its
   IOCs flow into VertGuard asynchronously.

Refer to [`../../docs/deployment-topology.md`](../../docs/deployment-topology.md)
for port assignments and the canonical platform layout.

## Out of scope

- **Full datacenter / region loss.** Cross-region failover is
  the responsibility of the ecosystem-level DR plan
  (compatibility-matrix.md, deployment-topology.md). This doc
  assumes the cluster is reachable and at least one healthy
  Postgres backend exists somewhere.
- **Disaster recovery for CITADEL or ThreatFlow themselves.**
  Each platform owns its own DR plan; see their respective
  `docs/` directories.
- **Forensic analysis of compromised data.** This doc covers
  restore-to-known-good; full forensic procedures live with the
  IRFlow runbooks.

## See also

- [`operator-runbook.md`](operator-runbook.md) — incident
  triage decision tree.
- [`secrets-management.md`](secrets-management.md) — sensitive
  field catalogue + rotation policy.
- [`citadel-integration.md`](citadel-integration.md) — chain
  semantics, WORM emit flow, MARSHAL gate.
- [`model-deployment.md`](model-deployment.md) — full model
  rollback procedure.
- [`c2pa-deployment.md`](c2pa-deployment.md) — trust-store
  provisioning (input to backup planning).
- [`deployment-helm.md`](deployment-helm.md) — chart reference.
- [`../../docs/deployment-topology.md`](../../docs/deployment-topology.md)
  — ecosystem port matrix and recovery dependencies.
- [`../../docs/release-process.md`](../../docs/release-process.md)
  — version management context for backup compatibility.
