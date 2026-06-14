# Deploying CITADEL

This document covers running CITADEL in production. For day-to-day
operations once running, see [operator-runbook.md](./operator-runbook.md).
For incident response, see [sop-012-incident.md](./sop-012-incident.md).

## System requirements

| Component | Minimum | Recommended |
|---|---|---|
| CPU | 2 vCPU | 4 vCPU |
| Memory | 512 MiB | 1 GiB per replica |
| PostgreSQL | 16 | 16 |
| Go (for building) | 1.24 | 1.24 |
| Disk | 1 GiB ephemeral + DB volume | SSD / provisioned IOPS for DB |

CITADEL itself is lightweight. Its critical dependency is PostgreSQL —
Gate 5 WORM append is disk-bound (4.22 ms baseline on Postgres 16),
and every MARSHAL decision round-trips through it. Size the DB for
your event volume.

## Configuration summary

Full reference in [configuration.md](./configuration.md). The minimum
a production deploy must set:

| Variable | Required? | Notes |
|---|---|---|
| `CITADEL_DB_URL` | **Required** | PostgreSQL connection string |
| `CITADEL_CITADEL_MASTER_KEY` | **Required in production** | Ed25519 anchor private key (64 hex chars) |
| `CITADEL_PORT` | No | Default 8099 |
| `CITADEL_LOG_LEVEL` | No | Default `info` |
| `CITADEL_CITADEL_ANCHOR_INTERVAL` | No | Default 100 |

Leaving `CITADEL_CITADEL_MASTER_KEY` empty disables anchor signing
with a loud WARN — the WORM chain is still tamper-evident, but not
tamper-resistant. **Never** run production without it.

## Local docker-compose (dev + integration)

The shipped [docker-compose.yml](../docker-compose.yml) brings up
Postgres on port 5434 (host) + CITADEL on 8099:

```bash
cd citadel/
docker-compose up --build -d

# Verify
curl -sf http://localhost:8099/api/v1/health | jq .
# { "status":"ok", "db":"ok", "version":"...", "commit":"...", "built":"..." }
```

The compose file mounts `migrations/001_initial.sql` into the Postgres
init directory, so the DB comes up with schema applied. For production
migrations, use a dedicated job — do not rely on the init-dir
mechanism beyond development.

## Production shape

A minimum production deploy needs:

1. **CITADEL Deployment** — container image, 1-2 replicas behind a
   Service (see "HA model" below). Stateless; replicas share the DB.
2. **Migration job** — one-shot, runs `make migrate` (or equivalent
   SQL apply) before each rollout that changes schema.
3. **Secret** containing `CITADEL_DB_URL` + `CITADEL_CITADEL_MASTER_KEY`.
4. **ConfigMap** for non-sensitive settings.
5. **PostgreSQL 16** — managed (RDS, Cloud SQL, AlloyDB) preferred.

## Kubernetes manifests

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: citadel
  labels: { app: citadel }
spec:
  replicas: 1                          # see HA model section
  strategy: { type: Recreate }         # single-writer chain; avoid concurrent old+new
  selector: { matchLabels: { app: citadel } }
  template:
    metadata: { labels: { app: citadel } }
    spec:
      containers:
      - name: citadel
        image: ghcr.io/opensecstack/citadel:1.0.0
        ports: [{ containerPort: 8099 }]
        envFrom:
          - configMapRef: { name: citadel-config }
          - secretRef:    { name: citadel-secrets }
        livenessProbe:
          httpGet: { path: /api/v1/health, port: 8099 }
          periodSeconds: 10
        readinessProbe:
          httpGet: { path: /api/v1/health, port: 8099 }
          periodSeconds: 5
        resources:
          requests: { cpu: "200m", memory: "256Mi" }
          limits:   { cpu: "1000m", memory: "1Gi" }
```

### ConfigMap + Secret

```yaml
apiVersion: v1
kind: ConfigMap
metadata: { name: citadel-config }
data:
  CITADEL_PORT: "8099"
  CITADEL_LOG_LEVEL: "info"
  CITADEL_CITADEL_ANCHOR_INTERVAL: "100"
---
apiVersion: v1
kind: Secret
metadata: { name: citadel-secrets }
type: Opaque
stringData:
  CITADEL_DB_URL: "postgres://citadel:...@postgres.internal:5432/citadel?sslmode=require"
  CITADEL_CITADEL_MASTER_KEY: "<64-hex-char Ed25519 private key>"
```

The Ed25519 master key should be sourced from a secret manager (CSI
driver for Vault, AWS Secrets Manager sync, GCP Secret Manager
workload identity) — not pasted as literal stringData.

### Migration job

```yaml
apiVersion: batch/v1
kind: Job
metadata: { name: citadel-migrate-1-0-0 }
spec:
  template:
    spec:
      restartPolicy: OnFailure
      containers:
      - name: migrate
        image: postgres:16-alpine
        command: ["psql"]
        args: ["-f", "/migrations/001_initial.sql"]
        env:
          - name: PGSERVICE
            valueFrom: { secretKeyRef: { name: citadel-secrets, key: CITADEL_DB_URL } }
        volumeMounts:
          - name: migrations
            mountPath: /migrations
      volumes:
        - name: migrations
          configMap: { name: citadel-migrations }
```

The migration image uses plain `psql` because CITADEL's v1.0.0
migration script is `001_initial.sql` — idempotent via
`CREATE TABLE IF NOT EXISTS`. Future versions will add a dedicated
`citadel migrate` subcommand.

## HA model — active / passive

CITADEL's WORM chain is **strictly single-writer**: concurrent appends
would produce divergent chains that cannot reconcile. For high
availability:

- Run **1 primary + 1 standby** replicas.
- Use a leader lock (Consul / Kubernetes Lease) so only one CITADEL
  process writes at a time.
- The standby serves read queries (`/worm/verify`, `/health`) during
  normal operation, and takes over primary on confirmed primary
  failure.

Kubernetes-native approach:

```yaml
spec:
  replicas: 2
  strategy: { type: Recreate }
  # Add a sidecar or init-container that acquires a Kubernetes Lease
  # before the CITADEL process starts writing.
```

A StatefulSet with ordinal-based leader election (index 0 is primary)
also works. Multi-writer sharded chains — the horizontal-scale story
— is a v2.0 feature.

## PostgreSQL

### Sizing

- **Small** (< 100 decisions/sec): default 2 vCPU / 4 GiB Postgres is
  ample.
- **Medium** (100-500 decisions/sec): 4 vCPU / 16 GiB, provisioned
  IOPS SSD.
- **Large** (> 500 decisions/sec): consider sharding by `project_id`
  across multiple CITADEL instances until v2.0.

### Critical tables

All growth is in `worm_entries` and `chain_anchors`. Back these up
daily (`pg_dump`) at minimum; PITR with WAL archiving is strongly
recommended for forensic replay.

### Connection pool

```
CITADEL_DB_MAX_OPEN_CONNS=25   # per-replica, default
CITADEL_DB_MAX_IDLE_CONNS=5
CITADEL_DB_CONN_MAX_LIFETIME=5m
```

At N replicas, ensure `N * max_open_conns <= Postgres max_connections - 10`.
The `-10` reserves slack for migrations and incidental psql sessions.

## Security checklist before going live

- [ ] `CITADEL_DB_URL` uses `sslmode=require` or `verify-full`
- [ ] `CITADEL_CITADEL_MASTER_KEY` sourced from a secret manager, 
      never committed, rotated per [SECURITY.md](../SECURITY.md)
- [ ] PostgreSQL reachable only on a private network
- [ ] `/api/v1/worm/verify` endpoint authenticated at the ingress
      (CITADEL itself does not require JWT for verify — adjust at
      ingress / WAF)
- [ ] TLS terminates at ingress with a certificate from a trusted CA
- [ ] Backups run daily, tested monthly
- [ ] Anchor public keys published to the auditor registry
- [ ] Initial chain verification succeeds (`curl /worm/verify` returns
      `{"valid": true}`)
- [ ] Operator runbook rehearsed by at least one on-call engineer

## Upgrading

CITADEL follows semantic versioning. For `1.x` → `1.y`:

1. Review [CHANGELOG.md](../CHANGELOG.md) for breaking changes
   (none within 1.x).
2. Run migration job with the new image (idempotent).
3. Roll Deployment forward — stateless replicas handle the cut-over.
4. Watch `/api/v1/health` — `version` reflects the new tag when the
   pod is healthy.

For `1.x → 2.0` (future): the chain format may change (multi-writer
sharding). Release notes will include an upgrade runbook that
preserves chain continuity across the boundary.

## Observability

| Endpoint | Use |
|---|---|
| `GET /api/v1/health` | Liveness + DB ping; 200 when healthy |
| `GET /metrics` | (v1.1+) Prometheus scrape endpoint |

Suggested alerts once metrics land in v1.1:

| Condition | Severity |
|---|---|
| `/health` down > 2 min | P1 |
| `citadel_worm_append_seconds{q=0.95}` > 50 ms for 10 min | P2 |
| `citadel_marshal_decisions_total{outcome="HARD_STOP"}` rate > 0 sustained | P1 |
| `citadel_anchors_created_total` stalled for > 10 min | P2 |

## Deployment topology

For the ecosystem-wide view — which platforms talk to CITADEL, what
ports, which network segments — see [../../docs/deployment-topology.md](../../docs/deployment-topology.md).

## Related

- [Configuration reference](./configuration.md)
- [Troubleshooting](./troubleshooting.md)
- [Operator runbook](./operator-runbook.md)
- [Security model](./security-model.md)
- [SECURITY.md](../SECURITY.md) — key rotation + threat model
