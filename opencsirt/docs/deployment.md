# OpenCSIRT Deployment

> v1.0.0. Two supported topologies: Docker Compose (single host,
> dev + small national-CSIRT pilots) and Helm/Kubernetes (production).
> See [configuration.md](configuration.md) for every env var.

---

## Topology

```
                    ┌──────────────┐
                    │  ingress     │  TLS termination
                    └──────┬───────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
    ┌──────────┐    ┌────────────┐    ┌──────────┐
    │ web (N)  │    │ api (N)    │    │ metrics  │
    │ nginx    │    │ Go :8088   │    │ scrape   │
    └──────────┘    └─────┬──────┘    └──────────┘
                          │
                          ▼ (loopback or cluster-internal)
                    ┌────────────┐
                    │ advisory   │   Python :8089
                    │ (1 in v1)  │
                    └─────┬──────┘
                          │
                          ▼
                    ┌────────────┐
                    │ postgres   │   :5432
                    └────────────┘
```

The Go API is **stateless** — scale horizontally. The Python
advisory subsystem is **single-instance in v1.0.0**; horizontal
scaling tracked for v1.1 (see [performance.md](performance.md)).
Postgres is the single SPOF; back it with managed Postgres or a
dedicated HA cluster.

---

## Docker Compose (dev)

```bash
make compose-up    # docker compose -f deploy/docker-compose.yml up -d
make compose-down  # tears down + removes volumes
```

The compose file ships:

- `postgres:16-alpine` (with the `0001_init.up.sql` schema applied
  by an init script — see [migrations.md](migrations.md)).
- `opencsirt-api` (built from `cmd/opencsirt/Dockerfile`).
- `opencsirt-advisory` (built from `python/Dockerfile`).
- `opencsirt-web` (built from `web/Dockerfile`, served by nginx).

Compose is fine for development and small pilots (~50 incidents /
week, single CSIRT-lead operator). It is **not** appropriate for
production national-CSIRT deployments.

---

## Helm (production)

The chart at [`deploy/helm/opencsirt/`](../deploy/helm/opencsirt/)
ships:

- `Deployment` for `api` (replicas configurable, default 2).
- `Deployment` for `advisory` (replicas pinned to 1; the chart
  blocks `replicas > 1` until v1.1).
- `Deployment` for `web` (replicas configurable).
- `StatefulSet` for `postgres` (only enabled when
  `.Values.postgres.embedded=true`; production should point at
  managed Postgres via `.Values.api.dbUrlSecret`).
- `Service` for each Deployment.
- `Ingress` (optional, TLS via cert-manager).
- `NetworkPolicy` (default-deny + per-tier allow rules).
- `ServiceMonitor` (Prometheus Operator).

Minimal `values.yaml`:

```yaml
api:
  replicas: 2
  image: ghcr.io/opensecstack/opencsirt-api:1.0.0
  dbUrlSecret: opencsirt-db
  jwtSecretSecret: opencsirt-jwt
  pepperSecret: opencsirt-pepper
  citadel:
    apiUrl: https://citadel.example.org
    hmacSecretsSecret: opencsirt-citadel-hmac
    keyId: opencsirt-1
advisory:
  replicas: 1   # do not change in v1.0.0
  jwtSecret: opencsirt-advisory-jwt
postgres:
  embedded: false   # use managed Postgres in prod
```

Apply:

```bash
helm upgrade --install opencsirt deploy/helm/opencsirt \
    -n opencsirt --create-namespace \
    -f values.yaml
```

---

## Container security posture

Every container in the chart runs with:

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 8088     # api / web
  runAsUser: 8089     # advisory
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

Writable mounts are `emptyDir` for `/tmp` and (advisory only) a
small cache volume for IOC enrichment responses.

`NetworkPolicy` (default deny):

- `api` accepts ingress from `web` and `ingress-nginx` on `:8088`.
- `advisory` accepts ingress only from `api` on `:8089`.
- `postgres` accepts ingress only from `api` on `:5432`.
- Egress from `api` to ThreatFlow / NIS2 Compass / VertGuard /
  CITADEL is allow-listed by FQDN/CIDR (set in
  `values.yaml.networkPolicy.egress`).

---

## Postgres tuning

Approximate starting points for a national CSIRT (~50–200
advisories/quarter, ~500–2000 incidents/year, see
[performance.md](performance.md)). Validate against your workload.

| Setting | Suggested | Why |
|---|---|---|
| `max_connections` | `100` | Headroom for `OPENCSIRT_DB_MAX_CONNS=16` × API replicas + a buffer for migrations / psql sessions. |
| `shared_buffers` | `25%` of RAM | Standard Postgres rule of thumb. |
| `work_mem` | `16 MB` | Few large analytical queries; the `metrics_snapshot` join is the most expensive read. |
| `wal_level` | `replica` | Required for streaming replication / managed-Postgres backups. |
| `synchronous_commit` | `on` | The CITADEL outbox correctness contract relies on durable commits. Do not set to `off`. |

Index sizing is dominated by `incidents` (3 indexes) and
`citadel_outbox` (state+created_at). Both are small in absolute
terms — see [data-model.md](data-model.md).

---

## Secret rotation

### CITADEL HMAC

`OPENCSIRT_CITADEL_HMAC_SECRETS` accepts a comma-separated rotation
list `primary,next,previous`. Rotation procedure (zero-downtime):

1. Generate new secret. Push to CITADEL as an additional accepted key.
2. Set `OPENCSIRT_CITADEL_HMAC_SECRETS=<new>,<old>` and roll API
   pods. New events sign with `<new>`; CITADEL accepts both.
3. After 24 h (well past the ±5 min replay window), remove `<old>`
   from CITADEL and from the env.

### JWT secret

`OPENCSIRT_JWT_SECRET` accepts a comma-separated rotation list.
The `Authenticator.Verify` loop (see
[`internal/auth/auth.go`](../internal/auth/auth.go)) tries every
secret. New tokens sign with `[0]`. Rotation:

1. Push new secret as `<new>,<old>`. Roll API pods.
2. Wait for `OPENCSIRT_TOKEN_TTL` (default `12h`) so all in-flight
   tokens have re-issued.
3. Drop `<old>`. Roll API pods.

### Password pepper

`OPENCSIRT_PASSWORD_PEPPER` is **not** rotatable in place — every
hash in `OPENCSIRT_USERS` is keyed to it. Rotation requires a
coordinated re-hash of every operator credential. Plan for an
operator window.

### IRFlow webhook secret

`OPENCSIRT_IRFLOW_WEBHOOK_SECRET` is single-valued in v1.0.0. Rotate
by coordinating with the IRFlow side and rolling both at once.
Multi-secret rotation tracked for v1.1.

### Advisory service JWT

`OPENCSIRT_ADVISORY_SERVICE_JWT` is signed by the same JWT secret
as user tokens; it rotates with the JWT secret rotation above.

---

## Scaling considerations

- **Go API**: stateless. Scale to N replicas behind a Service.
  `pgxpool` per replica × `OPENCSIRT_DB_MAX_CONNS` (default 16)
  must stay under Postgres `max_connections`.
- **Python advisory**: single-instance in v1.0.0. Latency budget
  is 1–5 s per draft (see [performance.md](performance.md)).
  Operators can deploy a Redis cache for IOC enrichment responses
  to cut tail latency; that is an optional sidecar, not a v1.0.0
  hard dependency.
- **Postgres**: single SPOF. Use a managed service or Patroni-class
  HA cluster. Backups: `pg_basebackup` + WAL archive, or the
  managed-service equivalent.
- **CITADEL outbox**: the watcher is a singleton goroutine. It
  uses `SELECT … FOR UPDATE SKIP LOCKED` so multiple API replicas
  cooperate safely without a leader election.

---

## See also

- [configuration.md](configuration.md)
- [migrations.md](migrations.md)
- [performance.md](performance.md)
- [security/](security/)
