# APIGuard High-Availability Deployment

## Architecture

APIGuard is **stateless at the application layer** — all state lives in PostgreSQL and Redis. This means horizontal scaling is straightforward: run multiple APIGuard instances behind a load balancer with shared DB and Redis.

```
                    ┌─────────────────┐
                    │  Load Balancer  │
                    │  (nginx/ALB)    │
                    └────┬───────┬────┘
                         │       │
              ┌──────────┴┐     ┌┴──────────┐
              │ APIGuard  │     │ APIGuard   │
              │  Pod 1    │     │  Pod 2..N  │
              └─────┬─────┘     └─────┬──────┘
                    │                 │
         ┌──────────┴─────────────────┴──────────┐
         │                                        │
    ┌────┴─────┐                          ┌───────┴───────┐
    │PostgreSQL│                          │    Redis      │
    │ Primary  │──▶ Standby (streaming)   │  (Sentinel)   │
    └──────────┘                          └───────────────┘
```

---

## Kubernetes Deployment

### Manifests

Manifests are in `deploy/k8s/apiguard/`:

| File | Resource | Purpose |
|------|----------|---------|
| `deployment.yaml` | Deployment (2 replicas) | Application pods |
| `service.yaml` | ClusterIP Service | Internal load balancing |
| `ingress.yaml` | Ingress | TLS termination + routing |
| `hpa.yaml` | HorizontalPodAutoscaler | Auto-scale 2–8 pods |

### Health Probes

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 30
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /api/v1/health
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 10
  failureThreshold: 2
```

The `/api/v1/health` endpoint performs a **deep health check** (v1.0.0+):
- Pings PostgreSQL with a 3-second timeout
- Returns `200 OK` with `"status": "ok"` when healthy
- Returns `503 Service Unavailable` with `"status": "degraded"` when DB is unreachable

```json
{
  "status": "degraded",
  "timestamp": "2026-03-31T10:00:00Z",
  "uptime": "4h12m30s",
  "checks": {
    "database": "unhealthy: dial tcp: connection refused"
  }
}
```

### Pod Disruption Budget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: apiguard-pdb
  namespace: opensecstack
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: apiguard
```

### Topology Spread

For multi-AZ resilience, add topology spread constraints:

```yaml
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: topology.kubernetes.io/zone
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app: apiguard
```

---

## Database HA

### PostgreSQL Streaming Replication

For production, use PostgreSQL with streaming replication:

| Component | Purpose |
|-----------|---------|
| Primary | All reads and writes |
| Standby (hot) | Automatic failover target, read replicas |
| PgBouncer | Connection pooling (recommended: pool_mode=transaction) |

**Configuration:**
```
APIGUARD_DB_URL=postgres://apiguard:secret@pgbouncer:6432/apiguard?sslmode=verify-full
APIGUARD_DB_MAX_OPEN_CONNS=20
APIGUARD_DB_MAX_IDLE_CONNS=5
```

### Failover Strategy

| Approach | Tool | RTO |
|----------|------|-----|
| Managed service | AWS RDS Multi-AZ, GCP Cloud SQL HA | < 1 min (automatic) |
| Self-managed | Patroni + etcd | 10–30 sec |
| Manual | pg_basebackup + promote | Minutes (operator action) |

---

## Redis HA

### Redis Sentinel

For production rate limiting and session state:

```
APIGUARD_REDIS_URL=redis://:password@redis-sentinel:26379/0
```

| Mode | Replicas | Failover |
|------|----------|----------|
| Standalone | 1 | Manual restart |
| Sentinel | 3 (1 primary + 2 replicas + 3 sentinels) | Automatic (< 30 sec) |
| Cluster | 6+ (3 primary + 3 replicas) | Automatic |

Redis data is ephemeral (rate limit counters, cached sessions). Loss of Redis degrades rate limiting but does not stop the service.

---

## Scaling Guidelines

| Metric | Threshold | Action |
|--------|-----------|--------|
| CPU utilisation > 70% | Sustained 5 min | HPA adds pods (up to 8) |
| Memory > 80% | Sustained 5 min | HPA adds pods |
| Scan queue depth > 50 | Sustained | Increase `SCANNER_CONCURRENCY` or add pods |
| DB connection pool exhausted | `pg_stat_activity` > max | Increase `DB_MAX_OPEN_CONNS` or add PgBouncer |
| P99 latency > 2s | Sustained | Profile with pprof, check DB slow queries |

### Capacity Planning

| Instance Size | Concurrent Scans | Findings/sec | Notes |
|--------------|------------------|-------------|-------|
| 1 vCPU, 512 MB | 5 | ~50 | Development only |
| 2 vCPU, 1 GB | 10 | ~200 | Small team (< 50 scans/day) |
| 4 vCPU, 2 GB | 20 | ~500 | Medium (50–200 scans/day) |
| 8 vCPU, 4 GB | 40 | ~1000 | Large (200+ scans/day) |

---

## Zero-Downtime Deployment

APIGuard supports rolling updates with zero downtime:

1. New pods start and pass readiness probe
2. Load balancer routes traffic to new pods
3. Old pods receive SIGTERM → `WaitScans()` drains in-flight scans (30s timeout)
4. CITADEL `Drain()` flushes pending audit events
5. Old pods terminate

```yaml
strategy:
  type: RollingUpdate
  rollingUpdate:
    maxSurge: 1
    maxUnavailable: 0
```

### JWT Secret Rotation

APIGuard supports dual JWT secrets for zero-downtime rotation:

1. Set `APIGUARD_AUTH_PREVIOUS_JWT_SECRET` to the current secret
2. Set `APIGUARD_AUTH_JWT_SECRET` to the new secret
3. Deploy — both secrets are accepted
4. Wait for all existing tokens to expire (default 1h)
5. Remove `APIGUARD_AUTH_PREVIOUS_JWT_SECRET`

---

## See Also

- [Load Testing](load-testing.md) — capacity planning and performance targets
- [Disaster Recovery](disaster-recovery.md) — failover procedures and backup strategy
- [Performance](performance.md) — scaling guidance and hardware recommendations
- [Operator Handbook](operator-handbook.md) — production deployment checklist
- [Security Audit](security-audit.md) — transport security and auth controls
