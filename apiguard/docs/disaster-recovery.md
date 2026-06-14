# APIGuard Disaster Recovery Runbook

## RPO / RTO Targets

| Metric | Target | How |
|--------|--------|-----|
| **RPO** (Recovery Point Objective) | < 1 hour | Hourly PostgreSQL WAL archival + daily pg_dump |
| **RTO** (Recovery Time Objective) | < 30 minutes | Automated K8s redeployment + DB restore |

---

## What Can Fail

| Component | Impact | Recovery |
|-----------|--------|----------|
| APIGuard pod(s) | Service degraded/down | K8s auto-restarts; HPA scales replacement pods |
| PostgreSQL | Full outage — no reads or writes | Restore from backup or promote standby |
| Redis | Rate limiting disabled, session loss | Restart Redis; APIGuard continues without it |
| CITADEL | Audit events queued, MARSHAL evaluations fail-open | APIGuard continues; events flushed when CITADEL recovers |
| Container registry | Cannot pull new images | Existing pods continue; use `imagePullPolicy: IfNotPresent` |
| DNS / Ingress | Service unreachable | Failover to secondary ingress or direct service IP |

---

## Backup Strategy

### PostgreSQL (daily + hourly)

```bash
# Daily full backup (cron: 02:00 UTC)
pg_dump -Fc -U apiguard -d apiguard > /backups/apiguard-$(date +%Y%m%d).dump

# Hourly WAL archival (continuous)
# Configure in postgresql.conf:
#   archive_mode = on
#   archive_command = 'cp %p /wal-archive/%f'
```

**Retention:** 30 daily dumps + 72 hours of WAL segments.

### What NOT to backup

- **Redis** — ephemeral rate limit counters; rebuild automatically on restart
- **WORM events** — stored in CITADEL's chain; APIGuard is not the source of truth
- **Docker images** — stored in ghcr.io; rebuild from source if registry is lost
- **Scan results** — these ARE in PostgreSQL; included in the pg_dump

---

## Recovery Procedures

### Procedure 1: Pod Failure (automatic)

**Detection:** Liveness probe fails → K8s restarts pod.

**Recovery:** Automatic — no operator action required.

**Verify:**
```bash
kubectl -n opensecstack get pods -l app=apiguard
curl -sf https://apiguard.opensecstack.io/api/v1/health | jq .
```

---

### Procedure 2: Database Failure

**Detection:** Health endpoint returns `503` with `"database": "unhealthy"`.

**Step 1: Assess**
```bash
# Check if PostgreSQL is running
pg_isready -h $DB_HOST -p 5432

# Check replication lag (if using standby)
psql -c "SELECT now() - pg_last_xact_replay_timestamp() AS replication_lag;"
```

**Step 2a: If managed service (RDS, Cloud SQL)**
- Failover is automatic (Multi-AZ)
- Verify new primary endpoint
- APIGuard reconnects automatically via connection pool

**Step 2b: If self-managed — promote standby**
```bash
# On standby server:
pg_ctl promote -D /var/lib/postgresql/data

# Update connection string if hostname changed
kubectl -n opensecstack edit secret apiguard-secrets
# → change database-url to point to new primary

# Restart APIGuard pods to pick up new connection
kubectl -n opensecstack rollout restart deployment/apiguard
```

**Step 2c: If no standby — restore from backup**
```bash
# Create fresh database
createdb -U postgres apiguard

# Restore from most recent dump
pg_restore -U postgres -d apiguard /backups/apiguard-YYYYMMDD.dump

# Apply WAL segments for point-in-time recovery
pg_restore --target-time="2026-03-31 09:00:00" ...

# Restart APIGuard
kubectl -n opensecstack rollout restart deployment/apiguard
```

**Step 3: Verify**
```bash
curl -sf https://apiguard.opensecstack.io/api/v1/health | jq .
# Expect: {"status":"ok","checks":{"database":"ok"}}

# Verify data integrity
psql -U apiguard -c "SELECT COUNT(*) FROM scans;"
psql -U apiguard -c "SELECT COUNT(*) FROM findings;"
```

---

### Procedure 3: Redis Failure

**Detection:** Rate limiting stops working; logs show Redis connection errors.

**Impact:** Rate limiting disabled — service continues but is vulnerable to abuse.

**Recovery:**
```bash
# Restart Redis
kubectl -n opensecstack rollout restart deployment/redis

# Or recreate:
kubectl -n opensecstack delete pod -l app=redis

# Verify
redis-cli -h redis -a $REDIS_PASSWORD ping
```

APIGuard does NOT need a restart after Redis recovery — the connection pool reconnects automatically.

---

### Procedure 4: Full Cluster Recovery

If the entire Kubernetes cluster is lost:

1. **Provision new cluster** (Terraform / cloud console)
2. **Apply namespace and shared resources:**
   ```bash
   kubectl apply -f deploy/k8s/namespace.yaml
   kubectl apply -f deploy/k8s/secrets.yaml  # copy from secrets.yaml.example first
   kubectl apply -f deploy/k8s/configmap.yaml
   ```
3. **Restore PostgreSQL** from offsite backup (see Procedure 2c)
4. **Deploy all services:**
   ```bash
   kubectl apply -f deploy/k8s/postgres/
   kubectl apply -f deploy/k8s/redis/
   kubectl apply -f deploy/k8s/apiguard/
   kubectl apply -f deploy/k8s/cert-manager/
   ```
5. **Verify health** across all endpoints
6. **Update DNS** if ingress IP changed
7. **Verify CITADEL WORM chain continuity** — the chain resumes from the last hash

---

## Post-Recovery Checklist

After any recovery event:

- [ ] Health endpoint returns `200 OK` with `"status": "ok"`
- [ ] All pods are Running and Ready
- [ ] Scan creation works end-to-end (create → execute → findings → report)
- [ ] Authentication works (JWT token exchange)
- [ ] Rate limiting is active (test with burst requests)
- [ ] CITADEL events are flowing (check CITADEL WORM log for recent entries)
- [ ] Monitoring dashboards show normal metrics
- [ ] Incident report filed (who, what, when, root cause, prevention)

---

## Testing DR

Run a DR test quarterly:

1. Take a fresh pg_dump
2. Spin up a parallel environment (different namespace)
3. Restore the backup into the parallel environment
4. Run the full test suite against the restored instance
5. Verify scan count, finding count, and audit log integrity
6. Tear down the parallel environment
7. Document results and any gaps found

---

## See Also

- [HA Deployment](ha-deployment.md) — high-availability architecture and failover
- [Operator Handbook](operator-handbook.md) — backup/restore procedures and upgrade guide
- [Security Audit](security-audit.md) — data protection controls
- [Load Testing](load-testing.md) — capacity verification after recovery
