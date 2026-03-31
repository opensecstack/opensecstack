# ThreatFlow Deployment Guide

This guide covers deploying ThreatFlow from local development through production Kubernetes clusters. ThreatFlow is a stateless HTTP service that relies on PostgreSQL for persistence and optionally Redis for caching and CITADEL for governance.

---

## Prerequisites

| Dependency | Version | Required | Purpose |
|-----------|---------|----------|---------|
| Go | 1.22+ | Build only | Compile from source |
| Docker | 24+ | Recommended | Container build and runtime |
| PostgreSQL | 16+ | Yes | IOC persistence, full-text search |
| Redis | 7+ | Optional (v0.5+) | Hot IOC lookup cache, feed poll state |
| CITADEL | Latest | Optional | MARSHAL governance, WORM audit logging |

---

## Quick Start (Docker Compose)

The fastest way to run ThreatFlow with all dependencies is Docker Compose.

### docker-compose.yml

```yaml
version: "3.9"

services:
  threatflow-api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8091:8091"
    environment:
      THREATFLOW_PORT: "8091"
      THREATFLOW_DB_URL: "postgres://threatflow:threatflow@postgres:5432/threatflow?sslmode=disable"
      THREATFLOW_LOG_LEVEL: "info"
      THREATFLOW_LOG_FORMAT: "json"
      THREATFLOW_CITADEL_API_URL: ""
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
    networks:
      - backend

  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: threatflow
      POSTGRES_PASSWORD: threatflow
      POSTGRES_DB: threatflow
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U threatflow"]
      interval: 5s
      timeout: 3s
      retries: 5
    networks:
      - backend

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: ["redis-server", "--maxmemory", "128mb", "--maxmemory-policy", "allkeys-lru"]
    networks:
      - backend

volumes:
  pgdata:

networks:
  backend:
    driver: bridge
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `THREATFLOW_PORT` | `8091` | HTTP listen port |
| `THREATFLOW_DB_URL` | `postgres://threatflow:threatflow@localhost:5432/threatflow?sslmode=disable` | PostgreSQL connection string |
| `THREATFLOW_DB_MAX_OPEN_CONNS` | `25` | Max open database connections |
| `THREATFLOW_DB_MAX_IDLE_CONNS` | `5` | Max idle database connections |
| `THREATFLOW_LOG_LEVEL` | `info` | Log level: debug, info, warn, error |
| `THREATFLOW_LOG_FORMAT` | `json` | Log format: json, text |
| `THREATFLOW_CITADEL_API_URL` | *(empty)* | CITADEL base URL (empty = disabled) |
| `THREATFLOW_CITADEL_KEY_ID` | | HMAC connector key ID |
| `THREATFLOW_CITADEL_KEY_SECRET` | | HMAC signing secret |
| `THREATFLOW_CITADEL_PROJECT_ID` | `threatflow` | CITADEL project identifier |

### Health Check Verification

```bash
# Start all services
docker compose up -d

# Wait for healthy state
docker compose ps

# Verify ThreatFlow is responding
curl http://localhost:8091/api/v1/health
# {"service":"threatflow","status":"ok"}

# Verify version
curl http://localhost:8091/api/v1/version
```

---

## Local Development

### Run from Source

```bash
cd threatflow
go run ./cmd/threatflow serve --log-format text
```

The server starts on `http://localhost:8091`. In local mode with no `THREATFLOW_CITADEL_API_URL` set, CITADEL governance is disabled and all MARSHAL evaluations return implicit EXECUTE.

### Build Binary

```bash
CGO_ENABLED=0 go build -o bin/threatflow ./cmd/threatflow
./bin/threatflow serve
```

---

## Docker

### Build Image

```bash
docker build -t threatflow:latest .
```

The multi-stage Dockerfile produces a minimal Alpine-based image (~15 MB) with a non-root `threatflow` user.

### Run Container

```bash
docker run -p 8091:8091 \
  -e THREATFLOW_DB_URL=postgres://threatflow:secret@host.docker.internal:5432/threatflow \
  -e THREATFLOW_CITADEL_API_URL=http://host.docker.internal:8099 \
  -e THREATFLOW_CITADEL_KEY_ID=tf-connector-key \
  -e THREATFLOW_CITADEL_KEY_SECRET=your-hmac-secret \
  threatflow:latest
```

---

## Production Checklist

Before deploying to production, verify every item:

- [ ] **TLS termination** configured at reverse proxy (nginx or Traefik)
- [ ] **Database connection string** uses `sslmode=verify-full`
- [ ] **Database connection pooling** configured (pgBouncer or internal pool via `THREATFLOW_DB_MAX_OPEN_CONNS`)
- [ ] **Database backup schedule** established (pg_dump cron, daily minimum)
- [ ] **Secrets management** in place (HashiCorp Vault, Kubernetes Secrets, or env injection)
- [ ] **Log aggregation** configured (JSON structured logs forwarded to ELK, Loki, or equivalent)
- [ ] **Monitoring** enabled (Prometheus metrics endpoint + Grafana dashboard)
- [ ] **Rate limiting** configured at ingress (per-IP and global limits)
- [ ] **CITADEL connector** registered (key ID and secret configured, HMAC auth verified)
- [ ] **Network policies** restrict database and Redis access to ThreatFlow pods only
- [ ] **Resource limits** set on all containers (CPU and memory)
- [ ] **Liveness and readiness probes** verified against `/api/v1/health`
- [ ] **Log level** set to `info` (not `debug`) to avoid sensitive data in logs
- [ ] **Image tag** pinned to specific version (not `latest`)

---

## Kubernetes Deployment

### Namespace

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: opensecstack
  labels:
    app.kubernetes.io/part-of: opensecstack
```

### ConfigMap

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: threatflow-config
  namespace: opensecstack
data:
  THREATFLOW_PORT: "8091"
  THREATFLOW_LOG_LEVEL: "info"
  THREATFLOW_LOG_FORMAT: "json"
  THREATFLOW_DB_MAX_OPEN_CONNS: "20"
  THREATFLOW_DB_MAX_IDLE_CONNS: "5"
  THREATFLOW_CITADEL_PROJECT_ID: "threatflow"
```

### Secret

```bash
kubectl create secret generic threatflow-secrets \
  --namespace opensecstack \
  --from-literal=database-url='postgres://threatflow:SECRET@postgres:5432/threatflow?sslmode=verify-full' \
  --from-literal=citadel-key-id='tf-connector-key' \
  --from-literal=citadel-key-secret='your-hmac-secret' \
  --from-literal=redis-password='your-redis-password'
```

### Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: threatflow
  namespace: opensecstack
  labels:
    app: threatflow
    app.kubernetes.io/name: threatflow
    app.kubernetes.io/part-of: opensecstack
spec:
  replicas: 2
  selector:
    matchLabels:
      app: threatflow
  template:
    metadata:
      labels:
        app: threatflow
    spec:
      serviceAccountName: threatflow
      containers:
        - name: threatflow
          image: ghcr.io/opensecstack/threatflow:latest
          ports:
            - containerPort: 8091
              protocol: TCP
          envFrom:
            - configMapRef:
                name: threatflow-config
          env:
            - name: THREATFLOW_DB_URL
              valueFrom:
                secretKeyRef:
                  name: threatflow-secrets
                  key: database-url
            - name: THREATFLOW_CITADEL_KEY_ID
              valueFrom:
                secretKeyRef:
                  name: threatflow-secrets
                  key: citadel-key-id
            - name: THREATFLOW_CITADEL_KEY_SECRET
              valueFrom:
                secretKeyRef:
                  name: threatflow-secrets
                  key: citadel-key-secret
            - name: THREATFLOW_CITADEL_API_URL
              value: "http://citadel-api.opensecstack.svc.cluster.local:8099"
          resources:
            requests:
              cpu: 250m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /api/v1/health
              port: 8091
            initialDelaySeconds: 10
            periodSeconds: 15
            timeoutSeconds: 3
            failureThreshold: 3
          readinessProbe:
            httpGet:
              path: /api/v1/health
              port: 8091
            initialDelaySeconds: 5
            periodSeconds: 10
            timeoutSeconds: 3
            failureThreshold: 2
          securityContext:
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            allowPrivilegeEscalation: false
      restartPolicy: Always
```

### Service

```yaml
apiVersion: v1
kind: Service
metadata:
  name: threatflow
  namespace: opensecstack
  labels:
    app: threatflow
spec:
  type: ClusterIP
  selector:
    app: threatflow
  ports:
    - port: 8091
      targetPort: 8091
      protocol: TCP
      name: http
```

### Ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: threatflow
  namespace: opensecstack
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/rate-limit-connections: "10"
    nginx.ingress.kubernetes.io/rate-limit-rps: "60"
spec:
  ingressClassName: nginx
  tls:
    - hosts:
        - threatflow.example.com
      secretName: threatflow-tls
  rules:
    - host: threatflow.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: threatflow
                port:
                  number: 8091
```

### HorizontalPodAutoscaler

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: threatflow
  namespace: opensecstack
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: threatflow
  minReplicas: 2
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
```

### PodDisruptionBudget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: threatflow
  namespace: opensecstack
spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: threatflow
```

### Deploy

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/threatflow/

# Verify rollout
kubectl -n opensecstack rollout status deployment/threatflow

# Port-forward for local verification
kubectl -n opensecstack port-forward svc/threatflow 8091:8091
curl http://localhost:8091/api/v1/health
```

---

## Scaling Guide

### Horizontal Scaling

ThreatFlow is a stateless HTTP service. All state lives in PostgreSQL (and optionally Redis). Add replicas freely:

```bash
kubectl -n opensecstack scale deployment/threatflow --replicas=5
```

The HPA handles automatic scaling based on CPU and memory utilisation.

### Database Connection Pool Sizing

Each ThreatFlow pod maintains its own connection pool. Size the total pool across all pods to stay within PostgreSQL limits:

| Pods | `max_open_conns` per pod | Total connections | Recommended `max_connections` (PostgreSQL) |
|------|-------------------------|-------------------|-------------------------------------------|
| 2 | 20 | 40 | 100 |
| 5 | 20 | 100 | 150 |
| 10 | 15 | 150 | 200 |

If using pgBouncer, set `pool_mode = transaction` and size the upstream connection count accordingly.

### Redis Scaling

For high-throughput deployments (> 1000 IOC lookups/second), use a dedicated Redis instance separate from other opensecstack services. Redis Sentinel or Redis Cluster is recommended for availability.

### Feed Polling Distribution

When running multiple replicas, feed polling must be coordinated to prevent duplicate ingestion. Strategies:

1. **Leader election** (recommended) — one pod is elected as the feed poller using a Redis-based or K8s lease-based lock
2. **External scheduler** — a CronJob triggers feed polls via the ThreatFlow API, hitting the Service endpoint (load-balanced to a single pod)
3. **Feed partitioning** — assign feed subsets to specific pods via configuration (manual, less flexible)

---

## Monitoring and Observability

### Health Endpoint

```
GET /api/v1/health
```

| Status Code | Meaning |
|------------|---------|
| `200` | All systems operational |
| `503` | Degraded — database unreachable or critical subsystem down |

Response body:

```json
{
  "service": "threatflow",
  "status": "ok"
}
```

### Metrics Endpoint (Planned v0.3)

```
GET /metrics
```

Prometheus-format metrics will be exposed at the `/metrics` endpoint.

### Key Metrics to Watch

| Metric | Type | Description |
|--------|------|-------------|
| `iocs_ingested_total` | Counter | Total IOCs ingested across all feeds |
| `ioc_ingestion_duration_seconds` | Histogram | Time to validate, deduplicate, and persist an IOC |
| `feed_poll_errors_total` | Counter | Failed feed poll attempts |
| `feed_poll_duration_seconds` | Histogram | Time per feed poll cycle |
| `citadel_marshal_decisions` | Counter | MARSHAL outcomes, labelled by `{outcome="EXECUTE\|REFUSE\|HARD_STOP"}` |
| `db_pool_active_connections` | Gauge | Current active database connections |
| `db_pool_idle_connections` | Gauge | Current idle database connections |
| `stix_bundles_imported_total` | Counter | STIX bundles successfully imported |
| `http_request_duration_seconds` | Histogram | HTTP request latency by endpoint |

### Alerting Rules (Prometheus)

```yaml
groups:
  - name: threatflow
    rules:
      - alert: ThreatFlowFeedPollFailure
        expr: increase(feed_poll_errors_total[15m]) > 3
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Feed poll failures exceeding threshold"
          description: "ThreatFlow has had {{ $value }} feed poll failures in the last 15 minutes."

      - alert: ThreatFlowIngestionLatencyHigh
        expr: histogram_quantile(0.99, rate(ioc_ingestion_duration_seconds_bucket[5m])) > 5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "IOC ingestion p99 latency above 5 seconds"

      - alert: ThreatFlowDBPoolExhaustion
        expr: db_pool_active_connections / THREATFLOW_DB_MAX_OPEN_CONNS > 0.8
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Database connection pool above 80% utilisation"

      - alert: ThreatFlowCitadelUnreachable
        expr: citadel_marshal_decisions{outcome="error"} > 0 and on() increase(citadel_marshal_decisions{outcome="error"}[5m]) > 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "CITADEL unreachable for more than 5 minutes"
          description: "ThreatFlow cannot reach CITADEL for MARSHAL decisions. Governance is degraded."
```

### Grafana Dashboard

A sample Grafana dashboard JSON is available at `deploy/grafana/threatflow-dashboard.json` (planned). Key panels:

- IOC ingestion rate (per feed, per minute)
- Feed poll success/failure ratio
- MARSHAL decision distribution
- HTTP request latency percentiles (p50, p95, p99)
- Database connection pool utilisation
- Active replicas and HPA scaling events

---

## Backup and Recovery

### Database Backup

ThreatFlow's IOC store lives entirely in PostgreSQL. Regular backups are critical.

**Daily pg_dump (cron example):**

```bash
# /etc/cron.d/threatflow-backup
0 2 * * * postgres pg_dump -Fc threatflow > /backups/threatflow-$(date +\%Y\%m\%d).dump 2>&1
```

**Retention policy:** 30-day rolling retention. Remove backups older than 30 days:

```bash
find /backups -name "threatflow-*.dump" -mtime +30 -delete
```

**Kubernetes CronJob alternative:**

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: threatflow-db-backup
  namespace: opensecstack
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: pg-dump
              image: postgres:16-alpine
              command:
                - /bin/sh
                - -c
                - pg_dump -Fc -h postgres -U threatflow threatflow > /backups/threatflow-$(date +%Y%m%d).dump
              env:
                - name: PGPASSWORD
                  valueFrom:
                    secretKeyRef:
                      name: threatflow-secrets
                      key: database-password
              volumeMounts:
                - name: backup-volume
                  mountPath: /backups
          restartPolicy: OnFailure
          volumes:
            - name: backup-volume
              persistentVolumeClaim:
                claimName: threatflow-backups
```

### WORM Events

WORM events are immutable and stored in the CITADEL chain. No ThreatFlow-side backup is needed for audit trail data. CITADEL maintains its own persistence and replication.

### Feed Configuration

Feed source configuration is stored in environment variables or configuration files. These should be version-controlled alongside application code. No runtime backup is needed.

### Recovery Procedure

1. **Restore the database** from the most recent pg_dump:
   ```bash
   pg_restore -d threatflow /backups/threatflow-YYYYMMDD.dump
   ```
2. **Redeploy ThreatFlow** with the same configuration (environment variables, secrets)
3. **Re-poll feeds** for the missed window to backfill any IOCs ingested between the backup and the failure:
   ```bash
   curl -X POST http://localhost:8091/api/v1/feeds/poll-all
   ```
4. **Verify health** and check CITADEL WORM chain for continuity:
   ```bash
   curl http://localhost:8091/api/v1/health
   ```
5. **Review MARSHAL decisions** — any decisions made during downtime were not evaluated; check for unapproved ingestions

---

## Reverse Proxy Configuration

ThreatFlow listens on plain HTTP internally. Always terminate TLS at a reverse proxy in production.

### nginx Example

```nginx
upstream threatflow {
    server 127.0.0.1:8091;
}

server {
    listen 443 ssl http2;
    server_name threatflow.example.com;

    ssl_certificate     /etc/ssl/certs/threatflow.crt;
    ssl_certificate_key /etc/ssl/private/threatflow.key;

    location / {
        proxy_pass http://threatflow;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Rate limiting
        limit_req zone=threatflow burst=20 nodelay;
    }
}

limit_req_zone $binary_remote_addr zone=threatflow:10m rate=60r/m;
```

### Traefik Example (Docker labels)

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.threatflow.rule=Host(`threatflow.example.com`)"
  - "traefik.http.routers.threatflow.entrypoints=websecure"
  - "traefik.http.routers.threatflow.tls.certresolver=letsencrypt"
  - "traefik.http.services.threatflow.loadbalancer.server.port=8091"
```

---

## See Also

- [Configuration](configuration.md) — all environment variables and config precedence
- [Security Model](security-model.md) — production security controls and hardening
- [CITADEL Integration](citadel-integration.md) — connector key setup for governance
- [Architecture](architecture.md) — system components deployed by these manifests
- [Troubleshooting](troubleshooting.md) — debugging deployment issues
