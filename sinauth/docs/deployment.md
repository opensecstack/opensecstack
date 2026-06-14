# Deployment

## Docker Compose (single node)

The repository ships with two Compose files:

| File | Purpose |
|---|---|
| `docker-compose.dev.yml` | Local development — hot reload, dev mode, PostgreSQL on port 5433 |
| `docker-compose.yml` | Production-style single-node deployment |

### Production Docker Compose

```bash
# 1. Generate signing key
make keys-generate

# 2. Copy and fill environment file
cp .env.example .env
# Edit .env — set SINAUTH_ISSUER, SINAUTH_DB_URL, SINAUTH_SIGNING_KEY_PATH, etc.

# 3. Start
docker compose up -d

# 4. Run migrations
docker compose exec sinauth /sinauth migrate
```

sinauth listens on port 8100. Place a reverse proxy (nginx or Caddy) in front for TLS termination.

## Kubernetes with Helm

The Helm chart is in `deploy/helm/sinauth/`.

```bash
# Add the chart (if published) or use a local path
helm install sinauth ./deploy/helm/sinauth \
  --set sinauth.issuer=https://auth.sin.to \
  --set sinauth.dbUrl=postgres://sinauth:secret@postgres:5432/sinauth \
  --set sinauth.signingKeyPath=/etc/sinauth/keys/sinauth.pem \
  --set image.tag=1.0.0
```

### Providing the signing key in Kubernetes

```bash
# Create the Secret from your local PEM file
kubectl create secret generic sinauth-key \
  --from-file=sinauth.pem=/path/to/your/sinauth.pem

# The Helm chart mounts this secret at /etc/sinauth/keys/sinauth.pem
# Set sinauth.signingKeyPath=/etc/sinauth/keys/sinauth.pem in values.yaml
```

### Running migrations in Kubernetes

Use an init container or a pre-upgrade Job:

```bash
kubectl run sinauth-migrate --rm -it \
  --image=ghcr.io/opensecstack/sinauth:1.0.0 \
  --env="SINAUTH_DB_URL=postgres://..." \
  --command -- /sinauth migrate
```

## Environment variables in production

Never write secrets to the container image or a committed `.env` file. Options:

| Platform | Recommended approach |
|---|---|
| Kubernetes | `Secret` objects mounted as env vars or files |
| Docker Swarm | Docker secrets |
| AWS ECS | SSM Parameter Store or Secrets Manager via task role |
| Bare metal / VM | systemd `EnvironmentFile` pointing to a `0600` file |

Minimum required vars for production (all others have safe defaults):

```
SINAUTH_ISSUER
SINAUTH_DB_URL
SINAUTH_SIGNING_KEY_PATH
```

## TLS termination

sinauth speaks plain HTTP internally. TLS must be terminated by a reverse proxy before traffic reaches sinauth.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name auth.sin.to;

    ssl_certificate     /etc/letsencrypt/live/auth.sin.to/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/auth.sin.to/privkey.pem;

    location / {
        proxy_pass         http://sinauth:8100;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

Set `SINAUTH_TRUSTED_PROXIES` to the nginx container IP so that sinauth reads the real client IP from `X-Forwarded-For` for rate limiting.

### Caddy

```caddyfile
auth.sin.to {
    reverse_proxy sinauth:8100
}
```

Caddy handles certificate provisioning and renewal automatically via Let's Encrypt.

## Health check endpoints

| Endpoint | Use |
|---|---|
| `GET /api/v1/health` | Liveness probe — returns `200` if the process is alive |
| `GET /api/v1/ready` | Readiness probe — returns `200` only if the database is reachable; `503` otherwise |

Configure your load balancer or orchestrator to use `/api/v1/ready` for readiness and `/api/v1/health` for liveness.

### Docker Compose healthcheck example

```yaml
healthcheck:
  test: ["CMD", "wget", "-qO-", "http://localhost:8100/api/v1/ready"]
  interval: 10s
  timeout: 5s
  retries: 5
  start_period: 15s
```

### Kubernetes probe example

```yaml
livenessProbe:
  httpGet:
    path: /api/v1/health
    port: 8100
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /api/v1/ready
    port: 8100
  initialDelaySeconds: 5
  periodSeconds: 10
```

## Database backup strategy

sinauth's entire state is in PostgreSQL. Back up the database regularly.

### Continuous WAL archiving (recommended for production)

Enable WAL archiving in `postgresql.conf` and stream WAL to an object store (S3, GCS). This gives point-in-time recovery.

### Periodic pg_dump (minimum)

```bash
# Daily dump, compressed
pg_dump -U sinauth sinauth | gzip > /backups/sinauth-$(date +%Y%m%d).sql.gz

# Retain 30 days
find /backups -name 'sinauth-*.sql.gz' -mtime +30 -delete
```

Test restores regularly. A backup that has never been restored is a backup that may not work when needed.

## Scaling

sinauth is stateless beyond the database. Multiple instances can run behind a load balancer — all state (sessions, tokens, codes) is in PostgreSQL.

For high-traffic deployments:
- Increase `SINAUTH_DB_MAX_CONNS` and size the PostgreSQL connection pool accordingly (consider PgBouncer).
- The JWKS endpoint (`Cache-Control: max-age=3600`) handles extremely high read rates — platforms cache it locally.
- Auth endpoints at 5 req/min per IP are the bottleneck by design (rate limiting). The global 120 req/min limit can be tuned for your traffic profile.
