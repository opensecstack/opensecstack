# SecureLab Deployment

> **ACCESS CONTROL WARNING:** SecureLab contains offensive tooling.
> The isolation requirements in this document are **mandatory**, not
> advisory. A misconfigured SecureLab deployment creates a ready-made
> attack platform inside your network.
>
> Do not deploy SecureLab in any environment until you have:
> 1. Obtained explicit written authorisation to run attack simulations
>    against the target systems.
> 2. Confirmed that the SecureLab network segment is isolated from
>    all systems outside the defined target scope.
> 3. Confirmed that access to the SecureLab API and dashboard is
>    restricted to authorised personnel only.

## Isolation architecture (mandatory)

SecureLab must be deployed in a dedicated, isolated network segment.
The following diagram shows the required network topology:

```
  ┌───────────────────────────────────────────────────────────────┐
  │  OPERATOR WORKSTATIONS (authorised red-team / SOC analysts)  │
  │  Access via: VPN or dedicated VLAN                           │
  └───────────────────────────┬───────────────────────────────────┘
                              │ HTTPS (authenticated + TLS)
                              │ Firewall: allow operator VLAN → port 3007/8087
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │  SECURELAB NETWORK SEGMENT (isolated bridge / VLAN)          │
  │  Subnet: e.g. 172.30.0.0/24                                  │
  │                                                               │
  │  securelab-api     :8087   (Python / FastAPI)                │
  │  securelab-worker          (Celery)                          │
  │  securelab-dashboard :3007 (React / Nginx)                   │
  │  securelab-postgres  :5432                                    │
  │  securelab-redis     :6379                                    │
  │                                                               │
  │  Firewall rules (egress):                                     │
  │   ALLOW → CITADEL API endpoint (specific IP:port)            │
  │   ALLOW → OpenScrub API endpoint                             │
  │   ALLOW → APIGuard API endpoint                              │
  │   ALLOW → ThreatFlow API endpoint                            │
  │   ALLOW → IRFlow API endpoint                                │
  │   ALLOW → Target simulation scope (CIDR allow-list)          │
  │   DENY ALL other egress                                       │
  └───────────────────────────┬───────────────────────────────────┘
                              │ Allow-listed egress only
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │  TARGET SIMULATION SCOPE (your lab / test network)           │
  │  e.g. 192.168.100.0/24                                       │
  │  Systems explicitly authorised for scenario execution        │
  └───────────────────────────────────────────────────────────────┘
```

**Non-negotiable rules:**

1. **No public internet exposure.** The API port (8087) and dashboard
   port (3007) must not be reachable from the internet under any
   circumstances.
2. **No routing to production.** The SecureLab network segment must
   not have a route to production network segments. Use separate VLANs
   and explicit firewall rules.
3. **Egress is allow-listed.** Only the specific IP/port combinations
   of integration endpoints and the target simulation CIDR are
   permitted as egress from the SecureLab segment.
4. **Postgres and Redis are internal only.** Ports 5432 and 6379 must
   not be reachable from outside the SecureLab network segment.

## Docker Compose deployment

The provided `docker-compose.yml` enforces isolation via Docker
networks:

- `securelab-internal`: `internal: true` — no routing to host
  networking or external networks. Postgres, Redis, API, and worker
  all attach here.
- `securelab-egress`: restricted bridge for API and worker egress to
  integration endpoints. Configure your host firewall to restrict
  this bridge's outbound traffic to the allow-list.

### Steps

```bash
# 1. Clone repository
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

# 2. Configure environment
cp .env.example .env
# Edit .env — see docs/configuration.md for required values

# 3. Build the image
make docker-build

# 4. Start the stack
docker compose up -d

# 5. Run database migrations
docker compose exec securelab alembic upgrade head

# 6. Verify health
curl http://127.0.0.1:8087/api/v1/health

# 7. Create the first operator account
docker compose exec securelab python -m securelab.cli operators create \
  --email ops@yourorg.internal \
  --role operator
```

### Production hardening checklist

- [ ] `SECURELAB_HTTP_ADDR` is set to `127.0.0.1:8087` or a private
      VLAN address. Not `0.0.0.0`.
- [ ] `SECURELAB_ISOLATION_MODE=strict` (default).
- [ ] `SECURELAB_TARGET_CIDR_ALLOWLIST` is set to the minimum
      necessary simulation scope.
- [ ] `SECURELAB_MFA_REQUIRED=true`.
- [ ] `SECURELAB_DRY_RUN_ONLY=true` until first live execution is
      explicitly approved.
- [ ] TLS termination in front of the API (nginx / Caddy as reverse
      proxy on the isolated VLAN).
- [ ] Host firewall restricts the `securelab-egress` bridge to
      allow-listed integration endpoints only.
- [ ] Docker image verified via Cosign signature before deployment.
- [ ] `POSTGRES_PASSWORD` is a strong random value (not the default
      `securelab`).
- [ ] Audit log is forwarded to CITADEL or a separate syslog target.

## Verifying the Docker image signature

SecureLab images are signed with Cosign at release. Verify before
deployment:

```bash
cosign verify \
  --certificate-identity-regexp "github.com/opensecstack/opensecstack" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/opensecstack/securelab:<version>
```

## Kubernetes deployment

A Kubernetes Helm chart will land with v1.0.0. Until then, the Docker
Compose reference deployment is the supported production configuration.

For Kubernetes, the mandatory isolation controls translate to:

- **NetworkPolicy:** deny all ingress to the SecureLab namespace by
  default; allow only from the operator namespace/VLAN. Deny all
  egress except to the allow-listed integration endpoints and target
  CIDR.
- **PodSecurityPolicy / PSA:** restricted profile. No host networking,
  no privileged containers, read-only root filesystem where possible.
- **Secrets:** use Kubernetes Secrets or an external secrets operator
  (Vault, AWS SSM) for HMAC keys, DB passwords, and the session secret
  key. Never put secrets in ConfigMaps.
- **RBAC:** SecureLab service accounts have no cluster-admin or
  namespace-admin rights.

## Reverse proxy (TLS termination)

Example nginx configuration for TLS termination in front of the
SecureLab API on the isolated VLAN:

```nginx
server {
    listen 443 ssl;
    server_name securelab.internal;

    ssl_certificate     /etc/nginx/certs/securelab.crt;
    ssl_certificate_key /etc/nginx/certs/securelab.key;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;

    # Only allow connections from the operator VLAN
    allow 10.0.100.0/24;
    deny all;

    location / {
        proxy_pass         http://127.0.0.1:8087;
        proxy_set_header   Host $host;
        proxy_set_header   X-Real-IP $remote_addr;
        proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header   X-Request-Id $request_id;
    }
}
```

## Upgrade procedure

```bash
# 1. Pull the new image
docker pull ghcr.io/opensecstack/securelab:<new-version>

# 2. Verify the image signature (see above)

# 3. Stop the current stack
docker compose down

# 4. Update the image tag in docker-compose.yml

# 5. Start the new stack
docker compose up -d

# 6. Run any pending migrations
docker compose exec securelab alembic upgrade head

# 7. Verify health
curl http://127.0.0.1:8087/api/v1/health
```

## Data persistence and backup

- **Postgres:** use `pg_dump` for regular backups. The `audit_log`
  table is INSERT-only and should be backed up frequently — it is
  the primary audit trail.
- **Payload store:** the content-addressed payload store
  (`SECURELAB_PAYLOAD_STORE_PATH`) should be backed up alongside the
  database. Execution records reference payloads by hash; a missing
  payload file makes an execution record non-reproducible.
- **Redis:** used only as a Celery broker; no persistent data that
  cannot be regenerated. Backup is optional.

## Related

- [SECURITY.md](../SECURITY.md) — threat model and access control
- [docs/configuration.md](configuration.md) — all env vars
- [docs/operator-handbook.md](operator-handbook.md) — day-2 ops
- [../docs/deployment-topology.md](../docs/deployment-topology.md) — ecosystem port map
