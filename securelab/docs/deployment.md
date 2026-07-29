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
                              │ Firewall: allow operator VLAN → port 3000/8080
                              ▼
  ┌───────────────────────────────────────────────────────────────┐
  │  SECURELAB NETWORK SEGMENT (isolated bridge / VLAN)          │
  │  Subnet: e.g. 172.30.0.0/24                                  │
  │                                                               │
  │  securelab-api     :8080   (Go binary)                       │
  │  securelab-web     :3000   (React, nginx)                    │
  │  securelab-db      :5432   (PostgreSQL, internal only)       │
  │                                                               │
  │  Firewall rules (egress):                                     │
  │   ALLOW → CITADEL API endpoint (specific IP:port)            │
  │   ALLOW → OpenScrub API endpoint                             │
  │   ALLOW → APIGuard API endpoint                              │
  │   ALLOW → ThreatFlow API endpoint                            │
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

1. **No public internet exposure.** The API port (8080) and dashboard
   port (3000) must not be reachable from the internet under any
   circumstances.
2. **No routing to production.** The SecureLab network segment must
   not have a route to production network segments. Use separate VLANs
   and explicit firewall rules.
3. **Egress is allow-listed.** Only the specific IP/port combinations
   of integration endpoints and the target simulation CIDR should be
   permitted as egress from the SecureLab segment, enforced at your
   host/VLAN firewall.
4. **Postgres is internal only.** The shipped `docker-compose.yml`
   does not publish a host port for `securelab-db` — keep it that way.

## Docker Compose deployment

The provided `docker-compose.yml` defines three services on a single
`securelab-net` bridge network: `securelab-api` (Go binary, port 8080
bound to `127.0.0.1`), `securelab-web` (nginx serving the built React
app, port 3000 bound to `127.0.0.1`), and `securelab-db` (PostgreSQL
16, no published host port). It does not itself enforce a hardened
`internal: true` / egress-restricted network — that isolation is the
operator's responsibility, per the rules above, at the VLAN/firewall
level surrounding the Docker host.

### Steps

```bash
# 1. Clone repository
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/securelab

# 2. Configure environment
cp .env.example .env
# Edit .env — see docs/configuration.md for required values

# 3. Start the stack (builds images from source)
docker compose up -d --build

# 4. Verify health
curl http://127.0.0.1:8080/health
```

Database migrations run automatically as part of the API server's
startup path (see `cmd/server`); there is no separate migration step
to run against the container.

### Production hardening checklist

- [ ] `SECURELAB_HTTP_ADDR` is set to `127.0.0.1:8080` or a private
      VLAN address. Not `0.0.0.0`, unless a reverse proxy on the same
      isolated host is the only thing that can reach it.
- [ ] `SECURELAB_CITADEL_DRY_RUN=false` only after the CITADEL
      integration has been validated end-to-end.
- [ ] `SECURELAB_JWT_SECRET` and `SECURELAB_CITADEL_HMAC_SECRET` are
      strong, random, and not the values from `.env.example`.
- [ ] TLS termination in front of the API (nginx / Caddy as reverse
      proxy on the isolated VLAN) — the shipped compose file does not
      terminate TLS itself.
- [ ] Host/VLAN firewall restricts outbound traffic from the Docker
      host to allow-listed integration endpoints only.
- [ ] Docker image verified via Cosign signature before deployment.
- [ ] `SECURELAB_DB_PASSWORD` is a strong random value.
- [ ] Audit-relevant events are confirmed flowing to CITADEL (see
      [docs/citadel-integration.md](citadel-integration.md)).

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

No Kubernetes/Helm manifests ship in this repository today. The
Docker Compose reference deployment is the supported configuration.
If you deploy SecureLab on Kubernetes yourself, the mandatory
isolation controls above translate to:

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
        proxy_pass         http://127.0.0.1:8080;
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

# 6. Verify health — pending migrations apply automatically on startup
curl http://127.0.0.1:8080/health
```

## Data persistence and backup

- **Postgres:** use `pg_dump` for regular backups of the
  `securelab-db-data` volume. This is the only persistent store —
  scenarios, environments, run results, and MITRE ATT&CK coverage
  data all live in PostgreSQL (see `internal/db/migrations/`).
- There is no separate broker or content-addressed payload store in
  the current implementation; nothing else requires backup.

## Related

- [SECURITY.md](../SECURITY.md) — threat model and access control
- [docs/configuration.md](configuration.md) — all env vars
- [docs/operator-handbook.md](operator-handbook.md) — day-2 ops
- [../docs/deployment-topology.md](../docs/deployment-topology.md) — ecosystem port map
