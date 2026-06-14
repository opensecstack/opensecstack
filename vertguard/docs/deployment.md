# VertGuard — Deployment

VertGuard supports two first-class deployment paths. Pick the one that
matches your environment:

| Path | Use when | Guide |
|------|----------|-------|
| Docker Compose | Local dev, single-host pilots, air-gapped demos | [`../docker-compose.yml`](../docker-compose.yml) + [`quick-start.md`](quick-start.md) |
| Helm / Kubernetes | Production, HA, multi-tenant clusters | [`deployment-helm.md`](deployment-helm.md) |

## Docker Compose (dev / pilot)

The repo-root `docker-compose.yml` brings up Postgres (`:5438`),
VertGuard API (`:8091`) and the dashboard (`:3009`). Defaults are tuned
for development — `VERTGUARD_AUTH_SECRET` and `VERTGUARD_DB_PASSWORD`
are placeholders and must be replaced before any external exposure.

```bash
docker compose up -d
curl http://localhost:8091/api/v1/health
```

See [`quick-start.md`](quick-start.md) for first-login JWT bootstrap and
[`configuration.md`](configuration.md) for the full env-var reference.

## Helm / Kubernetes (production)

The Helm chart at `deploy/helm/vertguard/` is the supported production
path. It bundles:

- HA Deployment (rolling, `maxUnavailable=0`) with PDB and HPA
- Optional Bitnami PostgreSQL subchart (or BYO managed DB)
- Hardened pod/container security context (non-root, RO root FS, drop
  ALL capabilities)
- Optional NetworkPolicy, Ingress (TLS), prometheus-operator
  ServiceMonitor

Full guide: [`deployment-helm.md`](deployment-helm.md).

## Configuration reference

Both paths consume the same `VERTGUARD_*` env vars defined in
`internal/config/config.go`. See [`configuration.md`](configuration.md)
for the canonical list.
