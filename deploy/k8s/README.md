# OpenSecStack — Kubernetes Deployment

Plain Kubernetes YAML manifests for the full OpenSecStack ecosystem
(APIGuard + NIS2 Compass + shared Postgres + Redis).

## Prerequisites

- `kubectl` configured against your target cluster
- An nginx Ingress controller installed in the cluster
  (`kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.10.1/deploy/static/provider/cloud/deploy.yaml`)
- A default `StorageClass` that supports `ReadWriteOnce` (most managed clusters provide one)

---

## 1. Create the namespace

```bash
kubectl apply -f deploy/k8s/namespace.yaml
```

---

## 2. Create secrets

**Never commit real secret values.** Use `kubectl create secret` directly:

```bash
# Database passwords
kubectl create secret generic opensecstack-db-secrets \
  --namespace opensecstack \
  --from-literal=POSTGRES_PASSWORD='<strong-password>' \
  --from-literal=NIS2_DB_PASSWORD='<strong-password>' \
  --from-literal=APIGUARD_DB_PASSWORD='<strong-password>'

# Application secrets
kubectl create secret generic opensecstack-app-secrets \
  --namespace opensecstack \
  --from-literal=APIGUARD_JWT_SECRET='<random-string-min-32-chars>' \
  --from-literal=NIS2_JWT_SECRET='<random-string-min-32-chars>' \
  --from-literal=NIS2_SECRET_KEY='<random-string-min-32-chars>' \
  --from-literal=REDIS_PASSWORD='<strong-password>'
```

`secrets.yaml.example` shows the Secret resource structure for reference.
You can also use it as a template — fill in real base64-encoded values and apply
it — but **do not commit that file to source control**.

To base64-encode a value:
```bash
echo -n 'your-value' | base64
```

---

## 3. Apply the manifests

```bash
kubectl apply -f deploy/k8s/ -R -n opensecstack
```

The `-R` flag recurses into subdirectories (`postgres/`, `redis/`, `apiguard/`,
`nis2compass/`). The `-n opensecstack` flag is a safety net; all manifests
already declare `namespace: opensecstack` explicitly.

### Apply order (if applying selectively)

1. `namespace.yaml`
2. `secrets.yaml` (your real secrets file, not the example)
3. `configmap.yaml`
4. `postgres/pvc.yaml`
5. `postgres/deployment.yaml` + `postgres/service.yaml`
6. `redis/deployment.yaml` + `redis/service.yaml`
7. `apiguard/deployment.yaml` + `apiguard/service.yaml` + `apiguard/ingress.yaml`
8. `nis2compass/deployment.yaml` + `nis2compass/service.yaml` + `nis2compass/ingress.yaml`

---

## 4. Database initialisation (NIS2 Compass)

The NIS2 Compass deployment includes an `initContainer` that runs
`python -m alembic upgrade head` before the main container starts.
This handles schema creation and migrations automatically on every rollout.

For the APIGuard service, migrations are managed by the application binary
itself on startup (golang-migrate embedded). No separate init step is needed.

### NIS2 database user

The shared Postgres instance uses `apiguard` as the superuser
(matching `POSTGRES_USER`). The `nis2compass` database and its dedicated DB
user must be created before the NIS2 service can connect. Mount the init SQL
script from `deploy/scripts/init-nis2-db.sql` as a ConfigMap into the Postgres
container's `/docker-entrypoint-initdb.d/` directory — see the commented-out
volume mount in `postgres/deployment.yaml`.

---

## 5. Check status

```bash
# Overall pod health
kubectl get pods -n opensecstack

# Watch rollout progress
kubectl rollout status deployment/apiguard -n opensecstack
kubectl rollout status deployment/nis2compass -n opensecstack

# Describe a pod for events / probe failures
kubectl describe pod -l app=apiguard -n opensecstack

# Tail logs
kubectl logs -l app=apiguard -n opensecstack --tail=100 -f
kubectl logs -l app=nis2compass -n opensecstack --tail=100 -f
```

---

## 6. Local access (port-forward)

If you are not using an Ingress controller locally, use `kubectl port-forward`:

```bash
# APIGuard API
kubectl port-forward svc/apiguard-service 8080:8080 -n opensecstack

# NIS2 Compass API
kubectl port-forward svc/nis2compass-service 8090:8090 -n opensecstack

# Postgres (for direct DB inspection)
kubectl port-forward svc/postgres-service 5432:5432 -n opensecstack
```

Then access the services at:
- APIGuard:    http://localhost:8080
- NIS2 Compass: http://localhost:8090

---

## 7. Ingress hostnames

Update the `host:` field in each ingress manifest before applying to production:

| File | Placeholder | Replace with |
|---|---|---|
| `apiguard/ingress.yaml` | `apiguard.opensecstack.local` | your real DNS name |
| `nis2compass/ingress.yaml` | `nis2compass.opensecstack.local` | your real DNS name |

For local testing without real DNS, add entries to `/etc/hosts` (or `C:\Windows\System32\drivers\etc\hosts` on Windows):

```
<ingress-controller-external-ip>  apiguard.opensecstack.local
<ingress-controller-external-ip>  nis2compass.opensecstack.local
```

Get the external IP with:
```bash
kubectl get svc -n ingress-nginx ingress-nginx-controller
```

---

## 8. TLS

TLS sections are present but commented out in both ingress manifests.
To enable TLS:

1. Create a TLS secret (manually or via cert-manager):
   ```bash
   kubectl create secret tls apiguard-tls \
     --cert=tls.crt --key=tls.key -n opensecstack
   ```
2. Uncomment the `tls:` block in the relevant ingress file.
3. Uncomment `nginx.ingress.kubernetes.io/ssl-redirect: "true"`.

---

## File structure

```
deploy/k8s/
  namespace.yaml            # opensecstack namespace
  secrets.yaml.example      # Secret structure reference (no real values)
  configmap.yaml            # Non-secret configuration
  postgres/
    pvc.yaml                # 10Gi persistent volume claim
    deployment.yaml         # postgres:16-alpine, single replica
    service.yaml            # ClusterIP :5432
  redis/
    deployment.yaml         # redis:7-alpine, single replica, requirepass
    service.yaml            # ClusterIP :6379
  apiguard/
    deployment.yaml         # 2 replicas, readiness/liveness probes
    service.yaml            # ClusterIP :8080
    ingress.yaml            # nginx, host apiguard.opensecstack.local
  nis2compass/
    deployment.yaml         # 2 replicas, alembic initContainer, probes
    service.yaml            # ClusterIP :8090
    ingress.yaml            # nginx, host nis2compass.opensecstack.local
  README.md                 # This file
```
