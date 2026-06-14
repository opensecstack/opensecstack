# VertGuard — Helm / Kubernetes Deployment

Production deployment guide for VertGuard on Kubernetes via the in-tree
Helm chart at `deploy/helm/vertguard/`.

## Prerequisites

- Kubernetes **1.27+** (PSA `restricted` profile compatible)
- Helm **3.13+**
- `kubectl` access to the target cluster
- A CNI that enforces NetworkPolicies (Cilium, Calico) — required if you
  enable `networkPolicy.enabled=true`
- For TLS: cert-manager 1.13+ (recommended) or pre-issued certs
- For metrics: prometheus-operator with `ServiceMonitor` CRDs (optional)
- For sealed secrets: SealedSecrets / External Secrets Operator / Vault CSI

## Quickstart

```bash
# 1. Add the OpenSecStack Helm repository (placeholder — replace once published).
helm repo add opensecstack https://charts.opensecstack.org
helm repo update

# 2. Install with bundled Postgres and a chart-managed dev Secret.
helm install vertguard opensecstack/vertguard \
  --namespace vertguard --create-namespace \
  --set secret.create=true \
  --set secret.authSecret="$(openssl rand -hex 32)"

# 3. Smoke test.
kubectl -n vertguard run -it --rm curl --image=curlimages/curl --restart=Never -- \
  curl -sf http://vertguard.vertguard.svc.cluster.local:8091/api/v1/health
```

The chart's `helm test` hook performs the same probe:
`helm test vertguard -n vertguard`.

## Production checklist

- [ ] **TLS** — terminate at the Ingress (`ingress.tls`) or upstream LB.
- [ ] **Sealed secrets** — set `existingSecret: vertguard-secrets` and
      drop `secret.create=true`. Required keys: `auth-secret`,
      `db-password`, `citadel-hmac-secret`, `threatflow-webhook-secret`.
- [ ] **External database** — set `postgresql.enabled=false`,
      `config.db.host` to a managed Postgres (RDS / Cloud SQL) with
      `ssl_mode: verify-full`.
- [ ] **NetworkPolicy** — `networkPolicy.enabled=true`, list approved
      namespaces under `networkPolicy.ingress.namespaces`, and pin
      egress CIDRs for CITADEL/ThreatFlow under `egress.extraCIDRs`.
- [ ] **PDB** — `podDisruptionBudget.enabled=true` (default), keep
      `replicaCount >= 2`.
- [ ] **ServiceMonitor** — `metrics.serviceMonitor.enabled=true` for
      prometheus-operator scrapes; otherwise rely on the `prometheus.io/*`
      annotations.
- [ ] **HPA** — `autoscaling.enabled=true` once load patterns are known.
- [ ] **Image pinning** — set `image.tag` to a content-addressable digest.

### Sample `values.production.yaml`

```yaml
replicaCount: 3

image:
  tag: "0.1.0"               # pin or use @sha256:...
  pullSecrets:
    - name: ghcr-pull

existingSecret: vertguard-secrets   # provisioned via ESO / SealedSecrets

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  hosts:
    - host: vertguard.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: vertguard-tls
      hosts: [vertguard.example.com]

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 12

metrics:
  serviceMonitor:
    enabled: true
    namespace: monitoring

networkPolicy:
  enabled: true
  ingress:
    namespaces: [ingress-nginx, monitoring]
  egress:
    extraCIDRs: ["10.20.0.0/16"]   # CITADEL/ThreatFlow VNet

postgresql:
  enabled: false                    # use managed Postgres

config:
  db:
    host: vertguard.cluster-abc.eu-west-1.rds.amazonaws.com
    ssl_mode: verify-full
  auth:
    dev_mode: false
  citadel:
    enabled: true
    base_url: https://citadel.internal
  threatflow:
    api_url: https://threatflow.internal
```

## Secrets management

The chart's `existingSecret` field is the integration point for an
out-of-band secret-provisioning workflow. The Deployment mounts four keys
as env vars: `auth-secret`, `db-password`, `citadel-hmac-secret`,
`threatflow-webhook-secret`.

For the supported provisioning patterns (Bitnami sealed-secrets and Vault
+ External Secrets Operator), rotation procedures, audit checklist, and
disaster-recovery notes, see [secrets-management.md](secrets-management.md).
Worked examples live under [secrets/](secrets/):

- [secrets/example-sealed-secret.yaml](secrets/example-sealed-secret.yaml)
- [secrets/example-external-secret.yaml](secrets/example-external-secret.yaml)

Do **not** rely on `secret.create=true` in production — the rendered
Secret becomes part of the Helm release manifest.

## Upgrade & rollback

```bash
helm upgrade vertguard opensecstack/vertguard \
  -n vertguard -f values.production.yaml --atomic --timeout 5m

helm history vertguard -n vertguard
helm rollback vertguard <REV> -n vertguard
```

The Deployment uses `RollingUpdate maxSurge=25% maxUnavailable=0`, so an
upgrade temporarily adds capacity rather than removing it. The chart's
`checksum/config` annotation forces a pod restart on ConfigMap change.

## Troubleshooting

- **`CrashLoopBackOff`** — `kubectl logs -n vertguard <pod> --previous`.
  Common causes: missing `auth-secret` key in the referenced Secret;
  `db.ssl_mode=require` against a Postgres without TLS; bad
  `config.db.host`. Cross-check with `WarnIfInsecure` warnings printed
  on startup.
- **DB migration on first boot** — VertGuard auto-applies
  `internal/db/migrations/*.sql` at startup. If the user lacks DDL, run
  the SQL out-of-band as a privileged role and grant the runtime user
  `SELECT, INSERT, UPDATE, DELETE` on the resulting schema.
- **Health probe failing but app up** — `/api/v1/health` pings the DB.
  A red probe almost always means the DB connection — check the
  Postgres pod / NetworkPolicy egress on TCP/5432.
- **`existingSecret` not found** — Helm renders the manifest but the
  pod fails to start. Verify with
  `kubectl get secret -n vertguard <name>`; the Secret must exist
  before `helm install` (ESO/SealedSecrets reconcile order matters).

## Disaster recovery

Critical tables for forensics & compliance:

- `audit_events` — every authenticated mutation (NIS2 Art. 21, AI Act).
- `prompt_scans`, `threat_iocs`, `webhook_subscribers` — operational
  state; reconstructable from CITADEL WORM if integration is enabled.

Recommended cadence:

```bash
# Logical backup, daily, retained 30d (encrypt at rest).
kubectl -n vertguard exec -it vertguard-postgresql-0 -- \
  pg_dump -U vertguard -Fc vertguard > vertguard-$(date +%F).dump
```

Restore drill (quarterly):

```bash
kubectl -n vertguard exec -i vertguard-postgresql-0 -- \
  pg_restore -U vertguard -d vertguard --clean --if-exists < vertguard-YYYY-MM-DD.dump
```

If CITADEL WORM is enabled (`config.citadel.enabled=true`), the
audit_events stream is also mirrored immutably upstream; a partial
restore can be reconciled from the CITADEL log.

## ML inference service

VertGuard's Python ML inference service ships as a **subchart** under
`deploy/helm/vertguard/charts/ml/` and is gated by a single parent flag:

```yaml
# parent values.yaml
ml:
  enabled: true        # default false — Phase 4.2 stub backend until DistilBERT v1
```

When the flag is on, Helm renders:

- `Deployment vertguard-ml` (gRPC server, `:50051`, `:9100/metrics`),
- `Service vertguard-ml` (stable name — Go side discovers it via DNS),
- `ConfigMap`, `Secret` (model-registry creds, optional),
- `NetworkPolicy` allowing only the parent VertGuard pods + Prometheus,
- `ServiceAccount`, `PDB`, `HPA` (CPU + p95 latency),

and the parent Deployment receives `VERTGUARD_ML_GRPC_URL=vertguard-ml:50051`
automatically — no manual wiring.

Override subchart values from the parent file by nesting under `ml.*`:

```yaml
ml:
  enabled: true
  image:
    tag: "0.1.0"
  config:
    backend: stub        # | distilbert | onnx | torch-gpu
    models_path: /var/lib/vertguard/models
  resources:
    requests: { cpu: 200m, memory: 256Mi }
    limits:   { cpu: "1",  memory: 2Gi }
  autoscaling:
    enabled: true
    minReplicas: 1
    maxReplicas: 6
    latency:
      enabled: true
      targetAverageValueMilliseconds: 60
  nodeSelector:
    node-role.opensecstack.io/gpu: "true"   # GPU pool when backend=torch-gpu
  tolerations:
    - key: nvidia.com/gpu
      operator: Exists
      effect: NoSchedule
```

Layout — the subchart mirrors the parent's template set so operators
recognise the manifests:

```
deploy/helm/vertguard/charts/ml/
  Chart.yaml
  values.yaml
  templates/
    _helpers.tpl
    configmap.yaml
    deployment.yaml
    hpa.yaml
    networkpolicy.yaml
    NOTES.txt
    pdb.yaml
    secret.yaml
    service.yaml
    serviceaccount.yaml
```

Opt-in flow:

```bash
# Stub backend, single replica — wire-protocol verification only.
helm upgrade vertguard ./deploy/helm/vertguard -n vertguard \
    -f values.production.yaml --set ml.enabled=true

# Real model (registry-backed) — DistilBERT v1.
helm upgrade vertguard ./deploy/helm/vertguard -n vertguard \
    -f values.production.yaml \
    --set ml.enabled=true \
    --set ml.config.backend=onnx \
    --set ml.config.registry_url=s3://vg-models/distilbert-prompt-injection/v1.0.0
```

Architecture and rollout details:
- [`ml-architecture.md`](ml-architecture.md)
- [`ml-training-guide.md`](ml-training-guide.md)
- [`ml-model-registry.md`](ml-model-registry.md)
- Operator playbook 3.10 in [`operator-runbook.md`](operator-runbook.md).

## Validation

`helm lint deploy/helm/vertguard` and `helm template deploy/helm/vertguard`
were **not** run on the authoring host (the `helm` binary was unavailable
in the sandbox at chart-creation time). Templates were authored against
Helm 3.13 conventions and reviewed by inspection. Run both commands
locally before publishing the chart.
