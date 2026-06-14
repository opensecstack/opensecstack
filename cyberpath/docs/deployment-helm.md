# CyberPath — Helm / Kubernetes Deployment

Production deployment guide for CyberPath on Kubernetes via the
in-tree Helm chart at `deploy/helm/cyberpath/` (lands with v1.0.0).

For single-host docker-compose, see [deployment.md](deployment.md).
For env-var reference, see [configuration.md](configuration.md).

## Prerequisites

- Kubernetes **1.27+** (PSA `restricted` profile compatible)
- Helm **3.13+**
- A CNI that enforces NetworkPolicy (Cilium, Calico) — required for
  cross-tenant isolation
- cert-manager 1.13+ (recommended) or pre-issued TLS certs
- prometheus-operator with `ServiceMonitor` CRDs (optional)
- SealedSecrets / External Secrets Operator / Vault CSI for secrets
- For Wasm sandbox labs (v1.0.0+): a node pool tolerating the
  `cyberpath.opensecstack.io/sandbox` taint

## Quickstart

```bash
helm repo add opensecstack https://charts.opensecstack.org
helm repo update

helm install cyberpath opensecstack/cyberpath \
  --namespace cyberpath --create-namespace \
  --set secret.create=true \
  --set secret.authSecret="$(openssl rand -hex 32)"

kubectl -n cyberpath run -it --rm curl --image=curlimages/curl --restart=Never -- \
  curl -sf http://cyberpath.cyberpath.svc.cluster.local:8086/readyz
```

The chart's `helm test` hook performs the same probe:
`helm test cyberpath -n cyberpath`.

## Chart layout

```
deploy/helm/cyberpath/
  Chart.yaml
  values.yaml
  templates/
    _helpers.tpl
    api-deployment.yaml
    api-service.yaml
    web-deployment.yaml
    web-service.yaml
    sandbox-daemonset.yaml          # v1.0.0+, wasmtime host
    sandbox-networkpolicy.yaml
    configmap.yaml
    secret.yaml                     # only when secret.create=true
    ingress.yaml
    hpa.yaml
    pdb.yaml
    serviceaccount.yaml
    rbac.yaml
    servicemonitor.yaml
    NOTES.txt
  charts/
    postgresql/                     # bitnami subchart, optional
```

## values.yaml reference

### Top-level

```yaml
replicaCount: 3

image:
  repository: ghcr.io/opensecstack/cyberpath
  tag:        "1.0.0"
  pullPolicy: IfNotPresent
  pullSecrets:
    - name: ghcr-pull

existingSecret: cyberpath-secrets    # ESO / SealedSecrets reference
secret:
  create: false                      # never true in prod

serviceAccount:
  create: true
  annotations: {}

podSecurityContext:
  runAsNonRoot: true
  runAsUser:    65532
  fsGroup:      65532
  seccompProfile: { type: RuntimeDefault }

containerSecurityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem:   true
  capabilities: { drop: [ALL] }
```

### `api`

```yaml
api:
  port: 8086
  resources:
    requests: { cpu: 200m, memory: 256Mi }
    limits:   { cpu: "2",  memory: 1Gi }
  env: {}
  config:
    log_level: info
    auth:
      issuer: cyberpath
    citadel:
      enabled:    true
      api_url:    https://citadel.internal:8099
      project_id: prod
    nis2compass:
      api_url: https://nis2.internal:8092
    irflow:
      api_url: https://irflow.internal:8087
```

### `web`

```yaml
web:
  port: 3006
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits:   { cpu: 500m, memory: 256Mi }
  apiUrl: https://cyberpath.example.com
```

### `sandbox` (v1.0.0+)

```yaml
sandbox:
  enabled:    true
  runtime:    wasmtime         # wasmtime | docker (development only)
  cpuQuota:   "1.0"
  memoryMib:  512
  network:    none             # none | egress-only | lab-net
  pidsLimit:  256
  imageRegistry: ghcr.io/opensecstack
  hpa:
    enabled:        true
    minReplicas:    2
    maxReplicas:    20
    targetCPU:      70
    targetSessions: 40         # custom metric: cyberpath_sandbox_active_sessions
  nodeSelector:
    node-role.opensecstack.io/sandbox: "true"
  tolerations:
    - key:      cyberpath.opensecstack.io/sandbox
      operator: Exists
      effect:   NoSchedule
```

### `postgresql` (subchart)

```yaml
postgresql:
  enabled: false               # use managed Postgres in prod
  auth:
    username: cyberpath
    database: cyberpath
  primary:
    persistence: { size: 20Gi }
```

### `ingress`

```yaml
ingress:
  enabled:   true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer:           letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-read-timeout:    "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout:    "3600"
    nginx.ingress.kubernetes.io/proxy-buffering:       "off"
  hosts:
    - host: cyberpath.example.com
      paths:
        - { path: /,                pathType: Prefix, backend: web }
        - { path: /api,             pathType: Prefix, backend: api }
        - { path: /api/v1/labs,     pathType: Prefix, backend: api }   # WebSocket
  tls:
    - secretName: cyberpath-tls
      hosts: [cyberpath.example.com]
```

### `monitoring`

```yaml
metrics:
  serviceMonitor:
    enabled:   true
    namespace: monitoring
    interval:  30s
```

### `networkPolicy`

```yaml
networkPolicy:
  enabled: true
  ingress:
    fromNamespaces: [ingress-nginx, monitoring]
  egress:
    toCIDRs:
      - 10.20.0.0/16     # CITADEL / NIS2 Compass / IRFlow VNet
    allowDNS: true
```

### `content`

```yaml
content:
  source: configmap            # configmap | sidecar | s3
  configMap:
    name: cyberpath-content
  sidecar:
    image: ghcr.io/opensecstack/cyberpath-content:1.0.0
  s3:
    bucket:    cyberpath-content
    prefix:    prod/
    region:    eu-west-1
    syncCron:  "0 */6 * * *"
```

## Sample `values.production.yaml`

```yaml
replicaCount: 3

image:
  tag: "1.0.0"
  pullSecrets: [{ name: ghcr-pull }]

existingSecret: cyberpath-secrets

api:
  config:
    citadel:
      enabled: true
      api_url: https://citadel.internal:8099
    nis2compass:
      api_url: https://nis2.internal:8092
    db:
      host:     cyberpath.cluster-abc.eu-west-1.rds.amazonaws.com
      ssl_mode: verify-full

postgresql: { enabled: false }

ingress:
  enabled: true
  className: nginx
  hosts: [{ host: cyberpath.example.com, paths: [{ path: /, pathType: Prefix }] }]
  tls:   [{ secretName: cyberpath-tls, hosts: [cyberpath.example.com] }]

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 12

sandbox:
  enabled: true
  runtime: wasmtime
  hpa: { enabled: true, minReplicas: 4, maxReplicas: 30 }

networkPolicy:
  enabled: true

metrics:
  serviceMonitor: { enabled: true, namespace: monitoring }

content:
  source: s3
  s3:    { bucket: cyberpath-content, prefix: prod/, region: eu-west-1 }
```

## Sealed-secrets bootstrap

The chart's `existingSecret` is the integration point. The Deployment
mounts the following keys as env vars:

- `auth-secret` → `CYBERPATH_AUTH_SECRET`
- `db-password` → injected into `CYBERPATH_DB_URL`
- `citadel-key-secret` → `CYBERPATH_CITADEL_KEY_SECRET`
- `irflow-webhook-secret` → `CYBERPATH_IRFLOW_WEBHOOK_SECRET`
- `cert-signing-key-ref` → `CYBERPATH_CERT_SIGNING_KEY` (KMS reference)

External Secrets Operator example:

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: cyberpath-secrets
  namespace: cyberpath
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: vault-backend
    kind: ClusterSecretStore
  target:
    name: cyberpath-secrets
  data:
    - secretKey: auth-secret
      remoteRef: { key: secret/cyberpath/auth-secret }
    - secretKey: db-password
      remoteRef: { key: secret/cyberpath/db-password }
    - secretKey: citadel-key-secret
      remoteRef: { key: secret/cyberpath/citadel-hmac }
    - secretKey: irflow-webhook-secret
      remoteRef: { key: secret/cyberpath/irflow-webhook }
```

The Secret must exist before `helm install` — ESO/SealedSecrets
reconcile order matters.

## Content distribution

Three options, in order of operational simplicity:

| Mode | When to use | Trade-off |
|---|---|---|
| `configmap` | Tracks rarely change; total size < 1 MiB | Fits in etcd; redeploy to update content |
| `sidecar` | Tracks change weekly; total size < 100 MiB | Image rebuild per content release; deterministic |
| `s3` | Tracks change frequently; multi-region; > 100 MiB | Requires periodic sync sidecar; eventual consistency |

For audit-grade environments, prefer `sidecar` — content lives in
an OCI image with a content-addressable digest, the same trust
chain as the API binary.

## HPA for sandbox pods (v1.0.0+)

Lab sandbox pods scale on a custom metric:

```yaml
sandbox:
  hpa:
    enabled: true
    minReplicas: 4
    maxReplicas: 30
    metrics:
      - type: Pods
        pods:
          metric: { name: cyberpath_sandbox_active_sessions }
          target:
            type: AverageValue
            averageValue: "40"
```

Tune `targetSessions` against your `SANDBOX_MEMORY_MIB` and observed
peak concurrency. Each wasmtime session is ~50 MiB resident in
typical configurations.

## NetworkPolicy for cross-tenant isolation

Sandbox pods are isolated from each other and from the API by
default. The chart renders one `NetworkPolicy` per namespace that:

- Allows ingress to `api` only from `ingress-nginx` and the
  Prometheus namespace
- Allows ingress to `web` only from `ingress-nginx`
- Allows ingress to sandbox pods only from `api` (terminal relay)
- Denies sandbox-to-sandbox traffic
- Allows egress from `api` to the configured CIDRs (CITADEL, NIS2,
  IRFlow), DNS, and the configured Postgres host

Multi-tenant deployments label namespaces with
`cyberpath.opensecstack.io/tenant: <id>` and inherit isolation from
the chart's tenant-aware policies.

## Multi-AZ ingress

For HA across availability zones:

- `replicaCount: ≥ 3` with `topologySpreadConstraints` per zone
- Bind `Service` to a load-balancer that fronts all zones
- Postgres: managed multi-AZ (RDS multi-AZ, Cloud SQL HA) — the chart
  does not manage cross-AZ DB failover

```yaml
topologySpreadConstraints:
  - maxSkew:           1
    topologyKey:       topology.kubernetes.io/zone
    whenUnsatisfiable: DoNotSchedule
    labelSelector:
      matchLabels:
        app.kubernetes.io/name:      cyberpath
        app.kubernetes.io/component: api
```

## Upgrade & rollback

```bash
helm upgrade cyberpath opensecstack/cyberpath \
  -n cyberpath -f values.production.yaml --atomic --timeout 5m

helm history  cyberpath -n cyberpath
helm rollback cyberpath <REV> -n cyberpath
```

The Deployment uses `RollingUpdate maxSurge=25% maxUnavailable=0`,
so an upgrade temporarily adds capacity rather than removing it.
The `checksum/config` annotation forces a pod restart on
ConfigMap change.

## Troubleshooting

- **`CrashLoopBackOff`** — `kubectl logs -n cyberpath <pod> --previous`.
  Common causes: missing `auth-secret` key in the referenced Secret,
  `db.ssl_mode=verify-full` against a Postgres without TLS, content
  ConfigMap too large.
- **Lab session 503** — sandbox pods unhealthy or HPA at min. Check
  `kubectl get pods -l app.kubernetes.io/component=sandbox`.
- **`existingSecret` not found** — the Secret must exist before
  `helm install`. Verify ESO/SealedSecrets reconciled first.
- **WebSocket terminal disconnects after 60s** — ingress timeouts.
  Set `proxy-read-timeout`/`proxy-send-timeout` ≥ session TTL.

## See also

- [deployment.md](deployment.md)
- [configuration.md](configuration.md)
- [troubleshooting.md](troubleshooting.md)
- [architecture.md](architecture.md)
- [citadel-integration.md](citadel-integration.md)
- [nis2-integration.md](nis2-integration.md)
