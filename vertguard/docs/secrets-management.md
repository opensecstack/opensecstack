## Secrets management

VertGuard reads every sensitive value from environment variables sourced from
a Kubernetes Secret. The Helm chart ([values.yaml](../deploy/helm/vertguard/values.yaml))
exposes two modes via [templates/secret.yaml](../deploy/helm/vertguard/templates/secret.yaml):

- `secret.create=true` — chart materialises a Secret from inline values.
  Suitable for dev/CI only; the plaintext ends up in the Helm release.
- `existingSecret: <name>` — chart references a pre-provisioned Secret.
  This is the integration point for the patterns documented below.

The Deployment ([templates/deployment.yaml](../deploy/helm/vertguard/templates/deployment.yaml))
mounts the four sensitive keys as env vars: `auth-secret`, `db-password`,
`citadel-hmac-secret`, `threatflow-webhook-secret`.

See [deployment-helm.md](deployment-helm.md) for the surrounding chart
configuration.

### Sensitive fields catalogue

Every field maps onto a struct in [internal/config/config.go](../internal/config/config.go).

| Env var | Secret key | Purpose | Blast radius if leaked | Rotation |
|---|---|---|---|---|
| `VERTGUARD_AUTH_SECRET` | `auth-secret` | HS256 JWT signing key (`AuthConfig.Secret`) | Forge any user/operator token; full API takeover | 90 days |
| `VERTGUARD_DB_PASSWORD` | `db-password` | Postgres runtime user password (`DBConfig.Password`) | Read/write all detections, audit_events, IOCs | 180 days |
| `VERTGUARD_CITADEL_HMAC_SECRET` | `citadel-hmac-secret` | HMAC signature for outbound CITADEL WORM emits (`CitadelConfig.HMACSecret`) | Forge audit-stream entries upstream; tamper with compliance log | 90 days |
| `VERTGUARD_THREATFLOW_WEBHOOK_SECRET` | `threatflow-webhook-secret` | Verifies inbound ThreatFlow webhook signatures (`ThreatFlowConfig.WebhookSecret`) | Inject false IOCs into the feed pipeline | 90 days |

`auth.secret` is the highest-impact value: an attacker holding it can issue
admin tokens offline without touching the cluster. Treat it as the rotation
priority.

### Pattern selector

| Criterion | Sealed-secrets | Vault + ESO |
|---|---|---|
| Team size | 1–10 operators | 10+ / multi-team |
| Workflow | GitOps (commit encrypted YAML) | API-driven (UI/CLI write to Vault) |
| Rotation source of truth | Git history | Vault KV versions |
| Multi-cluster sync | Per-cluster reseal required | Single Vault, many ESO consumers |
| Audit trail | Git log | Vault audit device |
| External dependencies | None beyond the controller | Vault HA + unseal infra |

Pick **sealed-secrets** when GitOps is already the deployment substrate and
no central secret store exists. Pick **Vault+ESO** when central rotation,
audit, or cross-cluster sync are hard requirements.

> **Do not use** any of the following:
> - Plaintext secrets in `values.yaml` committed to git.
> - `.env` files or `kubectl create secret` output committed to git.
> - Secrets passed via `helm install --set authSecret=...` from CI logs
>   (the value lands in the release manifest and shell history).
> - `secret.create=true` in production — the rendered Secret is part of
>   the Helm release object, readable by anyone with `helm get manifest`.

### Pattern A: Bitnami sealed-secrets

Upstream: <https://github.com/bitnami-labs/sealed-secrets>.

Encrypts a Secret manifest offline against a per-cluster public key. The
ciphertext is safe to commit; only the in-cluster controller can decrypt.

#### Steps

1. **Install the controller.**

   ```bash
   helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets
   helm install sealed-secrets sealed-secrets/sealed-secrets \
     -n kube-system --set-string fullnameOverride=sealed-secrets-controller
   ```

2. **Fetch the cluster public certificate.** This is safe to share.

   ```bash
   kubeseal --controller-name=sealed-secrets-controller \
            --controller-namespace=kube-system \
            --fetch-cert > pub-cert.pem
   ```

3. **Build the Secret manifest locally** (never commit this file).

   ```bash
   kubectl create secret generic vertguard-secrets \
     --namespace vertguard \
     --from-literal=auth-secret="$(openssl rand -hex 32)" \
     --from-literal=db-password="$(openssl rand -base64 24)" \
     --from-literal=citadel-hmac-secret="$(openssl rand -hex 32)" \
     --from-literal=threatflow-webhook-secret="$(openssl rand -hex 32)" \
     --dry-run=client -o yaml > secret.yaml
   ```

4. **Seal it.**

   ```bash
   kubeseal --cert pub-cert.pem --format yaml \
     < secret.yaml > sealed-secret.yaml
   shred -u secret.yaml
   ```

5. **Commit `sealed-secret.yaml` to git.** Decryptable only by the target
   cluster's controller. See [secrets/example-sealed-secret.yaml](secrets/example-sealed-secret.yaml).

6. **Apply and wire Helm.**

   ```bash
   kubectl apply -f sealed-secret.yaml
   kubectl -n vertguard get secret vertguard-secrets   # should now exist
   helm upgrade vertguard opensecstack/vertguard \
     -n vertguard -f values.production.yaml \
     --set existingSecret=vertguard-secrets
   ```

### Pattern B: Vault + External Secrets Operator

ESO docs: <https://external-secrets.io>. Vault docs: <https://developer.hashicorp.com/vault>.

Materialises a K8s Secret from a Vault KV path. Rotating in Vault propagates
to the cluster within the configured `refreshInterval`.

#### Steps

1. **Provision a KV v2 mount and write the four keys.**

   ```bash
   vault secrets enable -path=vertguard kv-v2
   vault kv put vertguard/prod \
     auth-secret="$(openssl rand -hex 32)" \
     db-password="$(openssl rand -base64 24)" \
     citadel-hmac-secret="$(openssl rand -hex 32)" \
     threatflow-webhook-secret="$(openssl rand -hex 32)"
   ```

2. **Bind the cluster's ServiceAccount to a Vault role** via the Kubernetes
   auth method.

   ```bash
   vault auth enable kubernetes
   vault write auth/kubernetes/config \
     kubernetes_host="https://kubernetes.default.svc"
   vault policy write vertguard-read - <<EOF
   path "vertguard/data/prod" { capabilities = ["read"] }
   EOF
   vault write auth/kubernetes/role/vertguard \
     bound_service_account_names=vertguard \
     bound_service_account_namespaces=vertguard \
     policies=vertguard-read \
     ttl=1h
   ```

3. **Install ESO.**

   ```bash
   helm repo add external-secrets https://charts.external-secrets.io
   helm install external-secrets external-secrets/external-secrets \
     -n external-secrets --create-namespace
   ```

4. **Apply a `SecretStore`** pointing at the Vault role + path. See
   [secrets/example-external-secret.yaml](secrets/example-external-secret.yaml).

5. **Apply an `ExternalSecret`** that materialises `vertguard-secrets`
   from `vertguard/prod`. ESO writes the K8s Secret on first reconcile and
   refreshes on the configured interval.

6. **Verify and wire Helm.**

   ```bash
   kubectl -n vertguard get externalsecret vertguard-secrets
   kubectl -n vertguard get secret vertguard-secrets
   helm upgrade vertguard opensecstack/vertguard \
     -n vertguard -f values.production.yaml \
     --set existingSecret=vertguard-secrets
   ```

### Rotation procedures

VertGuard supports **dual-secret JWT rotation** so operators can roll the
auth secret without invalidating in-flight tokens. The verifier accepts up
to three secrets simultaneously, in priority order:

| Env var | Slot | Purpose |
|---|---|---|
| `VERTGUARD_AUTH_SECRET` | `primary` | Active signing secret (always set) |
| `VERTGUARD_AUTH_SECRET_NEXT` | `next` | Optional. Pre-rollover: tokens may already be signed with this |
| `VERTGUARD_AUTH_SECRET_PREVIOUS` | `previous` | Optional. Post-rollover: drain window for old tokens |

The verifier emits `vertguard_jwt_secret_used_total{slot}` so operators
can observe which slot is validating live traffic.

#### Zero-downtime rotation flow

1. Operator sets `VERTGUARD_AUTH_SECRET_NEXT=<new>` and re-deploys. The
   verifier now accepts tokens signed with either the primary or the
   next secret. Startup logs include
   `JWT verifier accepting 2 secrets (rotation in progress)` with
   `slots:[primary,next]`.
2. Verify `vertguard_jwt_secret_used_total{slot="next"}` stays at zero
   while the issuer is still on the old secret — confirms the next slot
   is wired but unused.
3. Switch the **issuer** (the system that mints tokens — IRFlow, Citadel,
   or whoever owns JWT issuance) to sign with the new secret. The
   `slot="next"` counter starts climbing as new tokens land.
4. Wait `VERTGUARD_AUTH_TOKEN_TTL` (default 8h) for every primary-signed
   token to age out. Confirm `slot="primary"` has flat-lined.
5. Promote: set `VERTGUARD_AUTH_SECRET=<new>` and clear
   `VERTGUARD_AUTH_SECRET_NEXT`. Re-deploy. Verifier returns to single
   secret.
6. (Optional) For an extra-cautious drain window — clients caching the
   old token, long-lived sessions outside the TTL contract — set
   `VERTGUARD_AUTH_SECRET_PREVIOUS=<old>` for one deploy cycle, then
   clear it.

The verifier matches secrets in priority order with constant-time HMAC
comparison; first match wins. Other claim checks (issuer, exp, role)
run once after a successful HMAC match.

#### Sealed-secrets

```bash
# Mint new values, regenerate secret.yaml as in step 3 above.
kubeseal --cert pub-cert.pem --format yaml \
  < secret.yaml > sealed-secret.yaml
git commit sealed-secret.yaml -m "rotate vertguard secrets $(date +%F)"
git push   # ArgoCD/Flux applies; controller updates the Secret in-place

# Force pod restart so env vars re-read:
kubectl -n vertguard rollout restart deployment vertguard
```

#### Vault + ESO

```bash
vault kv put vertguard/prod \
  auth-secret="$(openssl rand -hex 32)" \
  db-password="<existing>" \
  citadel-hmac-secret="<existing>" \
  threatflow-webhook-secret="<existing>"
# ESO refreshes within refreshInterval; force immediate sync:
kubectl -n vertguard annotate externalsecret vertguard-secrets \
  force-sync=$(date +%s) --overwrite
kubectl -n vertguard rollout restart deployment vertguard
```

#### JWT grace window (manual fallback)

If you cannot use dual-secret rotation (e.g. the issuer cannot stage two
secrets), fall back to drain-and-rotate:

1. Announce the rotation; freeze new long-lived tokens.
2. Wait `auth.token_ttl` (default 8h) for short-lived sessions to expire.
3. Rotate the secret per pattern above.
4. Communicate to users: re-authenticate.

Prefer the dual-secret flow above; this manual procedure invalidates
every in-flight token at step 3.

### Audit checklist

Before flipping production:

- [ ] No plaintext credentials in any tracked git file. Run
      `git grep -E '(auth_?secret|db_?password|hmac_?secret|webhook_?secret)\s*[:=]\s*[^"\s]'`.
- [ ] `RoleBinding` restricts `get/list secrets` in the `vertguard`
      namespace to the controller SA and break-glass admins only.
- [ ] Sealed-secrets controller (or ESO controller) emits metrics scraped
      by Prometheus; an alert fires on reconcile failure.
- [ ] Alert on `Secret` deletion / mutation in the `vertguard` namespace
      (Kubernetes audit log → SIEM).
- [ ] `existingSecret` is set in the values file; `secret.create` is
      `false`.
- [ ] Pod env vars verified via
      `kubectl exec ... -- printenv | grep VERTGUARD_AUTH_SECRET`
      (value should be non-empty; do not log it).
- [ ] Backup of the sealing key (sealed-secrets) or the Vault unseal
      shards is escrowed offline (HSM, M-of-N split, paper backup).

### Disaster recovery

#### Sealed-secrets — sealing key lost

The controller keeps its private key in the
`sealed-secrets-key*` Secret(s) in `kube-system`. If lost (cluster wipe,
namespace deletion without backup), every `SealedSecret` in git becomes
undecryptable.

Recovery:

1. Reinstall the controller; it generates a new keypair.
2. Re-run kubeseal against every `SealedSecret` with the new pubkey.
3. Reseed every secret value (the old plaintexts are not recoverable from
   the encrypted YAML).

> **Without the sealing key, every operator credential must be re-issued.**
> Plan for offline escrow of the controller's private Secret.

#### Vault — unseal keys lost

A sealed Vault is unrecoverable without the unseal shards (or recovery
keys for auto-unseal). Re-init produces a new Vault with empty KV mounts.

Recovery:

1. Re-initialise Vault; safeguard the new shards immediately.
2. Re-create mounts, policies, auth roles per Pattern B step 1–2.
3. Reseed `vertguard/prod` with freshly generated secrets.
4. ESO re-syncs; restart pods.

> **Without the unseal keys, every operator credential must be re-issued.**

Reference: <https://developer.hashicorp.com/vault/docs/concepts/seal>.
