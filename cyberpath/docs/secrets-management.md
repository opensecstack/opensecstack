# CyberPath Secrets Management

CyberPath reads every sensitive value from environment variables
sourced from a Kubernetes Secret (or equivalent in non-k8s
deployments). The handling pattern matches VertGuard's — see
`vertguard/docs/secrets-management.md` for the canonical reference;
this document captures only the CyberPath-specific catalogue,
rotation policy, bootstrap, and recovery procedures.

---

## Sensitive fields catalogue

| Env var | Secret key | Purpose | Blast radius if leaked | Rotation |
|---|---|---|---|---|
| `CYBERPATH_AUTH_SECRET` | `auth-secret` | HS256 JWT signing key | Forge any user/operator/auditor token; full API takeover | **90 days** |
| `CYBERPATH_AUTH_PEPPER` | `auth-pepper` | Server-side Argon2id pepper (HMAC-SHA256 of plaintext before hashing) | Offline cracking of leaked password hashes becomes feasible | **180 days** |
| `CYBERPATH_DB_PASSWORD` | `db-password` | Postgres runtime user password | Read/write all completions, audit_events, content versions | 180 days |
| `CYBERPATH_CITADEL_KEY_SECRET` | `citadel-hmac-secret` | HMAC signature for outbound CITADEL `cyberpath.completion` events | Forge CITADEL ledger entries upstream — **chain split risk** | only-on-incident |
| `CYBERPATH_IRFLOW_KEY_SECRET` | `irflow-webhook-secret` | Verifies inbound IRFlow webhook signatures (incident → track) | Inject false training-recommendation triggers | 90 days |
| `CYBERPATH_CONTENT_REGISTRY_TOKEN` | `content-registry-token` | OCI registry write token for publishing lab images | Push tampered lab images (caught by cosign on pull) | annual |
| `CYBERPATH_CERT_SIGNING_KEY_REF` | `cert-signing-key-ref` | KMS reference to the Ed25519 certification signing key | Forge per-track certificates | only-on-incident |
| `CYBERPATH_COSIGN_PUB` | `cosign-pub-key` | **Public** key used to verify lab image signatures | None directly; pinning prevents key-substitution attacks | annual (with key root) |

`auth-secret` and `citadel-hmac-secret` are the highest-impact
values. `cert-signing-key-ref` is special: the key itself lives in
HSM/KMS in production — only the *reference* (a key id like
`projects/foo/locations/.../keyRings/cyberpath/cryptoKeys/cert-signer`)
sits in the env var.

`cosign-pub-key` is technically not a secret (it's a public key)
but it is **pinned** alongside the secrets so that a deployment
cannot silently switch trust roots. Treat it operationally as a
secret for change-control.

---

## Storage

Three deployment patterns, one per environment:

| Environment | Pattern |
|---|---|
| Production (k8s) | **Sealed Secrets (Bitnami)** — see VertGuard's secrets-management for full setup. CyberPath consumes the same controller. |
| Production (CITADEL signer) | **HSM/KMS** for the Ed25519 certification signing key. v1.0.0 supports GCP Cloud KMS, AWS KMS, and HashiCorp Vault Transit. |
| Staging (k8s) | Sealed Secrets, separate sealing-key per cluster |
| Local dev (docker-compose) | `.env` file (gitignored) |
| CI | Repository secrets, scoped to the workflow |

The Helm chart exposes `existingSecret: <name>` so production never
materialises plaintext into the release object. **Never** use
`secret.create=true` in production.

---

## Rotation policy

| Secret | Cadence | Procedure |
|---|---|---|
| `auth-secret` (JWT) | 90 days | Three-slot rotation (see below) |
| `db-password` | 180 days | Coordinated with Postgres user rotation |
| `citadel-hmac-secret` | only-on-incident | Coordinated rotation with CITADEL deployer |
| `irflow-webhook-secret` | 90 days | Rotate at IRFlow + CyberPath simultaneously |
| `content-registry-token` | annual | New OCI token; old token revoked at registry |
| `cert-signing-key-ref` | only-on-incident | **Key replacement = chain split.** Requires governance ticket |
| `cosign-pub-key` | annual | Coordinated with the OCI signing key root rotation |

### Three-slot JWT rotation

Mirrors the VertGuard pattern. The verifier accepts up to three
secrets simultaneously, in priority order:

| Env var | Slot | Purpose |
|---|---|---|
| `CYBERPATH_AUTH_SECRET` | `primary` | Active signing secret (always set) |
| `CYBERPATH_AUTH_SECRET_NEXT` | `next` | Pre-rollover: tokens may already be signed with this |
| `CYBERPATH_AUTH_SECRET_PREVIOUS` | `previous` | Post-rollover: drain window for old tokens |

The verifier emits `cyberpath_jwt_secret_used_total{slot}` so
operators can observe which slot is validating live traffic. Full
rollover procedure is identical to VertGuard's — set `next`,
verify zero usage, switch issuer, wait for TTL drain, promote `next`
to `primary`, optionally retain old as `previous` for one cycle.

### Argon2id pepper rotation

The password pepper rotates without forcing user resets via a two-slot
verifier: `CYBERPATH_AUTH_PEPPER` is the active value used for new
hashes and verify-first, and `CYBERPATH_AUTH_PEPPER_PREVIOUS` is the
optional fallback consulted when the active pepper fails to verify.
On a successful previous-pepper verification the login flow silently
re-hashes the password under the active pepper and persists the new
encoded value (best-effort; login still succeeds if the persist
fails). After at least one full login cycle for the active population
(in practice ~90 days; force-reset stragglers at the cutoff) remove
`CYBERPATH_AUTH_PEPPER_PREVIOUS` from configuration. See
`internal/auth/password.go` for the full procedure.

### CITADEL signer rotation (chain split)

The CITADEL HMAC secret authenticates CyberPath as the emitter of
`cyberpath.completion` events. Rotating it without coordination
breaks signature verification on the CITADEL side and orphans
in-flight outbox rows.

Rotation procedure (incident-driven only):

1. Open governance ticket; CITADEL deployer notified.
2. CITADEL accepts both the old and new secret simultaneously
   (CITADEL operator wires the rollover on their side first).
3. CyberPath operator updates `CYBERPATH_CITADEL_KEY_SECRET` to the
   new value; rolling restart.
4. CyberPath emits a `cyberpath.signer.rotated` audit event with
   the old + new key IDs.
5. After the configured drain window (default 24h), CITADEL drops
   the old secret.

The `cyberpath.signer.rotated` event is the chain-split marker —
auditors can see the boundary and verify each side of the split
under its corresponding key.

---

## Bootstrap: generate fresh keys

The `cyberpath-cli` command (lands with v1.0.0) provides:

```bash
# Generate a fresh JWT signing key (32 bytes, hex)
cyberpath-cli secrets generate auth-secret

# Generate a fresh HMAC secret (32 bytes, hex)
cyberpath-cli secrets generate citadel-hmac-secret
cyberpath-cli secrets generate irflow-webhook-secret

# Generate a fresh Ed25519 keypair for cert signing (writes to KMS via configured provider)
cyberpath-cli secrets generate cert-signing-key --kms gcp \
    --keyring cyberpath \
    --key cert-signer-2027a
```

For environments without the CLI, the underlying primitives:

```bash
# 32-byte hex secret for HS256 / HMAC
openssl rand -hex 32

# 32-byte base64 password
openssl rand -base64 24

# Ed25519 keypair (dev only — production keys live in KMS)
openssl genpkey -algorithm Ed25519 -out cert-signer.pem
openssl pkey -in cert-signer.pem -pubout -out cert-signer.pub
```

### Initial bootstrap secret manifest (sealed-secrets pattern)

```bash
kubectl create secret generic cyberpath-secrets \
    --namespace cyberpath \
    --from-literal=auth-secret="$(openssl rand -hex 32)" \
    --from-literal=db-password="$(openssl rand -base64 24)" \
    --from-literal=citadel-hmac-secret="$(openssl rand -hex 32)" \
    --from-literal=irflow-webhook-secret="$(openssl rand -hex 32)" \
    --from-literal=content-registry-token="<from registry CI>" \
    --from-literal=cert-signing-key-ref="<KMS reference>" \
    --from-file=cosign-pub-key=cosign.pub \
    --dry-run=client -o yaml > secret.yaml

kubeseal --cert pub-cert.pem --format yaml \
    < secret.yaml > sealed-secret.yaml
shred -u secret.yaml

git add sealed-secret.yaml
git commit -m "cyberpath: seed sealed secret"
```

---

## Audit

Every secret read is logged via the opensecstack/sdk auth
middleware. The middleware emits a structured log line on each
request; operators correlate `cyberpath_jwt_secret_used_total{slot}`
with audit-event timestamps to spot anomalies.

The `audit_events` table records:

- `secret.read` — when the application reads a secret at startup or
  rotation
- `secret.rotated` — when an operator runs the rotation procedure
- `cert.signed` — when the certification signer key is exercised
- `cyberpath.signer.rotated` — chain-split marker (CITADEL)

Retention: 7 years (NIS2 audit window) — see
[data-model.md](data-model.md).

---

## Recovery

### Lost JWT signing key (`auth-secret`)

**Acceptable failure mode: mass logout.**

Rotate the secret using the three-slot procedure but **without** the
`previous` slot. All in-flight tokens become invalid; learners
re-authenticate. Document the event in the audit trail. There is
no chain-split impact because JWTs are session-scoped and not part
of the audit-evidence chain.

### Lost CITADEL signer (`citadel-hmac-secret`)

**Chain-split scenario; governance ticket required.**

1. Open the governance ticket; halt CyberPath completion submissions
   to CITADEL until the new secret is provisioned.
2. New secret minted on the CITADEL side; CITADEL accepts both old
   (briefly, for in-flight) and new.
3. CyberPath operator updates the secret and emits the
   `cyberpath.signer.rotated` audit event with key IDs.
4. Reconciliation pass re-emits any outbox rows under the new
   secret (their `correlation_id`s dedupe at CITADEL).

Auditors verifying the post-split events use the new key; events
before the split verify under the old. The split is recorded in
both ledgers via the `cyberpath.signer.rotated` event.

### Lost certification signing key (`cert-signing-key-ref`)

**Chain-split scenario; governance ticket required.**

The certification signing key is long-lived (Ed25519 in KMS).
Replacement scenarios:

- **Key compromise.** Issue a `cyberpath.cert.key.revoked` event
  via CITADEL; mint a new keypair; sign all *future* certifications
  under the new key. Past certifications remain valid against the
  old (now-archived) public key. Verifiers must accept both keys
  during a documented transition window.
- **Key loss (no compromise).** Same procedure, minus the
  revocation event.

A documented `cyberpath-cert-keys.yaml` manifest in the deployment
repo lists every signing-key id and its status (`active`,
`archived`, `revoked`); auditors consult this manifest to know
which keys are valid for which time range.

### Lost sealing key (sealed-secrets controller)

Identical to VertGuard — every operator credential must be re-issued.
Plan for offline escrow of the controller's private Secret. See
`vertguard/docs/secrets-management.md` § "Disaster recovery".

---

## Audit checklist

Before flipping production:

- [ ] No plaintext credentials in any tracked git file.
- [ ] `existingSecret` is set in the values file; `secret.create` is
      `false`.
- [ ] `cosign-pub-key` is committed (it's public) but immutable —
      changes require a governance review.
- [ ] `cert-signing-key-ref` points at an HSM/KMS, not a local file.
- [ ] Three-slot JWT rotation is wired (`AUTH_SECRET`,
      `AUTH_SECRET_NEXT`, `AUTH_SECRET_PREVIOUS`) even if only the
      primary slot is populated initially.
- [ ] Sealed-secrets controller emits metrics; alert fires on
      reconcile failure.
- [ ] Backup of the sealing key (or Vault unseal shards) escrowed
      offline.

---

## See also

- VertGuard reference: `vertguard/docs/secrets-management.md` —
  sealed-secrets / Vault+ESO setup details, three-slot JWT pattern,
  audit checklist
- [data-model.md](data-model.md) — `audit_events` retention policy
- [citadel-integration.md](citadel-integration.md) — HMAC signing
  flow + chain-split semantics
- [wasm-sandbox.md](wasm-sandbox.md) — cosign trust root for lab
  images
- [migrations.md](migrations.md) — DB credential rotation
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
