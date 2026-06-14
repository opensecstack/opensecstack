## VertGuard ML Model Registry

Audience: SRE / platform team running the model registry that fronts
VertGuard's ML inference service. The registry is **Phase 4.2.1**;
this document is the design backstop and the prerequisite for the
controlled DistilBERT v1 rollout described in
[`ml-training-guide.md`](ml-training-guide.md).

Cross-references: [`ml-architecture.md`](ml-architecture.md),
[`ml-training-guide.md`](ml-training-guide.md),
[`secrets-management.md`](secrets-management.md),
[`deployment-helm.md`](deployment-helm.md),
[`operator-runbook.md`](operator-runbook.md) §3.10.

## Why

A model file on a PVC is acceptable for one cluster running one model.
It does not survive contact with three real requirements:

1. **Version pinning.** Operators need to ask "what is serving right
   now" and get a deterministic answer (semver + content hash). The
   `ModelInfo` RPC already returns these fields; the registry is what
   produces them honestly.
2. **Audit trail.** "Who promoted this?" is a NIS2 / AI Act question.
   Object-store object versions plus a signed promotion log answer it.
3. **Rollback.** Reverting a bad model must be O(seconds) and not
   require redeploying the chart.
4. **Multi-tenant.** Phase 4.3 wants per-tenant model selection; the
   registry is the namespace where that choice is expressed.

## Storage

S3-compatible object store (production: AWS S3, Cloud Storage, MinIO on
prem). Bucket-level versioning **must** be on so that a re-upload to the
same key cannot quietly replace history.

Layout — content-addressable per artefact, semver-keyed per release:

```
s3://vg-models/
  models/
    <model-name>/
      <version>/                       e.g. distilbert-prompt-injection/v1.0.0/
        model.onnx                     primary weights
        tokenizer.json                 transformers tokenizer
        tokenizer_config.json
        model_card.yaml                see ml-training-guide.md template
        SHA256SUMS                     line-per-file, signed (cosign / sigstore)
        SHA256SUMS.sig
      latest.txt                       single-line: vX.Y.Z (the active prod version)
      staging.txt                      single-line: vX.Y.Z (the canary candidate)
```

Why content-addressable + semver: the semver is what humans roll back to;
the content hash is what the loader verifies on every pull. The two
together prevent a "v1.0.0 was retagged" attack vector.

Credentials live in a Kubernetes Secret managed via the patterns
documented in [`secrets-management.md`](secrets-management.md):
`registry-access-key`, `registry-secret-key`. The Helm subchart accepts
either `secret.create=true` (dev) or `secret.existingSecret` (prod via
SealedSecrets / ESO / Vault).

## Loading

The Python ML service polls the registry on startup, then on a configurable
interval (`VERTGUARD_ML_REGISTRY_POLL`, default 5 min):

1. GET `<registry>/models/<name>/latest.txt` → version string.
2. If unchanged from the in-memory active model: no-op.
3. Else: download `<version>/` into a scratch dir, verify `SHA256SUMS`
   against `SHA256SUMS.sig`, refuse to swap if signature fails.
4. Load the new model into a side slot, run a 5-sample warm-up batch
   (golden inputs from the model card), only then atomic-swap the
   active pointer.
5. Old slot is unloaded after the in-flight requests drain.

**Fallback to last-known-good.** If the registry is unreachable at
startup, the service serves the previously-cached model from local disk
(`<config.models_path>/cache/`) and emits
`vertguard_ml_registry_unreachable_total` with a non-fatal status. A
fresh pod with no cache fails closed — readiness probe stays 503 until
the registry returns.

## Promotion flow

Stages and gates:

```
   [ artefact uploaded ]
            │
            ▼
   ┌──────────────┐  staging.txt = vX.Y.Z
   │   STAGING    │
   └──────────────┘
            │  manual approval  +  staging eval ≥ ship gates
            ▼
   ┌──────────────┐  canary 5%  (5% of pods serve vX.Y.Z, 95% serve previous)
   │   CANARY 5   │   gate: macro_f1 in production traffic ≥ ML target,
   └──────────────┘         no FP-rate regression > 2 pp over 6 h
            │
            ▼
   ┌──────────────┐  canary 50%
   │   CANARY 50  │   gate: same metrics, 24 h
   └──────────────┘
            │
            ▼
   ┌──────────────┐  latest.txt = vX.Y.Z
   │   PRODUCTION │
   └──────────────┘
```

Production traffic gates use the same metrics defined in
[`ml-architecture.md`](ml-architecture.md) §Observability.

**Rollback.** Edit `latest.txt` back to the previous version; the next
poll cycle reloads the previous artefact (already in disk cache). No
chart redeploy. Time-to-rollback target: ≤ 2 minutes including the warm-up.

## Approval

Promotion is gated on a four-eyes principle:

- ML engineer signs off the staging eval report (`eval_report.json`).
- SRE on-call signs off the canary metric snapshot at each gate.

The promoter identity is recorded in a tamper-evident promotion log
(WORM) — the same CITADEL log VertGuard uses for audit_events when
configured. ADR-0XX (placeholder until issued) ratifies the flow and
names the approver pool.

## Phase 4.2.1 timeline

| Milestone                                              | Target          |
|--------------------------------------------------------|-----------------|
| Registry stood up (MinIO in lab; S3 in prod)           | Phase 4.2.1 W1  |
| First DistilBERT v1 in staging                         | Phase 4.2.1 W2  |
| Canary 5% in prod                                      | Phase 4.2.1 W3  |
| Canary 50% / 100%                                      | Phase 4.2.1 W4  |
| Sign off Phase 4.2.1, open Phase 4.2.2 (explainability) | Phase 4.2.1 W5 |

Until W1 lands, operators run with the PVC-mounted weights workflow in
[`ml-training-guide.md`](ml-training-guide.md) §Deployment.
