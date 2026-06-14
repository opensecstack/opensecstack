## VertGuard ML Training Guide

Audience: ML engineer joining the team and shipping the v1 prompt-injection
classifier (and, by reuse, the phishing classifier). Covers data,
training, evaluation gates, ONNX conversion, and deployment via the
[model registry](ml-model-registry.md).

Cross-references: [`ml-architecture.md`](ml-architecture.md),
[`ml-model-registry.md`](ml-model-registry.md),
[`operator-runbook.md`](operator-runbook.md) §3.10,
[`deployment-helm.md`](deployment-helm.md),
[`internal/prompt/corpus/TUNING.md`](../internal/prompt/corpus/TUNING.md).

## Prerequisites

- Python **3.11** (the gRPC service pins this; train on the same minor).
- A GPU is **recommended** (A100/H100 ideal; T4/A10 acceptable). CPU-only
  works for smoke tests up to `--max-steps 100`.
- Python extras `[ml,training]` from `python/pyproject.toml`:
  ```bash
  cd vertguard/python
  pip install -e ".[ml,training]"
  ```
- Optional: `wandb` or `mlflow` for run tracking — set `WANDB_API_KEY`
  or `MLFLOW_TRACKING_URI` before `train.py`.

## Quickstart

```bash
git clone https://github.com/opensecstack/opensecstack.git
cd opensecstack/vertguard/python

pip install -e ".[ml,training]"

# 5-step smoke test on CPU. Verifies the pipeline end-to-end without
# waiting for a real run; no model artefact worth keeping.
python -m training.train \
    --config training/configs/distilbert_prompt.yaml \
    --max-steps 5 \
    --cpu \
    --output-dir /tmp/vg-smoke
```

If the smoke test exits 0 with a `model.safetensors` and a
`model_card.yaml` written, the toolchain is good.

**Full GPU run (recommended).** A ready Colab notebook lives at
`python/training/notebooks/train_distilbert_colab.ipynb`. Open it in
Colab with a T4/L4/A100 runtime; it clones the repo, verifies the
corpus SHA-256, runs the full 3-epoch fine-tune (~10-15 min on T4),
sanity-checks inference, and packages the artefacts as a downloadable
zip ready to drop into `/var/lib/vertguard/models/distilbert-prompt/`.

## Dataset

Current state, as of the gap analysis in
[`internal/prompt/corpus/TUNING.md`](../internal/prompt/corpus/TUNING.md):

| Property              | Value                                            |
|-----------------------|--------------------------------------------------|
| File                  | `internal/prompt/corpus/corpus.jsonl`            |
| Samples               | 100 (35 BLOCKED, 25 SUSPICIOUS, 40 CLEAN)        |
| Languages             | English (primary), some Albanian                 |
| Failure modes covered | Canonical OWASP LLM01/06 phrasings               |
| Gaps                  | Paraphrase, indirect, base64-encoded, multi-step |

Expansion plan (tracked under VG-007/VG-008):

1. **Back-translation augmentation** — round-trip BLOCKED samples
   through 3+ pivot languages with a translation model; keep only
   pairs that diverge ≥ 0.3 cosine in embedding space from the source.
2. **Community contributions** — opt-in upload from VertGuard
   deployments via CITADEL. Submitter-side hashing prevents raw text
   leaking; only confirmed BLOCKED samples (with reviewer sign-off)
   merge.
3. **Adversarial red-team** — monthly batch from the security team:
   paraphrase, encoding, and indirect attacks targeting the current
   model's failure clusters. Owner: ML team.

## Training

```bash
python training/train.py \
    --config       training/configs/distilbert-base.yaml \
    --train-data   internal/prompt/corpus/corpus.jsonl \
    --eval-data    internal/prompt/corpus/eval.jsonl \
    --output-dir   artifacts/distilbert-prompt-v1 \
    --seed         42 \
    --report-to    wandb
```

Expected wall-clock on a single A100 (40 GB): **~25 min** for the v1
config (3 epochs, effective batch 64, fp16, max_steps unset). T4: ~3 h.

Hyperparameters that matter (defined in `configs/distilbert-base.yaml`):

| Knob                     | Default | Why this default                                |
|--------------------------|---------|-------------------------------------------------|
| base model               | `distilbert-base-multilingual-cased` | Albanian ↔ English mix     |
| learning rate            | 2e-5    | Standard transformers fine-tune lr              |
| batch size               | 32      | Fits A100 fp16; halve for T4                    |
| epochs                   | 3       | Corpus is small; more = overfit                 |
| weight decay             | 0.01    | Regularises against the small corpus            |
| warmup steps             | 50      | Stabilises tiny-corpus runs                     |
| label smoothing          | 0.05    | Soft-labels SUSPICIOUS class                    |
| max sequence length      | 256     | 99th percentile of corpus inputs                |
| early-stop patience      | 2       | On macro-F1 plateau                             |
| seed                     | 42      | Reproducibility — see Reproducibility section   |

Validation metrics to watch live:

- `val/macro_f1` — primary gate.
- `val/blocked_recall` — secondary gate (must hit 0.90).
- `val/blocked_precision` — paired secondary (must hit 0.95).
- `val/loss` — divergence between train and val signals overfit.
- `val/confusion_matrix` — confirm no class collapse.

## Evaluation

```bash
python training/eval.py \
    --model-dir   artifacts/distilbert-prompt-v1 \
    --eval-data   internal/prompt/corpus/eval.jsonl \
    --report-out  artifacts/distilbert-prompt-v1/eval_report.json
```

The report prints per-class precision/recall/F1, the confusion matrix,
and a list of misclassified samples (capped at 50).

**Ship gates** — must all pass:

| Metric              | Target | Why                                             |
|---------------------|--------|-------------------------------------------------|
| `macro_f1`          | ≥ 0.80 | Lifts off the regex baseline (0.30)             |
| `blocked_recall`    | ≥ 0.90 | We must catch attacks                           |
| `blocked_precision` | ≥ 0.95 | False BLOCKED is a user-visible outage         |

These thresholds match the targets cited in
[`internal/prompt/corpus/TUNING.md`](../internal/prompt/corpus/TUNING.md)
§ "Phase 4.2 plan".

## ONNX conversion

```bash
python training/convert.py \
    --model-dir   artifacts/distilbert-prompt-v1 \
    --output      artifacts/distilbert-prompt-v1/model.onnx \
    --opset       17 \
    --verify
```

The `--verify` flag re-runs the eval set through the ONNX model and
asserts identical predictions vs the PyTorch reference (allow ε for
fp16). Failure here means do not ship.

## Deployment

1. Push the artefact bundle to the configured registry path (see
   [`ml-model-registry.md`](ml-model-registry.md) for the canonical
   layout):
   ```
   models/distilbert-prompt-injection/v1.0.0/
       model.onnx
       tokenizer.json
       tokenizer_config.json
       model_card.yaml
   ```
2. Update the running service:
   ```bash
   helm upgrade vertguard ./deploy/helm/vertguard \
     -n vertguard \
     -f values.production.yaml \
     --set ml.enabled=true \
     --set ml.config.backend=onnx \
     --set ml.config.registry_url=s3://vg-models/distilbert-prompt-injection/v1.0.0
   ```
3. Watch the canary in
   [`operator-runbook.md`](operator-runbook.md) §3.10. Rollback:
   `helm rollback vertguard <REV>`.

## Reproducibility

Every model artefact records three identifiers in its model card:

- **Seed** — RNG seed for Python, NumPy, PyTorch, and Transformers.
- **Dataset hash** — SHA-256 over the JSONL bytes (sorted by `id`).
- **Code version** — git commit of the `vertguard` repo at train time.

`train.py` writes all three into `model_card.yaml`. Rebuilding from
`(seed, dataset_hash, code_version)` MUST yield bit-identical weights
on identical hardware. Different GPU generations may diverge in the
last layer of the embedding matrix; record the GPU model alongside.

## Model card template

```yaml
# artefacts/<model>/<version>/model_card.yaml
model:
  name: distilbert-prompt-injection
  version: v1.0.0
  base: distilbert-base-multilingual-cased
training:
  seed: 42
  dataset_hash: sha256:...
  code_version: git:abcdef1
  hardware: NVIDIA A100-SXM4-40GB
  framework: torch==2.2.1+cu121, transformers==4.40.0
  duration_seconds: 1500
  hyperparameters:
    learning_rate: 2.0e-5
    batch_size: 32
    epochs: 3
    weight_decay: 0.01
eval:
  macro_f1: 0.83
  blocked_precision: 0.96
  blocked_recall: 0.92
  clean_precision: 0.88
  clean_recall: 0.81
  suspicious_f1: 0.71
  confusion_matrix: [[...]]
deployment:
  backend: onnx
  opset: 17
  fp16: false
  expected_p95_ms_cpu: 50
  expected_p95_ms_gpu: 10
```

These fields are referenced verbatim by the architecture doc's
"Observability" section (see
[`ml-architecture.md`](ml-architecture.md)) — adding a field here means
adding a corresponding metric there.

## Adversarial / red-team cadence

| Item       | Detail                                                              |
|------------|---------------------------------------------------------------------|
| Frequency  | Monthly                                                             |
| Owner      | ML team (lead) + Security team (paraphrase generation)              |
| Inputs     | (a) Last month's audit_events tagged `false_negative_suspected`     |
|            | (b) New paraphrase batch (target: 200 samples, balanced)            |
|            | (c) New encoding tricks (base64, rot13, unicode-confusable, …)      |
| Process    | Eval current production model on the new corpus; if any ship gate   |
|            | regresses by > 2 pp, file VG-XXXX and trigger re-train.             |
| Output     | Updated `eval_report.json` attached to the model card.              |
| Escalation | Two consecutive monthly regressions ⇒ promote to a Sev-2 incident.  |
