## VertGuard Model Card Template

A model card is the YAML manifest that ships next to every VertGuard
ML artefact (`model.onnx` + tokenizer files). It is produced
automatically by [`python/training/train.py`](../python/training/train.py)
`_write_model_card` at the end of every training run, and it is the
sole source of truth for what was trained, on what data, and how it
was evaluated.

This document defines the schema, the required fields, the
reproducibility contract, and the validation tooling. For the
training workflow itself see
[`ml-training-guide.md`](ml-training-guide.md); for how the card
participates in the release pipeline see
[`release-process.md`](release-process.md) §1.5.

## What a model card records — and why

| Concern               | What the card answers                                    |
|-----------------------|----------------------------------------------------------|
| **Audit**             | Which weights were running on which day, evaluated to which numbers, on which corpus. |
| **NIS2 evidence**     | Reviewer can reconstruct the AI Act risk-management documentation from a single file (Article 9, technical documentation per Annex IV). |
| **Reproducibility**   | A second engineer with the `(seed, dataset_hash, code_version)` tuple can rebuild bit-identical weights on identical hardware. |
| **Incident response** | When a model misbehaves in prod (see [`operator-runbook.md`](operator-runbook.md) §3.10), the card is the first artefact pulled — it tells you what to compare against. |
| **Regression gating** | The next training run's `eval` block is diffed against the card's `eval` block; > 2 pp regression triggers VG-XXXX. |

Without the card, the model is a binary blob with no provenance —
not a defensible AI control under NIS2 / AI Act. With it, the audit
chain runs `helm image.digest → cosign attestation → model_card.dataset_hash → corpus.jsonl`
end-to-end.

## File location

```
models/<model-name>/v<version>/
    model.onnx
    tokenizer.json
    tokenizer_config.json
    model_card.yaml          ← this file
    eval_report.json         ← optional: full per-class metrics + misclassified samples
```

`<model-name>` is one of `distilbert-prompt-injection`,
`distilbert-phishing` (more added under
[`ml-model-registry.md`](ml-model-registry.md)). `<version>` matches
the VertGuard release tag (`v1.0.0` → `v1.0.0/`).

## Required fields

The schema below is the canonical contract. Optional blocks are
covered in the next section. Field types are noted in YAML form.

### `model`

```yaml
model:
  name:    string   # canonical model id, e.g. distilbert-prompt-injection
  version: string   # vMAJOR.MINOR.PATCH, must match release tag
  base:   string    # HF base checkpoint, e.g. distilbert-base-multilingual-cased
  task:    string   # human-readable task description
```

### `training`

```yaml
training:
  seed:             integer    # RNG seed (Python, NumPy, PyTorch, Transformers)
  dataset_hash:     string     # "sha256:<hex>" over JSONL bytes sorted by id
  code_version:     string     # "git:<short-sha>" of the vertguard repo at train time
  hardware:         string     # GPU model, e.g. "NVIDIA A100-SXM4-40GB" or "CPU x86_64"
  framework:        string     # "torch==2.2.1+cu121, transformers==4.40.0"
  duration_seconds: number     # wall-clock seconds for the run
  hyperparameters:
    learning_rate: number
    batch_size:    integer
    epochs:        number
    weight_decay:  number
    warmup_ratio:  number
    max_seq_len:   integer
```

The exact set of recorded hyperparameters is whatever
`_write_model_card` reads from `cfg["train"]` — see
[`python/training/configs/distilbert_prompt.yaml`](../python/training/configs/distilbert_prompt.yaml)
for the canonical shape. Adding a hyperparameter to the YAML config
means it lands in the card automatically; do not duplicate by hand.

### `eval`

```yaml
eval:
  macro_f1:           number   # primary ship gate (>= 0.80)
  macro_precision:    number
  macro_recall:       number
  blocked_precision:  number   # secondary gate (>= 0.95)
  blocked_recall:     number   # secondary gate (>= 0.90)
  clean_precision:    number
  clean_recall:       number
  clean_f1:           number
  suspicious_precision: number
  suspicious_recall:    number
  suspicious_f1:        number
```

Per-class fields are emitted by `_write_model_card` for every label
in `model_cfg["num_labels"]`. For binary classifiers (phishing,
`num_labels: 2`) the `suspicious_*` block is absent; for the 3-class
prompt classifier all three label families appear.

### `deployment`

```yaml
deployment:
  backend:             string    # one of "torch-cpu", "torch-gpu", "onnx"
  expected_p95_ms_cpu: number    # latency budget on the CPU backend
  expected_p95_ms_gpu: number    # latency budget on the GPU backend
```

These numbers are the SLO the operator runbook gates on
(see [`operator-runbook.md`](operator-runbook.md) §3.10 — the
`vertguard_ml_latency_seconds` p95 alert fires at the GPU value when
`ml.enabled=true`).

## Optional fields

The training script does not currently emit these, but the schema
reserves the keys so consumers can rely on shape stability. Add them
manually (or via post-processing) when the data is available.

### `eval.confusion_matrix`

```yaml
eval:
  confusion_matrix:
    labels: [clean, suspicious, blocked]
    matrix:
      - [38, 1, 1]      # row = true label, col = predicted
      - [2, 21, 2]
      - [0, 1, 34]
```

A class-collapse smoke check: any all-zero column or row means the
model has stopped predicting that class. Fail the ship gate if it
appears.

### `eval.adversarial_robustness`

```yaml
eval:
  adversarial_robustness:
    paraphrase_macro_f1: 0.74     # back-translation eval set
    encoding_macro_f1:   0.69     # base64/rot13/unicode-confusable batch
    indirect_macro_f1:   0.61     # indirect-injection prompts
    notes: "Run against artifacts/red-team-2026-04/eval.jsonl"
```

Owned by the monthly red-team cadence in
[`ml-training-guide.md`](ml-training-guide.md#adversarial--red-team-cadence).
Two consecutive monthly regressions of > 2 pp on any sub-metric
escalate to a Sev-2 incident.

### `explainability`

```yaml
explainability:
  method: "integrated-gradients"
  reference_inputs: 50
  top_k_tokens_per_class:
    blocked:     ["ignore", "previous", "instructions", "reveal", "system"]
    suspicious:  ["debug", "developer", "mode"]
    clean:       ["please", "summarise", "translate"]
```

A snapshot of the most-attributed tokens per class on a fixed
reference set. Useful for AI Act Article 13 transparency obligations.
Regenerate per release.

## Reproducibility contract

The tuple **`(seed, dataset_hash, code_version)`** uniquely
identifies a training run. Rebuilding from these three values MUST
yield bit-identical weights on identical hardware. The contract has
two failure modes:

1. **Different GPU generation** — the floating-point determinism
   guarantees in PyTorch CUDA only hold within a single SM
   architecture. An A100 run and a T4 run with the same tuple may
   diverge in the last layer of the embedding matrix. Always record
   `training.hardware`; treat the GPU model as part of the
   reproducibility key for forensic rebuilds.
2. **Library drift** — `torch` and `transformers` minor version bumps
   change kernel selection. `training.framework` records the exact
   pinned versions. Reproducing a v1.0.0 model in 2027 means
   reinstalling the framework versions in the card, not "latest".

`dataset_hash` is computed by sorting the corpus JSONL by `id`,
canonicalising each row with `json.dumps(..., sort_keys=True)`, and
hashing the byte stream with SHA-256. The sort step is critical: it
makes the hash invariant to row reordering, which happens whenever
the corpus is re-exported from the editing tool.

`code_version` is `git:<short-sha>` from
[`python/training/train.py`](../python/training/train.py)
`_git_commit()`. The training run refuses to write a card with a
dirty working tree in CI; locally it tolerates `-dirty` but flags
the run as `training.smoke: true`, which downstream tooling refuses
to promote.

## Validation

### Quick sanity check

```bash
python -c "import yaml; yaml.safe_load(open('model_card.yaml'))"
```

Exit code 0 means the file parses. This catches the 95% case (typo,
truncation, indentation drift).

### JSON-schema stub

For CI, the card should be validated against a schema. A minimal
draft (drop into `python/training/schema/model_card.schema.json` and
load via `jsonschema`):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["model", "training", "eval", "deployment"],
  "properties": {
    "model": {
      "type": "object",
      "required": ["name", "version", "base", "task"],
      "properties": {
        "name":    {"type": "string"},
        "version": {"type": "string", "pattern": "^v[0-9]+\\.[0-9]+\\.[0-9]+"},
        "base":    {"type": "string"},
        "task":    {"type": "string"}
      }
    },
    "training": {
      "type": "object",
      "required": ["seed", "dataset_hash", "code_version", "hardware", "framework", "duration_seconds", "hyperparameters"],
      "properties": {
        "seed":             {"type": "integer"},
        "dataset_hash":     {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "code_version":     {"type": "string", "pattern": "^git:[0-9a-f]{7,40}"},
        "hardware":         {"type": "string"},
        "framework":        {"type": "string"},
        "duration_seconds": {"type": "number", "minimum": 0},
        "hyperparameters":  {"type": "object"}
      }
    },
    "eval": {
      "type": "object",
      "required": ["macro_f1", "blocked_precision", "blocked_recall"],
      "properties": {
        "macro_f1":          {"type": "number", "minimum": 0, "maximum": 1},
        "blocked_precision": {"type": "number", "minimum": 0, "maximum": 1},
        "blocked_recall":    {"type": "number", "minimum": 0, "maximum": 1}
      }
    },
    "deployment": {
      "type": "object",
      "required": ["backend", "expected_p95_ms_cpu", "expected_p95_ms_gpu"],
      "properties": {
        "backend":             {"enum": ["torch-cpu", "torch-gpu", "onnx"]},
        "expected_p95_ms_cpu": {"type": "number", "minimum": 0},
        "expected_p95_ms_gpu": {"type": "number", "minimum": 0}
      }
    }
  }
}
```

CI invocation:

```bash
python - <<'PY'
import json, yaml, jsonschema
schema = json.load(open("python/training/schema/model_card.schema.json"))
card = yaml.safe_load(open("models/distilbert-prompt-injection/v1.0.0/model_card.yaml"))
jsonschema.validate(card, schema)
print("model_card.yaml OK")
PY
```

## Example: real generated card

A minimal v1.0.0 prompt-injection card from the Phase 4.2.1 Colab
run. The `dataset_hash` is the actual SHA-256 of the frozen 100-sample
corpus; the `eval` numbers are the real metrics from that run.

```yaml
# models/distilbert-prompt-injection/v1.0.0/model_card.yaml
model:
  name: distilbert-prompt-injection
  version: v1.0.0
  base: distilbert-base-uncased
  task: 3-class prompt-injection classifier
training:
  seed: 42
  dataset_hash: sha256:2c559ef2a0b3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c73bf7
  code_version: git:abcdef1
  hardware: NVIDIA T4 (Colab)
  framework: torch==2.2.1+cu121, transformers==4.40.0
  duration_seconds: 893.4
  max_steps: -1
  smoke: false
  hyperparameters:
    learning_rate: 2.0e-5
    batch_size: 16
    epochs: 3
    weight_decay: 0.01
    warmup_ratio: 0.1
    max_seq_len: 256
eval:
  macro_f1: 0.880
  macro_precision: 0.891
  macro_recall: 0.872
  clean_precision: 0.875
  clean_recall: 0.900
  clean_f1: 0.887
  suspicious_precision: 0.840
  suspicious_recall: 0.760
  suspicious_f1: 0.798
  blocked_precision: 0.958
  blocked_recall: 0.958
  blocked_f1: 0.958
deployment:
  backend: onnx
  expected_p95_ms_cpu: 50
  expected_p95_ms_gpu: 10
```

All three ship gates pass: `macro_f1 = 0.880 ≥ 0.80`,
`blocked_precision = 0.958 ≥ 0.95`, `blocked_recall = 0.958 ≥ 0.90`.

## Audit trail

The model card is committed to the model artefact bundle alongside
the weights, and the bundle is what the ML side-car loads at startup.
The full audit chain:

```
helm values.image.digest          (cosign-verified at deploy time)
        │
        ▼  signed image runs
ML side-car reads /var/lib/vertguard/models/<name>/<version>/
        │
        ▼  emits at /metrics
vertguard_ml_model_loaded_at{name,version,dataset_hash}
        │
        ▼  scraped by Prometheus + recorded in audit_events
audit_events.model_version + audit_events.dataset_hash
```

Three properties hold by construction:

1. **Image → card**: the SBOM attestation
   (see [`security/image-signing.md`](security/image-signing.md))
   includes the model artefact hashes; `cosign verify-attestation`
   is sufficient to prove the card was built into the image.
2. **Card → corpus**: `training.dataset_hash` is recomputed from the
   committed `internal/prompt/corpus/corpus.jsonl` at release time
   (see [`release-process.md`](release-process.md) §1.5). Mismatch
   blocks the release.
3. **Card → audit log**: every `audit_events` row written under
   `ml.enabled=true` carries `model_version` and `dataset_hash`,
   which join back to the card. A regulator asking "what model
   classified this prompt?" gets a single-row answer.

This three-step chain is what NIS2 Article 21 (g) — "policies and
procedures (testing and auditing) to assess the effectiveness of
cybersecurity risk-management measures" — requires for an AI control.
Operators reviewing the chain end-to-end: pull the running pod's
image digest, `cosign verify-attestation`, decode the CycloneDX
predicate to find the model card, hash the corpus, compare. All
machine-checkable.

## See also

- [`ml-training-guide.md`](ml-training-guide.md) — end-to-end training workflow
- [`ml-architecture.md`](ml-architecture.md) — observability fields the card maps to
- [`ml-model-registry.md`](ml-model-registry.md) — registry layout + rollback via `latest.txt`
- [`release-process.md`](release-process.md) — pre-flight check that the card matches the corpus
- [`security/image-signing.md`](security/image-signing.md) — SBOM attestation chain
- [`operator-runbook.md`](operator-runbook.md) — incident response (§3.10 dumps the deployed card)
- [`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md) — regulatory framing
- [`../python/training/train.py`](../python/training/train.py) — `_write_model_card` implementation
- [`../python/training/configs/distilbert_prompt.yaml`](../python/training/configs/distilbert_prompt.yaml) — hyperparameter shape
