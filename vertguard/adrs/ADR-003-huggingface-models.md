## ADR-003 — HuggingFace DistilBERT variants for text classification

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.2
- Owners: VertGuard core, Security ML
- Related: [`docs/ml-architecture.md`](../docs/ml-architecture.md),
  [`docs/ml-model-registry.md`](../docs/ml-model-registry.md),
  [`models/models.yaml`](../models/models.yaml),
  [`python/ml_service/`](../python/ml_service/)

## Context

Modules 2 (Phishing) and 3 (Prompt Injection) need pre-trained text
classification models. The Phase 4.1 regex-only scanner achieves
macro-F1 ≈ 0.30 against the labelled corpus. Threshold tuning cannot
improve recall against paraphrase, indirect, and encoded attacks;
an ML classifier is required.

Options evaluated: OpenAI / Anthropic SaaS API, local HuggingFace
models, custom-trained models from scratch, and rules-only with no ML.

## Decision

VertGuard uses **HuggingFace DistilBERT variants** (and
`sentence-transformers/all-MiniLM-L6-v2` for email classification)
loaded locally inside the Python ML service. Models are declared in
`models/models.yaml` with SHA-256 checksums and downloaded at first
startup via `models/download.sh`. A missing or checksum-mismatched
model aborts the Python ML service start.

## Reasons

- **Privacy / data sovereignty.** SaaS APIs (OpenAI, Anthropic,
  Cohere) send raw user input — which may include confidential
  phishing email bodies or injected prompts — to a third party.
  VertGuard's ASNI / NIS2 / AI Act posture prohibits this. See
  ADR-004 for the local-only inference hard requirement.
- **Offline operation.** Deployments in air-gapped networks (ASNI
  tactical environments) must function without internet access.
  Local models satisfy this; SaaS APIs do not.
- **DistilBERT size/accuracy tradeoff.** DistilBERT is 40% smaller
  than BERT-base with 97% of its classification accuracy on GLUE
  benchmarks. This fits in the target pod's 2 GiB RAM limit without
  GPU, while BERT-large or GPT-2 class models would require GPU-only
  nodes.
- **Fine-tuning path.** ASNI-specific Albanian-language threats
  require fine-tuning on domain corpora. The `python/training/`
  pipeline produces LoRA adapters on top of DistilBERT. A SaaS API
  offers no fine-tuning path compatible with data-sovereignty
  requirements.
- **Model registry with checksums.** `models/models.yaml` pins
  model version, source URL, and SHA-256. This prevents silent model
  drift and enables reproducible deployments.

## Consequences

- **Hardware floor.** Minimum 2 GiB RAM for the Python pod without
  GPU; 4 GiB recommended when both phishing and prompt models are
  loaded simultaneously.
- **Download step.** First startup in a new environment runs
  `models/download.sh`. The Helm chart's init-container handles this
  for Kubernetes deployments.
- **Model update process.** Updating a model requires bumping the
  SHA-256 and URL in `models/models.yaml`, re-running download, and
  re-validating accuracy benchmarks in CI.

## Alternatives considered + rejected

- **OpenAI / Anthropic API.** Data leaves the deployment; per-request
  cost; availability dependency; no fine-tuning with sovereign data.
  **Rejected.** (See ADR-004.)
- **Custom model training from scratch.** Months of labelled data
  collection and GPU compute. DistilBERT fine-tuning achieves
  comparable accuracy on domain tasks with a fraction of the effort.
  **Rejected as the primary approach** (retained as the fine-tuning
  strategy on top of DistilBERT).
- **Rules-only (no ML).** Phase 4.1 baseline; macro-F1 ≈ 0.30 is
  insufficient for production detection rates. **Rejected for Phase
  4.2.**

## Validation

- `python -m pytest tests/ml/phishing_accuracy_test.py` must achieve
  F1 ≥ 0.80 on the labelled phishing corpus.
- `python -m pytest tests/ml/prompt_accuracy_test.py` must achieve
  BLOCKED recall ≥ 0.75 on the prompt injection corpus.
- `models/download.sh --verify` must exit 0 (all checksums match).

## Follow-ups

- ADR-013 (when issued) — model registry approval and signing.
- Phase 4.3: ONNX export for CPU-optimised inference on resource-
  constrained nodes.
