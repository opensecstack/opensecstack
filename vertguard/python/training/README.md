# VertGuard ML Training Pipeline

This directory holds the fine-tuning pipeline for VertGuard's prompt-injection
and phishing classifiers. It produces PyTorch checkpoints + ONNX exports that
the inference service in `../vertguard_ml/` serves over gRPC
(`proto/ml/v1/inference.proto`).

The 15 OWASP regex patterns currently score Macro-F1 ~0.30 on the labelled
corpus; this pipeline trains a DistilBERT classifier to lift recall on
paraphrased attacks. See `../../internal/prompt/corpus/TUNING.md` for the gap
analysis.

## Prerequisites

- Python 3.11+
- A GPU is **strongly recommended** for real training. CPU is fine for the
  smoke test, ONNX export, and unit tests.
- Install training extras (the `torch` wheel is large; CPU-only wheels are
  acceptable for dev):

  ```
  pip install -e ..[ml,training]
  ```

## Layout

```
training/
  data/      loader, augmentation stub, stratified splits
  configs/   YAML hyperparams (3-class prompt + binary phishing variants)
  train.py   fine-tune entrypoint
  eval.py    score a checkpoint against corpus.jsonl, emit JSON+markdown
  convert.py PyTorch -> ONNX, with round-trip parity check
  tests/     unit + slow smoke
```

## Quickstart

Smoke run (CPU, <30s, proves wiring):

```
python -m training.train \
  --config training/configs/distilbert_prompt.yaml \
  --output-dir /tmp/vg-smoke \
  --max-steps 2 --cpu
```

Full run (GPU recommended):

```
python -m training.train \
  --config training/configs/distilbert_prompt.yaml \
  --output-dir checkpoints/prompt-v1
```

Evaluate against the labelled corpus:

```
python -m training.eval \
  --checkpoint checkpoints/prompt-v1 \
  --corpus ../internal/prompt/corpus/corpus.jsonl \
  --report reports/prompt-v1.json
```

Export to ONNX for production inference:

```
python -m training.convert \
  --checkpoint checkpoints/prompt-v1 \
  --output-dir checkpoints/prompt-v1/onnx
```

## Pointing the inference service at a checkpoint

The `vertguard_ml` gRPC service loads the ONNX artifact at startup. After
running `convert.py`, set the model path env var the service reads (see
`../vertguard_ml/server.py`) and restart:

```
VERTGUARD_MODEL_DIR=$(pwd)/checkpoints/prompt-v1/onnx
```

The tokenizer artifacts in the same directory are required.

## Reproducibility

- Seeds: `--seed 42` (default), propagated through `transformers.set_seed` and
  the sklearn split.
- Pin versions in `pyproject.toml [training]` (transformers>=4.40, torch>=2.2,
  datasets>=2.18). Lock with a constraints file when promoting to a release.
- Dataset hash: record the SHA256 of `corpus.jsonl` next to every checkpoint
  (planned: emit it into `metadata.json` alongside the model — Phase 4.2.1).

## Tests

```
pytest -q tests/                      # fast unit tests (no GPU, no torch needed)
pytest -q -m slow tests/              # opt into the train smoke (downloads HF model)
```

The non-slow tests use `pytest.importorskip` so they pass on a fresh checkout
without the heavy ML extras.

## Known limitations

- Today's corpus has only ~100 samples — too small for production-grade
  training. Phase 4.2.1 expands to ~10k via back-translation augmentation
  (currently a stub in `data/augment.py`) and community contributions.
- `paraphrase_back_translation` is a stub: it returns input unchanged with a
  warning. Real implementation needs `facebook/m2m100` and a GPU.
- Smoke tests exercise wiring, not model quality. Real Macro-F1 numbers
  require the full training run on GPU.

## Cross-links

- `docs/ml-architecture.md` (planned) — overall ML architecture.
- `proto/ml/v1/inference.proto` — the gRPC contract.
- `../../internal/prompt/corpus/corpus.go` — Go-side evaluator (parity target).
