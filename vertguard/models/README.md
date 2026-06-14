# VertGuard Model Artefacts

This directory holds the ML model artefacts used by VertGuard's inference modules.
Git only tracks the registry (`models.yaml`) and this README; the actual model
weights are excluded via `.gitignore` because they are large binary files.

## Downloading models

Run the auto-download script from the repository root:

```sh
bash models/download.sh
```

The script reads `models/models.yaml`, verifies SHA-256 checksums after each
download, and places the weights in the subdirectories listed under `path:`.

### Requirements

- `curl` or `wget`
- `sha256sum` (Linux) / `shasum -a 256` (macOS)
- Approximately 2 GB of free disk space for all four models

## Model registry

See `models/models.yaml` for the authoritative list of models, versions,
expected checksums, and source URLs.

## Directory layout after download

```
models/
  distilbert-prompt-injection/
    config.json
    pytorch_model.bin
    tokenizer_config.json
    tokenizer.json
    vocab.txt
  distilbert-phishing/
    config.json
    pytorch_model.bin
    tokenizer_config.json
    tokenizer.json
    vocab.txt
  identity-gan-detector/
    config.json
    pytorch_model.bin
    tokenizer_config.json
  media-deepfake-detector/
    config.json
    pytorch_model.bin
```

## Updating a model

1. Update the `version` and `sha256` fields in `models.yaml`.
2. Run `bash models/download.sh` to fetch and verify the new weights.
3. Restart the ML service (`python/ml_service/`).

## Offline / air-gapped environments

Set the `VERTGUARD_MODEL_MIRROR` environment variable to an internal HTTP
server that mirrors the HuggingFace model repos, then run `download.sh`.
The script uses that URL prefix instead of the public source URLs.
