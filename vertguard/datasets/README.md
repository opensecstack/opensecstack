# VertGuard Training Datasets

This directory holds the training and evaluation datasets used to fine-tune
and benchmark VertGuard's ML models.  Git only tracks the registry
(`datasets.yaml`) and this README; raw dataset files are excluded via
`.gitignore` because they can be large and may contain sensitive content.

## Downloading datasets

Run the auto-download script from the repository root:

```sh
bash datasets/download.sh
```

The script reads `datasets/datasets.yaml`, verifies SHA-256 checksums after
each download, and extracts the data into the subdirectories listed under
`path:`.

### Requirements

- `curl` or `wget`
- `sha256sum` (Linux) / `shasum -a 256` (macOS)
- Approximately 5 GB of free disk space for all datasets

## Dataset registry

See `datasets/datasets.yaml` for the full list of datasets, versions,
expected checksums, and source URLs.

## Directory layout after download

```
datasets/
  prompt-injection/
    train.jsonl
    eval.jsonl
    test.jsonl
  phishing/
    train.jsonl
    eval.jsonl
    test.jsonl
  identity-synthetic/
    train.jsonl
    eval.jsonl
    test.jsonl
  media-deepfake/
    train/
    eval/
    test/
```

## License and usage

Datasets are sourced from public research corpora and OpenSecStack-curated
samples.  Check each dataset's `license` field in `datasets.yaml` before
using in a commercial deployment.

## Adding a new dataset

1. Add an entry to `datasets.yaml` with `sha256: "placeholder-..."` initially.
2. Run `bash datasets/download.sh --dataset <name> --dry-run` to confirm the URL resolves.
3. Download, compute the real SHA-256, and update the registry.
4. Open a PR with the updated `datasets.yaml` only — never commit raw dataset files.
