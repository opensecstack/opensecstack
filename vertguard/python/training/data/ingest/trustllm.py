"""Ingester skeleton for the TrustLLM safety subset.

Reference: https://github.com/HowieHwong/TrustLLM
Paper:     https://arxiv.org/abs/2401.05561
License:   MIT (per upstream repo) — verify before redistribution.

STATUS: NOT IMPLEMENTED. As of writing, TrustLLM ships its safety
benchmarks as JSON files in the upstream GitHub repo rather than as a
versioned, single-config HuggingFace dataset. There are several
community mirrors (e.g. `TrustLLM-Benchmark/*`) but none we trust as
canonical for stable provenance.

Rather than fabricate a loader against an unstable mirror, this module
intentionally raises. To wire it up:

    1. Pick a specific upstream artifact (raw JSON URL with a commit
       SHA, or a HF mirror with a fixed revision).
    2. Implement `ingest()` to download it (e.g. via `urllib.request`),
       parse, and emit our schema.
    3. Map prompts in jailbreak / misuse subsets -> BLOCKED. Map
       benign-control prompts -> CLEAN. Tag with the originating
       subset name.
    4. Add the URL + SHA of the artifact to the provenance log.

Run (currently):
    python -m training.data.ingest.trustllm --output corpus.jsonl
"""

from __future__ import annotations

import argparse
import sys

from ._common import add_common_args

SOURCE_URL = "https://github.com/HowieHwong/TrustLLM"
DATASET_ID = "TrustLLM (upstream JSON, no canonical HF mirror)"
SOURCE_TAG = "public:trustllm"


def ingest(*_args, **_kwargs) -> int:
    raise NotImplementedError(
        "TrustLLM ingester is not implemented. See module docstring; "
        "pin a specific upstream artifact (raw URL + commit SHA) before "
        "wiring this up. Do NOT fabricate samples."
    )


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    add_common_args(p)
    args = p.parse_args()
    print(
        "[trustllm] not implemented. Reference: "
        f"{SOURCE_URL}\nSee module docstring for wiring steps. "
        f"args.output={args.output}",
        file=sys.stderr,
    )
    sys.exit(3)


if __name__ == "__main__":
    main()
