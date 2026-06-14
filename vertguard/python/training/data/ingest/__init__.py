"""Public-source corpus ingesters.

Each module in this package downloads a public, license-compatible
jailbreak / prompt-injection / harmful-prompt dataset and emits JSONL
in VertGuard's corpus schema:

    {"id", "text", "expected", "context", "source", "tags"?, "notes"?}

Run modules as scripts (requires `datasets>=2.18` + network):

    python -m training.data.ingest.jailbreakbench --output out.jsonl
    python -m training.data.ingest.do_not_answer  --output out.jsonl
    python -m training.data.ingest.anthropic_hh   --output out.jsonl --max 2000
    python -m training.data.ingest.trustllm       --output out.jsonl   # skeleton

Each ingester documents its source URL, license, and label-mapping rule
in its module docstring. NEVER fabricate samples and stamp them with a
public-source `source` field — that taints downstream training.

The `REGISTRY` below maps a short source name to the module path; tools
that programmatically dispatch by name (e.g. a future `ingest --source X`
runner) should consult this table.
"""

from __future__ import annotations

REGISTRY: dict[str, str] = {
    "jailbreakbench": "training.data.ingest.jailbreakbench",
    "do_not_answer":  "training.data.ingest.do_not_answer",
    "anthropic_hh":   "training.data.ingest.anthropic_hh",
    "trustllm":       "training.data.ingest.trustllm",
}

# Stable label expected from each source; used for sanity-checking
# downstream balance reports without re-reading the JSONL.
EXPECTED_LABELS: dict[str, tuple[str, ...]] = {
    "jailbreakbench": ("BLOCKED", "CLEAN"),
    "do_not_answer":  ("BLOCKED",),
    "anthropic_hh":   ("BLOCKED", "SUSPICIOUS"),
    "trustllm":       ("BLOCKED", "CLEAN"),  # once implemented
}

__all__ = ["REGISTRY", "EXPECTED_LABELS"]
