"""Shared helpers for public-dataset ingesters.

These ingesters download from upstream HuggingFace datasets at runtime
and convert each row to VertGuard's corpus schema:

    {"id", "text", "expected", "context", "source", "tags"?, "notes"?}

NEVER fabricate sample content here. The point of an ingester is to
faithfully relay an upstream public dataset; if the upstream is
unreachable, the ingester must fail loudly, not invent rows.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Iterable, Iterator

# Cap any single sample at this many characters. Some datasets contain
# multi-paragraph dialogue turns; longer than 4096 chars rarely helps
# the classifier and bloats the corpus on disk.
MAX_LEN = 4096

_WS_RE = re.compile(r"\s+")


def normalize(text: str) -> str:
    """Strip + collapse whitespace + truncate to MAX_LEN.

    Returns "" if input is None/empty after stripping. Truncation is at
    the character level (not token); we don't try to land on a word
    boundary because the trainer's tokenizer handles that.
    """
    if not text:
        return ""
    cleaned = _WS_RE.sub(" ", str(text)).strip()
    if len(cleaned) > MAX_LEN:
        cleaned = cleaned[:MAX_LEN]
    return cleaned


def make_id(source: str, idx: int, text: str) -> str:
    """Deterministic ID: `<source>_<idx:05d>_<sha256(text)[:8]>`.

    Same text under the same (source, idx) yields the same ID across
    runs — important for dedup and reproducibility.
    """
    h = hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]
    safe_source = re.sub(r"[^a-zA-Z0-9]+", "", source).lower()[:16] or "src"
    return f"{safe_source}_{idx:05d}_{h}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _existing_ids(path: Path) -> set[str]:
    """Read existing JSONL and return the set of IDs present.

    Skips comment lines (#) and blank lines, matching corpus.jsonl
    convention. Malformed lines are ignored (we don't want a single
    bad line to block dedup).
    """
    ids: set[str] = set()
    if not path.exists():
        return ids
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            sid = obj.get("id")
            if isinstance(sid, str):
                ids.add(sid)
    return ids


def write_jsonl(path: Path, samples: Iterable[dict], append: bool = True) -> int:
    """Write samples to JSONL, deduping by ID against existing rows.

    Returns the number of NEW samples written (excludes dedup hits).
    With append=False, the file is truncated first.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    seen = _existing_ids(path) if append else set()
    mode = "a" if (append and path.exists()) else "w"
    written = 0
    with path.open(mode, encoding="utf-8") as fh:
        for s in samples:
            sid = s.get("id")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
            written += 1
    return written


def require_datasets():
    """Import `datasets` lazily; print install instructions if missing."""
    try:
        import datasets  # noqa: F401
        return datasets
    except ImportError:
        print(
            "ERROR: the `datasets` package is required for public-dataset "
            "ingesters.\n"
            "Install with one of:\n"
            "    pip install 'datasets>=2.18'\n"
            "    pip install -e 'python[training]'   # from repo root\n",
            file=sys.stderr,
        )
        sys.exit(2)


def add_common_args(parser) -> None:
    """Attach --output, --max, --seed, --append flags to a parser."""
    parser.add_argument("--output", required=True, type=Path,
                        help="Destination JSONL path (will be created if missing).")
    parser.add_argument("--max", type=int, default=1000,
                        help="Cap on emitted samples after sampling (default 1000).")
    parser.add_argument("--seed", type=int, default=42,
                        help="RNG seed for sub-sampling (default 42).")
    parser.add_argument("--append", action="store_true", default=True,
                        help="Append to --output (default). Use --no-append to overwrite.")
    parser.add_argument("--no-append", dest="append", action="store_false")
    parser.add_argument("--revision", type=str, default=None,
                        help="Optional HuggingFace dataset revision (commit SHA / tag).")


def log_provenance(*, source_url: str, dataset_id: str, revision: str | None,
                   raw_count: int, written: int, output: Path) -> None:
    """Emit a single-line provenance summary + SHA-256 of the output file."""
    digest = sha256_file(output) if output.exists() else "<missing>"
    print(
        f"[ingest] source_url={source_url} dataset={dataset_id} "
        f"revision={revision or 'default'} upstream_rows={raw_count} "
        f"written={written} output={output} sha256={digest}"
    )


def take_sample(rows: list, max_n: int, seed: int) -> list:
    """Deterministically subsample a list of rows."""
    if max_n <= 0 or len(rows) <= max_n:
        return rows
    import random
    rng = random.Random(seed)
    idxs = list(range(len(rows)))
    rng.shuffle(idxs)
    chosen = sorted(idxs[:max_n])
    return [rows[i] for i in chosen]


def iter_to_list(ds) -> list[dict]:
    """Materialise a HF dataset (or iterable of dict-like rows) into a list."""
    out: list[dict] = []
    for row in ds:
        # HF rows are dict-like; cast for safety.
        out.append(dict(row))
    return out
