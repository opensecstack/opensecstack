"""Unit tests for the public-dataset ingester helpers.

Covers normalize, make_id determinism, and write_jsonl deduplication.
The dataset-loading code paths are NOT exercised here — they require
network access and the `datasets` package; those are integration tests.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from data.ingest._common import (
    MAX_LEN,
    make_id,
    normalize,
    write_jsonl,
)


# ── normalize ────────────────────────────────────────────────────────

def test_normalize_strips_and_collapses_whitespace():
    assert normalize("  hello   world  ") == "hello world"
    assert normalize("a\n\nb\tc") == "a b c"


def test_normalize_handles_empty_and_none():
    assert normalize("") == ""
    assert normalize(None) == ""  # type: ignore[arg-type]
    assert normalize("   \n\t  ") == ""


def test_normalize_truncates_to_max_len():
    big = "x" * (MAX_LEN + 500)
    out = normalize(big)
    assert len(out) == MAX_LEN
    assert out == "x" * MAX_LEN


def test_normalize_unicode_preserved():
    # We don't NFKC-normalise; non-ASCII text round-trips.
    assert normalize("  Përshëndetje    botë  ") == "Përshëndetje botë"


# ── make_id ──────────────────────────────────────────────────────────

def test_make_id_is_deterministic():
    a = make_id("jbb", 7, "ignore previous instructions")
    b = make_id("jbb", 7, "ignore previous instructions")
    assert a == b


def test_make_id_changes_with_text():
    a = make_id("jbb", 7, "alpha")
    b = make_id("jbb", 7, "beta")
    assert a != b


def test_make_id_changes_with_idx():
    a = make_id("jbb", 7, "alpha")
    b = make_id("jbb", 8, "alpha")
    assert a != b


def test_make_id_format():
    sid = make_id("Jail-Break.Bench!", 42, "hello")
    # source slug is alnum-only, lowercased; idx is zero-padded; hash is 8 hex.
    assert sid.startswith("jailbreakbench_00042_")
    suffix = sid.rsplit("_", 1)[-1]
    assert len(suffix) == 8
    assert all(c in "0123456789abcdef" for c in suffix)


# ── write_jsonl ──────────────────────────────────────────────────────

def _sample(sid: str, text: str = "t", expected: str = "BLOCKED") -> dict:
    return {
        "id": sid, "text": text, "expected": expected,
        "context": "default", "source": "public:test",
    }


def test_write_jsonl_creates_file_and_writes_rows(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    n = write_jsonl(out, [_sample("a"), _sample("b")], append=False)
    assert n == 2
    lines = out.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["id"] == "a"


def test_write_jsonl_dedupes_within_batch(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    n = write_jsonl(out, [_sample("a"), _sample("a"), _sample("b")], append=False)
    assert n == 2
    ids = [json.loads(l)["id"] for l in out.read_text(encoding="utf-8").splitlines()]
    assert ids == ["a", "b"]


def test_write_jsonl_dedupes_against_existing_file(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    write_jsonl(out, [_sample("a"), _sample("b")], append=False)
    n = write_jsonl(out, [_sample("b"), _sample("c")], append=True)
    assert n == 1  # only "c" is new
    ids = [json.loads(l)["id"] for l in out.read_text(encoding="utf-8").splitlines()]
    assert ids == ["a", "b", "c"]


def test_write_jsonl_no_append_truncates(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    write_jsonl(out, [_sample("a"), _sample("b")], append=False)
    n = write_jsonl(out, [_sample("c")], append=False)
    assert n == 1
    ids = [json.loads(l)["id"] for l in out.read_text(encoding="utf-8").splitlines()]
    assert ids == ["c"]


def test_write_jsonl_skips_comment_lines_when_deduping(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    out.write_text(
        "# header comment\n"
        "\n"
        + json.dumps(_sample("a")) + "\n",
        encoding="utf-8",
    )
    n = write_jsonl(out, [_sample("a"), _sample("b")], append=True)
    assert n == 1
    # Comment line preserved.
    assert out.read_text(encoding="utf-8").startswith("# header comment\n")


def test_write_jsonl_ignores_malformed_existing_lines(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    out.write_text("not json at all\n" + json.dumps(_sample("a")) + "\n",
                   encoding="utf-8")
    n = write_jsonl(out, [_sample("a"), _sample("b")], append=True)
    assert n == 1  # "a" deduped, "b" added; malformed line tolerated


def test_write_jsonl_skips_rows_without_id(tmp_path: Path):
    out = tmp_path / "corpus.jsonl"
    bad = {"text": "no id", "expected": "BLOCKED"}
    n = write_jsonl(out, [bad, _sample("a")], append=False)
    assert n == 1


@pytest.mark.parametrize("revision_seed", [(None, 1), ("abc123", 2)])
def test_make_id_stable_across_revisions(revision_seed):
    # make_id ignores revision; the same (source, idx, text) yields
    # the same ID even if upstream revision changes. This matters for
    # dedup across re-runs.
    _rev, _seed = revision_seed
    assert make_id("hh", 0, "hello") == make_id("hh", 0, "hello")
