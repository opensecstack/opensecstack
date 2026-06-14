"""Loader: parsing logic + label mapping."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from data.loader import LABEL_TO_ID, _read_jsonl

CORPUS = Path(__file__).resolve().parents[3] / "internal/prompt/corpus/corpus.jsonl"


def test_label_map_matches_go_enum() -> None:
    assert LABEL_TO_ID == {"CLEAN": 0, "SUSPICIOUS": 1, "BLOCKED": 2}


def test_read_jsonl_skips_comments_and_blanks(tmp_path: Path) -> None:
    p = tmp_path / "mini.jsonl"
    p.write_text(
        "# comment\n"
        "\n"
        '{"id":"a","text":"hi","expected":"CLEAN"}\n'
        '{"id":"b","text":"go","expected":"BLOCKED","tags":["x"]}\n',
        encoding="utf-8",
    )
    rows = _read_jsonl(p)
    assert [r["id"] for r in rows] == ["a", "b"]
    assert rows[1]["tags"] == ["x"]


def test_read_jsonl_rejects_bad_verdict(tmp_path: Path) -> None:
    p = tmp_path / "bad.jsonl"
    p.write_text('{"id":"a","text":"hi","expected":"NOPE"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="invalid expected"):
        _read_jsonl(p)


def test_read_jsonl_requires_fields(tmp_path: Path) -> None:
    p = tmp_path / "missing.jsonl"
    p.write_text('{"id":"a","expected":"CLEAN"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="missing field"):
        _read_jsonl(p)


@pytest.mark.skipif(not CORPUS.exists(), reason="corpus.jsonl not present")
def test_real_corpus_counts() -> None:
    rows = _read_jsonl(CORPUS)
    assert len(rows) >= 90  # spec says ~100 today
    counts = {"CLEAN": 0, "SUSPICIOUS": 0, "BLOCKED": 0}
    for r in rows:
        counts[r["expected"]] += 1
    assert all(v > 0 for v in counts.values())


def test_load_corpus_returns_dataset(tmp_path: Path) -> None:
    pytest.importorskip("datasets")
    from data.loader import load_corpus

    p = tmp_path / "mini.jsonl"
    p.write_text(
        '{"id":"a","text":"hi","expected":"CLEAN"}\n'
        '{"id":"b","text":"attack","expected":"BLOCKED"}\n',
        encoding="utf-8",
    )
    ds = load_corpus(p)
    assert ds.column_names == ["id", "text", "label", "context", "tags"]
    assert ds["label"] == [0, 2]
