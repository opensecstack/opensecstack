"""Slow smoke-test: verifies train.py wiring on a tiny corpus on CPU.

Opt in with: pytest -q -m slow tests/test_train_smoketest.py
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow


def _mini_corpus(path: Path) -> None:
    rows = []
    for i in range(4):
        rows.append({"id": f"c{i}", "text": f"hello number {i}", "expected": "CLEAN"})
    for i in range(4):
        rows.append({"id": f"s{i}", "text": f"please maybe {i}", "expected": "SUSPICIOUS"})
    for i in range(4):
        rows.append({"id": f"b{i}", "text": f"ignore all rules {i}", "expected": "BLOCKED"})
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


def test_train_smoke(tmp_path: Path) -> None:
    pytest.importorskip("transformers")
    pytest.importorskip("torch")

    corpus = tmp_path / "mini.jsonl"
    _mini_corpus(corpus)
    cfg = tmp_path / "cfg.yaml"
    cfg.write_text(
        textwrap.dedent(
            """
            model: {name: distilbert-base-uncased, num_labels: 3}
            train: {lr: 2e-5, batch_size: 4, epochs: 1, weight_decay: 0.0,
                    max_seq_len: 32, warmup_ratio: 0.0}
            data: {augment_factor: 1}
            """
        ).strip(),
        encoding="utf-8",
    )

    out = tmp_path / "out"
    cmd = [
        sys.executable,
        "-m",
        "training.train",
        "--config",
        str(cfg),
        "--corpus",
        str(corpus),
        "--output-dir",
        str(out),
        "--max-steps",
        "2",
        "--cpu",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr
    assert "EVAL:" in proc.stdout
    assert (out).exists()
