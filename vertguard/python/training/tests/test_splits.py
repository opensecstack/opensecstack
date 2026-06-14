"""Stratified split: ratios within tolerance, every class present in each split."""

from __future__ import annotations

import pytest


def _build_ds(n_per_class: int = 30):
    pytest.importorskip("datasets")
    pytest.importorskip("sklearn")
    from datasets import Dataset

    ids: list[str] = []
    texts: list[str] = []
    labels: list[int] = []
    for cls in (0, 1, 2):
        for i in range(n_per_class):
            ids.append(f"c{cls}_{i}")
            texts.append(f"sample {cls} {i}")
            labels.append(cls)
    return Dataset.from_dict(
        {"id": ids, "text": texts, "label": labels, "context": ["default"] * len(ids), "tags": [[]] * len(ids)}
    )


def test_split_ratios_within_one_percent() -> None:
    pytest.importorskip("sklearn")
    from data.splits import stratified_split

    ds = _build_ds(40)
    out = stratified_split(ds)
    total = len(ds)
    for name, target in [("train", 0.70), ("validation", 0.15), ("test", 0.15)]:
        actual = len(out[name]) / total
        assert abs(actual - target) <= 0.02, f"{name}={actual:.3f} vs {target}"


def test_all_classes_present_in_every_split() -> None:
    pytest.importorskip("sklearn")
    from data.splits import stratified_split

    ds = _build_ds(20)
    out = stratified_split(ds)
    for name, split in out.items():
        assert set(split["label"]) == {0, 1, 2}, name


def test_ratios_must_sum_to_one() -> None:
    pytest.importorskip("sklearn")
    from data.splits import stratified_split

    ds = _build_ds(10)
    with pytest.raises(ValueError):
        stratified_split(ds, train=0.6, val=0.2, test=0.3)
