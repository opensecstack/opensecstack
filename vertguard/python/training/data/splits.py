"""Stratified 70/15/15 train/val/test splits."""

from __future__ import annotations

from typing import Any


def stratified_split(
    ds: Any,
    train: float = 0.70,
    val: float = 0.15,
    test: float = 0.15,
    seed: int = 42,
) -> Any:
    """Return DatasetDict with train/val/test, stratified on `label`."""
    if abs(train + val + test - 1.0) > 1e-6:
        raise ValueError(f"split ratios must sum to 1.0, got {train + val + test}")

    from datasets import Dataset, DatasetDict  # type: ignore
    from sklearn.model_selection import train_test_split  # type: ignore

    indices = list(range(len(ds)))
    labels = list(ds["label"])

    # First carve off the test set, then split the remainder into train/val so
    # both later splits stay stratified relative to the original distribution.
    train_val_idx, test_idx = train_test_split(
        indices, test_size=test, random_state=seed, stratify=labels
    )
    train_val_labels = [labels[i] for i in train_val_idx]
    relative_val = val / (train + val)
    train_idx, val_idx = train_test_split(
        train_val_idx,
        test_size=relative_val,
        random_state=seed,
        stratify=train_val_labels,
    )

    def _select(idx: list[int]) -> Dataset:
        return ds.select(idx)

    out = DatasetDict(
        train=_select(train_idx),
        validation=_select(val_idx),
        test=_select(test_idx),
    )
    for name, split in out.items():
        present = set(split["label"])
        if len(present) < len(set(labels)):
            raise AssertionError(f"split {name!r} missing classes; got {present}")
    return out
