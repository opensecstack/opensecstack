"""Paraphrase augmentation (stub today; back-translation when GPU + model land)."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# TODO(phase-4.2.1): replace stub with facebook/m2m100 round-trip.
# Tracking issue: https://github.com/opensecstack/vertguard/issues/TBD
_STUB_WARNED = False


def paraphrase_back_translation(
    text: str, source_lang: str = "en", pivot_lang: str = "fr"
) -> str:
    """Stub: returns input unchanged. Real impl pivots through pivot_lang."""
    global _STUB_WARNED
    if not _STUB_WARNED:
        logger.warning(
            "paraphrase_back_translation is a stub (source=%s pivot=%s); "
            "install facebook/m2m100 and wire it up for real augmentation.",
            source_lang,
            pivot_lang,
        )
        _STUB_WARNED = True
    return text


def augment_dataset(ds: Any, factor: int = 2) -> Any:
    """Duplicate rows factor-1 times via the paraphrase stub.

    Pipeline-shape only: today this just multiplies the dataset size so the
    rest of the wiring (tokenizer, trainer) exercises realistic batch counts.
    """
    if factor <= 1:
        return ds
    from datasets import Dataset, concatenate_datasets  # type: ignore

    parts = [ds]
    for _ in range(factor - 1):
        new_texts = [paraphrase_back_translation(t) for t in ds["text"]]
        clone = Dataset.from_dict({**{c: ds[c] for c in ds.column_names}, "text": new_texts})
        parts.append(clone)
    return concatenate_datasets(parts)
