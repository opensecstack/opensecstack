"""MediaModel unit tests — Phase 4.2 sklearn gradient-boosting backend.

Three test groups:
  1. Stub backend: verify score_media runs end-to-end using StubModel so
     the test suite has no weight-file dependency.
  2. C2PA override logic: validate the hard cap/floor rules applied on
     top of the raw model score by monkey-patching a minimal classifier.
  3. Missing model directory: verify FileNotFoundError is raised loudly
     when VERTGUARD_ML_MEDIA_MODEL_DIR points to a non-existent path.
"""

from __future__ import annotations

import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest

from vertguard_ml.models.base import (
    VERDICT_BLOCKED,
    VERDICT_CLEAN,
    VERDICT_SUSPICIOUS,
    MediaFeatures,
)
from vertguard_ml.models.stub import StubModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_features(
    *,
    file_hash: str = "sha256:aabbcc",
    mime_type: str = "image/jpeg",
    file_size: int = 2 * 1024 * 1024,
    has_c2pa_manifest: bool = True,
    c2pa_signature_valid: bool = True,
) -> MediaFeatures:
    return MediaFeatures(
        file_hash=file_hash,
        mime_type=mime_type,
        file_size=file_size,
        has_c2pa_manifest=has_c2pa_manifest,
        c2pa_signature_valid=c2pa_signature_valid,
    )


def _make_mock_clf(proba: float) -> MagicMock:
    """Return a sklearn-style classifier mock that yields *proba* as P(class=1)."""
    clf = MagicMock()
    clf.predict_proba.return_value = np.array([[1.0 - proba, proba]])
    return clf


# ---------------------------------------------------------------------------
# 1. Stub backend — no weight files needed
# ---------------------------------------------------------------------------

@pytest.fixture
def stub() -> StubModel:
    return StubModel()


def test_stub_score_media_clean_with_valid_manifest(stub: StubModel) -> None:
    result = stub.score_media(_make_features(has_c2pa_manifest=True, c2pa_signature_valid=True))
    assert result.verdict == VERDICT_CLEAN
    assert result.confidence < 0.3
    assert result.input_hash == "sha256:aabbcc"


def test_stub_score_media_suspicious_no_manifest(stub: StubModel) -> None:
    result = stub.score_media(_make_features(has_c2pa_manifest=False, c2pa_signature_valid=False))
    assert result.confidence >= 0.25
    assert any(f.name == "no_c2pa_manifest" for f in result.top_features)


def test_stub_score_media_higher_score_invalid_signature(stub: StubModel) -> None:
    invalid = stub.score_media(_make_features(has_c2pa_manifest=True, c2pa_signature_valid=False))
    no_manifest = stub.score_media(_make_features(has_c2pa_manifest=False, c2pa_signature_valid=False))
    # Invalid signature (0.50) > no manifest (0.25).
    assert invalid.confidence > no_manifest.confidence


def test_stub_score_media_top_features_capped_at_three(stub: StubModel) -> None:
    result = stub.score_media(
        _make_features(
            has_c2pa_manifest=False,
            c2pa_signature_valid=False,
            mime_type="video/mp4",
            file_size=50 * 1024 * 1024,
        )
    )
    assert len(result.top_features) <= 3
    weights = [f.weight for f in result.top_features]
    assert weights == sorted(weights, reverse=True)


def test_stub_score_media_latency_recorded(stub: StubModel) -> None:
    result = stub.score_media(_make_features())
    assert result.latency_ms >= 0.0


def test_stub_score_media_backend_tag(stub: StubModel) -> None:
    result = stub.score_media(_make_features())
    assert result.backend == "stub"


# ---------------------------------------------------------------------------
# 2. C2PA override logic — tested via MediaModel with a mocked classifier
# ---------------------------------------------------------------------------

def _build_media_model(clf_proba: float, tmp_path: Path) -> "MediaModel":
    """Construct a MediaModel backed by a mock classifier in *tmp_path*."""
    from vertguard_ml.models.media import MediaModel

    # Write minimal artefacts so __init__ succeeds.
    (tmp_path / "model.joblib").touch()
    (tmp_path / "version.txt").write_text("v4.2-test", encoding="utf-8")

    mock_joblib = types.ModuleType("joblib")
    mock_joblib.load = MagicMock(return_value=_make_mock_clf(clf_proba))  # type: ignore[attr-defined]

    with patch.dict("sys.modules", {"joblib": mock_joblib}):
        model = MediaModel(weights_path=str(tmp_path))

    # Replace the live clf with a fresh mock (joblib.load already ran).
    model._clf = _make_mock_clf(clf_proba)
    return model


def test_c2pa_valid_manifest_caps_confidence(tmp_path: Path) -> None:
    """Valid C2PA manifest must cap confidence at 0.15 even if model scores high."""
    from vertguard_ml.models.media import _C2PA_VALID_CAP

    model = _build_media_model(clf_proba=0.90, tmp_path=tmp_path)
    result = model.score_media(
        _make_features(has_c2pa_manifest=True, c2pa_signature_valid=True)
    )
    assert result.confidence <= _C2PA_VALID_CAP
    assert result.verdict == VERDICT_CLEAN


def test_c2pa_invalid_signature_floors_confidence(tmp_path: Path) -> None:
    """Invalid C2PA signature must floor confidence at 0.70 even if model scores low."""
    from vertguard_ml.models.media import _C2PA_INVALID_FLOOR

    model = _build_media_model(clf_proba=0.05, tmp_path=tmp_path)
    result = model.score_media(
        _make_features(has_c2pa_manifest=True, c2pa_signature_valid=False)
    )
    assert result.confidence >= _C2PA_INVALID_FLOOR
    assert result.verdict == VERDICT_BLOCKED


def test_no_c2pa_manifest_passes_raw_score_through(tmp_path: Path) -> None:
    """When no manifest is present, the raw model score is used without override."""
    model = _build_media_model(clf_proba=0.50, tmp_path=tmp_path)
    result = model.score_media(
        _make_features(has_c2pa_manifest=False, c2pa_signature_valid=False)
    )
    # Raw score 0.50 → SUSPICIOUS; no cap or floor applied.
    assert result.verdict == VERDICT_SUSPICIOUS
    assert 0.40 <= result.confidence <= 0.60


def test_score_media_returns_correct_version(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.10, tmp_path=tmp_path)
    result = model.score_media(_make_features())
    assert result.model_version == "v4.2-test"


def test_score_media_backend_is_sklearn_cpu(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.10, tmp_path=tmp_path)
    result = model.score_media(_make_features())
    assert result.backend == "sklearn-cpu"


def test_score_media_input_hash_is_file_hash(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.10, tmp_path=tmp_path)
    features = _make_features(file_hash="sha256:deadbeef")
    result = model.score_media(features)
    assert result.input_hash == "sha256:deadbeef"


def test_score_media_video_mime_fires_feature(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.40, tmp_path=tmp_path)
    result = model.score_media(
        _make_features(
            mime_type="video/mp4",
            has_c2pa_manifest=False,
            c2pa_signature_valid=False,
        )
    )
    assert any("mime_is_video" in f.name for f in result.top_features)


def test_score_prompt_raises(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.10, tmp_path=tmp_path)
    with pytest.raises(NotImplementedError):
        model.score_prompt("hello")


def test_score_phishing_raises(tmp_path: Path) -> None:
    model = _build_media_model(clf_proba=0.10, tmp_path=tmp_path)
    with pytest.raises(NotImplementedError):
        model.score_phishing("phish")


# ---------------------------------------------------------------------------
# 3. Missing model directory → FileNotFoundError
# ---------------------------------------------------------------------------

def test_missing_model_dir_raises_file_not_found_error() -> None:
    from vertguard_ml.models.media import MediaModel

    mock_joblib = types.ModuleType("joblib")
    mock_joblib.load = MagicMock()  # type: ignore[attr-defined]

    with patch.dict("sys.modules", {"joblib": mock_joblib}):
        with pytest.raises(FileNotFoundError, match="Media ML model directory not found"):
            MediaModel(weights_path="/nonexistent/path/that/does/not/exist")


def test_missing_model_joblib_raises_file_not_found_error(tmp_path: Path) -> None:
    """Directory exists but model.joblib is absent — must raise FileNotFoundError."""
    from vertguard_ml.models.media import MediaModel

    # Directory present, no model.joblib inside.
    (tmp_path / "version.txt").write_text("v4.2-test", encoding="utf-8")

    mock_joblib = types.ModuleType("joblib")
    mock_joblib.load = MagicMock()  # type: ignore[attr-defined]

    with patch.dict("sys.modules", {"joblib": mock_joblib}):
        with pytest.raises(FileNotFoundError, match="model.joblib"):
            MediaModel(weights_path=str(tmp_path))


def test_missing_version_txt_falls_back_gracefully(tmp_path: Path) -> None:
    """Absent version.txt must not crash — fall back to 'v0-unversioned'."""
    from vertguard_ml.models.media import MediaModel

    (tmp_path / "model.joblib").touch()
    # No version.txt written.

    mock_joblib = types.ModuleType("joblib")
    mock_joblib.load = MagicMock(return_value=_make_mock_clf(0.10))  # type: ignore[attr-defined]

    with patch.dict("sys.modules", {"joblib": mock_joblib}):
        model = MediaModel(weights_path=str(tmp_path))

    model._clf = _make_mock_clf(0.10)
    assert model.version == "v0-unversioned"
