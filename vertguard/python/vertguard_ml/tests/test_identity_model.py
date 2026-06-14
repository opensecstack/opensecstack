"""Identity model unit tests — Phase 4.2 Isolation Forest backend.

Coverage:
  - StubModel.score_identity baseline behaviour (no weights required)
  - IdentityModel override rules exercised via a monkey-patched classifier
  - FileNotFoundError when model directory is absent
"""

from __future__ import annotations

import json
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vertguard_ml.models.base import (
    VERDICT_BLOCKED,
    VERDICT_CLEAN,
    VERDICT_SUSPICIOUS,
    IdentityFeatures,
)
from vertguard_ml.models.stub import StubModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _features(
    *,
    claim_type: str = "passport",
    context: str = "kyc",
    name_token_count: int = 2,
    email_domain_is_disposable: bool = False,
    id_format_valid: bool = True,
    issuer_country: str = "DE",
    has_dob: bool = True,
    replay_count: int = 0,
) -> IdentityFeatures:
    return IdentityFeatures(
        claim_type=claim_type,
        context=context,
        name_token_count=name_token_count,
        email_domain_is_disposable=email_domain_is_disposable,
        id_format_valid=id_format_valid,
        issuer_country=issuer_country,
        has_dob=has_dob,
        replay_count=replay_count,
    )


def _make_identity_model(tmp_path: Path, raw_score: float = -0.1) -> "IdentityModel":
    """Construct an IdentityModel with a monkey-patched sklearn classifier.

    The real model file is replaced with a MagicMock so tests run without
    trained weights on disk. ``raw_score`` controls the value returned by
    ``score_samples`` (Isolation Forest convention: negative = anomalous).
    """
    from vertguard_ml.models.identity import IdentityModel

    # Write the minimum artefacts the constructor needs.
    (tmp_path / "model.joblib").write_bytes(b"placeholder")
    (tmp_path / "country_risk_scores.json").write_text(
        json.dumps({"DE": 0.1, "RU": 0.7, "KP": 0.95}), encoding="utf-8"
    )

    clf_mock = MagicMock()
    clf_mock.score_samples.return_value = [raw_score]

    with (
        patch("joblib.load", return_value=clf_mock),
        patch.dict("os.environ", {"VERTGUARD_ML_IDENTITY_MODEL_DIR": str(tmp_path)}),
    ):
        model = IdentityModel()

    # Replace the real classifier with the mock after construction so
    # score_identity calls use the controlled return value.
    model._clf = clf_mock
    return model


# ---------------------------------------------------------------------------
# StubModel — score_identity baseline
# ---------------------------------------------------------------------------

class TestStubModelScoreIdentity:
    @pytest.fixture
    def stub(self) -> StubModel:
        return StubModel()

    def test_clean_benign_identity(self, stub: StubModel) -> None:
        result = stub.score_identity(_features())
        assert result.verdict == VERDICT_CLEAN
        assert result.confidence < 0.3
        assert result.input_hash.startswith("sha256:")

    def test_disposable_email_raises_score(self, stub: StubModel) -> None:
        result = stub.score_identity(_features(email_domain_is_disposable=True))
        assert result.confidence >= 0.3
        assert any(f.name == "disposable_email" for f in result.top_features)

    def test_sanctioned_country_is_suspicious_or_blocked(self, stub: StubModel) -> None:
        result = stub.score_identity(_features(issuer_country="KP"))
        assert result.verdict in (VERDICT_SUSPICIOUS, VERDICT_BLOCKED)
        assert any(f.name == "sanctioned_jurisdiction" for f in result.top_features)

    def test_invalid_id_format_raises_score(self, stub: StubModel) -> None:
        base = stub.score_identity(_features(id_format_valid=True))
        invalid = stub.score_identity(_features(id_format_valid=False))
        assert invalid.confidence > base.confidence

    def test_top_features_capped_at_three(self, stub: StubModel) -> None:
        result = stub.score_identity(
            _features(
                email_domain_is_disposable=True,
                id_format_valid=False,
                issuer_country="KP",
                replay_count=5,
            )
        )
        assert len(result.top_features) <= 3
        weights = [f.weight for f in result.top_features]
        assert weights == sorted(weights, reverse=True)

    def test_input_hash_is_stable(self, stub: StubModel) -> None:
        feat = _features(issuer_country="AL", replay_count=1)
        assert stub.score_identity(feat).input_hash == stub.score_identity(feat).input_hash

    def test_score_prompt_raises(self, stub: StubModel) -> None:
        # StubModel supports score_prompt; this just checks it doesn't raise
        # unexpectedly for a safe input.
        result = stub.score_prompt("hello")
        assert result.verdict == VERDICT_CLEAN

    def test_latency_ms_is_positive(self, stub: StubModel) -> None:
        result = stub.score_identity(_features())
        assert result.latency_ms >= 0.0


# ---------------------------------------------------------------------------
# IdentityModel — override rules
# ---------------------------------------------------------------------------

class TestIdentityModelOverrideRules:
    def test_replay_count_gte_3_floors_confidence_at_0_80(
        self, tmp_path: Path
    ) -> None:
        # Use a raw score close to 0 so the normalised confidence would be
        # ~0.5 without the override, confirming the floor is applied.
        model = _make_identity_model(tmp_path, raw_score=-0.0)
        result = model.score_identity(_features(replay_count=3))
        assert result.confidence >= 0.80

    def test_replay_count_exactly_3_is_floored(self, tmp_path: Path) -> None:
        model = _make_identity_model(tmp_path, raw_score=0.4)  # normally ~0.1
        result = model.score_identity(_features(replay_count=3))
        assert result.confidence >= 0.80

    def test_replay_count_2_does_not_trigger_floor(self, tmp_path: Path) -> None:
        # raw_score=0.4 → confidence = clamp(1-(0.4+0.5)) = clamp(0.1) = 0.1
        model = _make_identity_model(tmp_path, raw_score=0.4)
        result = model.score_identity(_features(replay_count=2))
        assert result.confidence < 0.80

    def test_disposable_email_and_invalid_format_floors_at_0_70(
        self, tmp_path: Path
    ) -> None:
        # raw_score=0.4 → base confidence ~0.1; override should raise to 0.70.
        model = _make_identity_model(tmp_path, raw_score=0.4)
        result = model.score_identity(
            _features(email_domain_is_disposable=True, id_format_valid=False)
        )
        assert result.confidence >= 0.70

    def test_disposable_email_alone_does_not_trigger_combined_floor(
        self, tmp_path: Path
    ) -> None:
        model = _make_identity_model(tmp_path, raw_score=0.4)
        result = model.score_identity(
            _features(email_domain_is_disposable=True, id_format_valid=True)
        )
        # Combined floor (0.70) must NOT apply when id_format_valid is True.
        assert result.confidence < 0.70

    def test_both_overrides_active_takes_max(self, tmp_path: Path) -> None:
        # replay_count>=3 (floor 0.80) + disposable+invalid (floor 0.70)
        # → final confidence >= 0.80.
        model = _make_identity_model(tmp_path, raw_score=0.4)
        result = model.score_identity(
            _features(
                replay_count=5,
                email_domain_is_disposable=True,
                id_format_valid=False,
            )
        )
        assert result.confidence >= 0.80

    def test_score_result_fields_populated(self, tmp_path: Path) -> None:
        model = _make_identity_model(tmp_path, raw_score=-0.2)
        result = model.score_identity(_features(issuer_country="RU"))
        assert result.input_hash.startswith("sha256:")
        assert result.backend == "sklearn-cpu"
        assert result.latency_ms >= 0.0
        assert result.verdict in (VERDICT_CLEAN, VERDICT_SUSPICIOUS, VERDICT_BLOCKED)

    def test_top_features_sorted_desc_by_weight(self, tmp_path: Path) -> None:
        model = _make_identity_model(tmp_path, raw_score=-0.2)
        result = model.score_identity(
            _features(
                email_domain_is_disposable=True,
                id_format_valid=False,
                replay_count=1,
                issuer_country="RU",
            )
        )
        weights = [f.weight for f in result.top_features]
        assert weights == sorted(weights, reverse=True)

    def test_score_prompt_raises_not_implemented(self, tmp_path: Path) -> None:
        model = _make_identity_model(tmp_path)
        with pytest.raises(NotImplementedError):
            model.score_prompt("text")

    def test_score_phishing_raises_not_implemented(self, tmp_path: Path) -> None:
        model = _make_identity_model(tmp_path)
        with pytest.raises(NotImplementedError):
            model.score_phishing("text")


# ---------------------------------------------------------------------------
# IdentityModel — FileNotFoundError on missing artefacts
# ---------------------------------------------------------------------------

class TestIdentityModelFileNotFound:
    def test_missing_model_dir_raises(self, tmp_path: Path) -> None:
        absent = str(tmp_path / "does_not_exist")
        with (
            patch.dict("os.environ", {"VERTGUARD_ML_IDENTITY_MODEL_DIR": absent}),
            pytest.raises(FileNotFoundError, match="Identity ML model directory not found"),
        ):
            from vertguard_ml.models.identity import IdentityModel
            IdentityModel()

    def test_missing_model_joblib_raises(self, tmp_path: Path) -> None:
        # Dir exists but model.joblib is absent.
        (tmp_path / "country_risk_scores.json").write_text("{}", encoding="utf-8")
        with (
            patch("joblib.load"),
            patch.dict("os.environ", {"VERTGUARD_ML_IDENTITY_MODEL_DIR": str(tmp_path)}),
            pytest.raises(FileNotFoundError, match="model.joblib"),
        ):
            from vertguard_ml.models.identity import IdentityModel
            IdentityModel()

    def test_missing_country_risk_json_raises(self, tmp_path: Path) -> None:
        # Dir exists, model.joblib exists, but country_risk_scores.json absent.
        (tmp_path / "model.joblib").write_bytes(b"placeholder")
        with (
            patch("joblib.load", return_value=MagicMock()),
            patch.dict("os.environ", {"VERTGUARD_ML_IDENTITY_MODEL_DIR": str(tmp_path)}),
            pytest.raises(FileNotFoundError, match="country_risk_scores.json"),
        ):
            from vertguard_ml.models.identity import IdentityModel
            IdentityModel()
