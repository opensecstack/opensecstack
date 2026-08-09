"""
Unit tests for pure helper functions in app/api/compliance.py:
_compute_compliance_score() and _sign_artifact(). No database required.
"""
import hashlib
import hmac
from decimal import Decimal
from types import SimpleNamespace

from app.api.compliance import _compute_compliance_score, _sign_artifact


def _control(status):
    return SimpleNamespace(status=status)


class TestComputeComplianceScore:
    def test_empty_list_returns_none(self):
        assert _compute_compliance_score([]) is None

    def test_all_not_applicable_returns_none(self):
        controls = [_control("not_applicable"), _control("not_applicable")]
        assert _compute_compliance_score(controls) is None

    def test_all_compliant_is_100(self):
        controls = [_control("compliant"), _control("compliant")]
        assert _compute_compliance_score(controls) == Decimal("100.00")

    def test_all_non_compliant_is_0(self):
        controls = [_control("non_compliant"), _control("non_compliant")]
        assert _compute_compliance_score(controls) == Decimal("0.00")

    def test_all_not_assessed_is_0(self):
        controls = [_control("not_assessed")]
        assert _compute_compliance_score(controls) == Decimal("0.00")

    def test_partially_compliant_weighted_at_50(self):
        controls = [_control("partially_compliant")]
        assert _compute_compliance_score(controls) == Decimal("50.00")

    def test_mixed_statuses_averaged(self):
        # compliant(100) + non_compliant(0) + partially_compliant(50) = 150 / 3 = 50.00
        controls = [_control("compliant"), _control("non_compliant"), _control("partially_compliant")]
        assert _compute_compliance_score(controls) == Decimal("50.00")

    def test_not_applicable_excluded_from_denominator(self):
        # Only the 'compliant' control counts; not_applicable is excluded entirely.
        controls = [_control("compliant"), _control("not_applicable")]
        assert _compute_compliance_score(controls) == Decimal("100.00")

    def test_unknown_status_treated_as_zero_weight(self):
        controls = [_control("some_future_status")]
        assert _compute_compliance_score(controls) == Decimal("0.00")

    def test_result_quantized_to_two_decimal_places(self):
        # 100 + 0 + 0 = 100 / 3 = 33.333... -> rounds to 33.33
        controls = [_control("compliant"), _control("non_compliant"), _control("non_compliant")]
        score = _compute_compliance_score(controls)
        assert score == Decimal("33.33")
        assert str(score) == "33.33"


class TestSignArtifact:
    def test_returns_64_char_hex_digest(self):
        sig = _sign_artifact("filehash123", "alice", "secret")
        assert len(sig) == 64
        assert all(c in "0123456789abcdef" for c in sig)

    def test_deterministic(self):
        s1 = _sign_artifact("filehash123", "alice", "secret")
        s2 = _sign_artifact("filehash123", "alice", "secret")
        assert s1 == s2

    def test_matches_manual_hmac(self):
        file_hash, actor, secret = "abc123", "bob", "topsecret"
        message = f"{file_hash}:{actor}".encode()
        expected = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
        assert _sign_artifact(file_hash, actor, secret) == expected

    def test_different_actor_produces_different_signature(self):
        s1 = _sign_artifact("filehash123", "alice", "secret")
        s2 = _sign_artifact("filehash123", "bob", "secret")
        assert s1 != s2

    def test_different_secret_produces_different_signature(self):
        s1 = _sign_artifact("filehash123", "alice", "secret1")
        s2 = _sign_artifact("filehash123", "alice", "secret2")
        assert s1 != s2

    def test_different_file_hash_produces_different_signature(self):
        s1 = _sign_artifact("hash1", "alice", "secret")
        s2 = _sign_artifact("hash2", "alice", "secret")
        assert s1 != s2
