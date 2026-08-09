"""
Unit tests for app/audit.py — redact_pii() and the version=1 legacy
chain-hash formula. Pure functions, no database required.
"""
import hashlib

from app.audit import redact_pii, _compute_chain_hash


class TestRedactPii:
    def test_none_returns_none(self):
        assert redact_pii(None) is None

    def test_non_dict_non_list_scalar_passthrough(self):
        assert redact_pii(42) == 42
        assert redact_pii(True) is True

    def test_plain_string_not_matching_email_passthrough(self):
        assert redact_pii("just a string") == "just a string"

    def test_bare_string_email_is_redacted(self):
        assert redact_pii("alice@example.com") == "[REDACTED]"

    def test_pii_key_value_redacted_case_insensitive(self):
        obj = {"Email": "alice@example.com", "PHONE": "+1234567890"}
        out = redact_pii(obj)
        assert out["Email"] == "[REDACTED]"
        assert out["PHONE"] == "[REDACTED]"

    def test_non_pii_key_left_untouched(self):
        obj = {"status": "compliant", "score": 95}
        assert redact_pii(obj) == {"status": "compliant", "score": 95}

    def test_email_shaped_value_under_non_pii_key_is_still_redacted(self):
        obj = {"notes": "bob@example.com"}
        out = redact_pii(obj)
        assert out["notes"] == "[REDACTED]"

    def test_recurses_into_nested_dict(self):
        obj = {"actor": {"email": "carol@example.com", "role": "admin"}}
        out = redact_pii(obj)
        assert out["actor"]["email"] == "[REDACTED]"
        assert out["actor"]["role"] == "admin"

    def test_recurses_into_list_of_dicts(self):
        obj = {"contacts": [{"email": "a@example.com"}, {"email": "b@example.com"}]}
        out = redact_pii(obj)
        assert out["contacts"][0]["email"] == "[REDACTED]"
        assert out["contacts"][1]["email"] == "[REDACTED]"

    def test_recurses_into_plain_list(self):
        obj = ["alice@example.com", "not an email"]
        out = redact_pii(obj)
        assert out == ["[REDACTED]", "not an email"]

    def test_all_pii_keys_covered(self):
        pii_keys = [
            "email", "contact_email", "phone", "phone_number", "ssn",
            "national_id", "tax_id", "iban", "first_name", "last_name",
            "full_name", "address", "street", "postal_code", "zip_code",
        ]
        obj = {k: "sensitive-value" for k in pii_keys}
        out = redact_pii(obj)
        assert all(v == "[REDACTED]" for v in out.values())

    def test_does_not_mutate_original(self):
        obj = {"email": "alice@example.com"}
        redact_pii(obj)
        assert obj["email"] == "alice@example.com"

    def test_none_value_under_pii_key_still_redacted(self):
        # A PII key is always masked regardless of its value's type.
        obj = {"email": None}
        assert redact_pii(obj)["email"] == "[REDACTED]"


class TestComputeChainHashLegacyVersion:
    def test_version_1_uses_bare_concatenation(self):
        entry_id, action, actor, resource_type = "id1", "created", "bob", "org"
        rid, ph, ts = "res1", "prev1", "2026-01-01T00:00:00"
        raw = f"{entry_id}{action}{actor}{resource_type}{rid}{ph}{ts}"
        expected = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        result = _compute_chain_hash(entry_id, action, actor, resource_type, rid, ph, ts, version=1)
        assert result == expected

    def test_version_1_and_version_2_differ_for_same_inputs(self):
        args = ("id1", "created", "bob", "org", "res1", "prev1", "2026-01-01T00:00:00")
        h1 = _compute_chain_hash(*args, version=1)
        h2 = _compute_chain_hash(*args, version=2)
        assert h1 != h2

    def test_version_1_null_resource_and_prev_hash(self):
        # None resource_id/prev_hash are represented as the literal "NULL"
        # string in the bare-concatenation (version=1) formula too.
        expected = hashlib.sha256("id1createdboborgNULLNULLts".encode("utf-8")).hexdigest()
        result = _compute_chain_hash("id1", "created", "bob", "org", None, None, "ts", version=1)
        assert result == expected
