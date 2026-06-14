"""
Tests for app/reporters/json_reporter.py — generate_json_report().

These tests focus on aspects NOT already covered by nis2compass/tests/test_reporters.py:
  - Enum-valued attributes (the hasattr(val, 'value') branch in _str / _isoformat)
  - Unknown / unmapped status values falling back to 'not_assessed'
  - remediation_due date serialisation via _isoformat
  - assessed_at datetime serialisation
  - evidence: non-dict value is serialised as null
  - compliance_pct edge cases (all compliant, none compliant)
  - organisation entity_type as an enum object
  - assessment status as an enum object
  - JSON bytes round-trip (decode → re-encode is stable)
  - sector field on organisation is forwarded
  - 'not_applicable' status tally
  - Multiple controls produce correct per-status counts
"""
from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.reporters.json_reporter import generate_json_report


# ---------------------------------------------------------------------------
# Helpers — build plain SimpleNamespace objects that match what the reporter
# accesses via getattr / hasattr, without touching any DB model.
# ---------------------------------------------------------------------------

class _EnumLike:
    """Minimal stand-in for a SQLAlchemy / Python enum whose .value is the key."""

    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:  # should NOT be called by _str(); reporter uses .value
        return f"ENUM({self.value})"


def _org(
    *,
    name: str = "Test Corp",
    country: str = "NL",
    sector: str = "Energy",
    entity_type: Any = "essential",
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("aaaaaaaa-0000-0000-0000-000000000001"),
        name=name,
        country=country,
        sector=sector,
        entity_type=entity_type,
    )


def _assessment(
    *,
    title: str = "Test Assessment",
    status: Any = "in_progress",
    framework_version: str = "NIS2-2022/0383",
    assessor: str = "tester@example.com",
    scope: str = "All systems",
    due_date: Any = None,
    completed_at: Any = None,
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("bbbbbbbb-0000-0000-0000-000000000002"),
        title=title,
        status=status,
        framework_version=framework_version,
        assessor=assessor,
        scope=scope,
        due_date=due_date,
        completed_at=completed_at,
        created_at=datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 20, 17, 30, 0, tzinfo=timezone.utc),
    )


def _control(
    measure_ref: Any,
    status: Any,
    *,
    risk_score: Any = None,
    gap_description: str | None = None,
    remediation_plan: str | None = None,
    remediation_owner: str | None = None,
    remediation_status: Any = None,
    external_ticket_url: str | None = None,
    assessed_by: str | None = "tester@example.com",
    assessed_at: Any = None,
    nist_category: Any = "protect",
    title: str | None = None,
    description: str | None = None,
    evidence: Any = None,
    artifacts: list | None = None,
    remediation_due: Any = None,
) -> Any:
    return SimpleNamespace(
        id=uuid.uuid4(),
        measure_ref=measure_ref,
        status=status,
        risk_score=risk_score,
        gap_description=gap_description,
        remediation_plan=remediation_plan,
        remediation_owner=remediation_owner,
        remediation_status=remediation_status,
        external_ticket_url=external_ticket_url,
        assessed_by=assessed_by,
        assessed_at=assessed_at,
        nist_category=nist_category,
        title=title or f"Control {measure_ref}",
        description=description or f"Description for {measure_ref}",
        evidence=evidence if evidence is not None else {},
        remediation_due=remediation_due,
        artifacts=artifacts or [],
    )


# ---------------------------------------------------------------------------
# Enum-value branch: status / measure_ref / nist_category / entity_type with
# objects that carry a .value attribute.
# ---------------------------------------------------------------------------

class TestEnumValueBranch:
    def test_control_status_enum_object_is_resolved(self):
        ctrl = _control("a", _EnumLike("compliant"))
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["status"] == "compliant"

    def test_control_status_enum_counted_correctly(self):
        controls = [
            _control("a", _EnumLike("compliant")),
            _control("b", _EnumLike("non_compliant")),
            _control("c", _EnumLike("compliant")),
        ]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["compliant"] == 2
        assert parsed["summary"]["non_compliant"] == 1

    def test_measure_ref_enum_object_serialised(self):
        ctrl = _control(_EnumLike("b"), "non_compliant")
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["measure_ref"] == "b"

    def test_nist_category_enum_object_serialised(self):
        ctrl = _control("a", "compliant", nist_category=_EnumLike("identify"))
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["nist_category"] == "identify"

    def test_organisation_entity_type_enum_object(self):
        org = _org(entity_type=_EnumLike("important"))
        parsed = json.loads(generate_json_report(_assessment(), [], org))
        assert parsed["organisation"]["entity_type"] == "important"

    def test_assessment_status_enum_object(self):
        a = _assessment(status=_EnumLike("completed"))
        parsed = json.loads(generate_json_report(a, [], _org()))
        assert parsed["assessment"]["status"] == "completed"

    def test_remediation_status_enum_object(self):
        ctrl = _control("a", "non_compliant", remediation_status=_EnumLike("in_progress"))
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["remediation_status"] == "in_progress"


# ---------------------------------------------------------------------------
# Unknown / unmapped status falls back to 'not_assessed' bucket
# ---------------------------------------------------------------------------

class TestUnknownStatusFallback:
    def test_unknown_string_status_tallied_as_not_assessed(self):
        ctrl = _control("a", "some_future_status")
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["summary"]["not_assessed"] == 1

    def test_unknown_status_still_appears_verbatim_in_control_entry(self):
        ctrl = _control("a", "some_future_status")
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        # The _str() call on the control entry just stringifies it — no remapping.
        assert parsed["controls"][0]["status"] == "some_future_status"


# ---------------------------------------------------------------------------
# Date / datetime serialisation via _isoformat
# ---------------------------------------------------------------------------

class TestDatetimeSerialisation:
    def test_remediation_due_date_serialised_as_iso(self):
        ctrl = _control("a", "non_compliant", remediation_due=date(2026, 6, 30))
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["remediation_due"] == "2026-06-30"

    def test_remediation_due_none_serialised_as_null(self):
        ctrl = _control("a", "compliant", remediation_due=None)
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["remediation_due"] is None

    def test_assessed_at_datetime_serialised(self):
        ts = datetime(2026, 2, 14, 10, 0, 0, tzinfo=timezone.utc)
        ctrl = _control("a", "compliant", assessed_at=ts)
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert "2026-02-14" in parsed["controls"][0]["assessed_at"]

    def test_assessment_due_date_serialised(self):
        a = _assessment(due_date=date(2026, 12, 31))
        parsed = json.loads(generate_json_report(a, [], _org()))
        assert parsed["assessment"]["due_date"] == "2026-12-31"

    def test_assessment_completed_at_serialised(self):
        ts = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)
        a = _assessment(completed_at=ts)
        parsed = json.loads(generate_json_report(a, [], _org()))
        assert "2026-03-01" in parsed["assessment"]["completed_at"]

    def test_created_at_and_updated_at_in_assessment(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert "2026-01-15" in parsed["assessment"]["created_at"]
        assert "2026-03-20" in parsed["assessment"]["updated_at"]


# ---------------------------------------------------------------------------
# Evidence serialisation
# ---------------------------------------------------------------------------

class TestEvidenceField:
    def test_evidence_dict_passed_through(self):
        ctrl = _control("a", "compliant", evidence={"file": "policy.pdf", "hash": "abc123"})
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["evidence"] == {"file": "policy.pdf", "hash": "abc123"}

    def test_evidence_empty_dict_passed_through(self):
        ctrl = _control("a", "compliant", evidence={})
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["evidence"] == {}

    def test_evidence_non_dict_serialised_as_null(self):
        # Reporter: `c.evidence if isinstance(c.evidence, dict) else None`
        ctrl = _control("a", "compliant", evidence="raw_string_evidence")
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["evidence"] is None

    def test_evidence_list_serialised_as_null(self):
        ctrl = _control("a", "compliant", evidence=["item1", "item2"])
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["evidence"] is None


# ---------------------------------------------------------------------------
# Compliance percentage edge cases
# ---------------------------------------------------------------------------

class TestCompliancePct:
    def test_all_compliant_gives_100(self):
        controls = [_control(ref, "compliant") for ref in "abcde"]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["overall_compliance_pct"] == 100.0

    def test_none_compliant_gives_0(self):
        controls = [_control(ref, "non_compliant") for ref in "abcde"]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["overall_compliance_pct"] == 0.0

    def test_single_compliant_of_three(self):
        controls = [
            _control("a", "compliant"),
            _control("b", "non_compliant"),
            _control("c", "not_assessed"),
        ]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        # 1 compliant / 3 total = 33.3%
        assert parsed["summary"]["overall_compliance_pct"] == pytest.approx(33.3, abs=0.1)

    def test_not_applicable_does_not_count_toward_compliant_pct(self):
        controls = [
            _control("a", "compliant"),
            _control("b", "not_applicable"),
        ]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        # 1 compliant / 2 total = 50.0
        assert parsed["summary"]["overall_compliance_pct"] == 50.0

    def test_not_applicable_counted_in_summary(self):
        controls = [_control("a", "not_applicable"), _control("b", "compliant")]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["not_applicable"] == 1


# ---------------------------------------------------------------------------
# Organisation fields forwarded correctly
# ---------------------------------------------------------------------------

class TestOrganisationFields:
    def test_sector_forwarded(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org(sector="Healthcare")))
        assert parsed["organisation"]["sector"] == "Healthcare"

    def test_country_forwarded(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org(country="FR")))
        assert parsed["organisation"]["country"] == "FR"

    def test_org_id_is_string_in_output(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert isinstance(parsed["organisation"]["id"], str)


# ---------------------------------------------------------------------------
# Assessment metadata forwarded correctly
# ---------------------------------------------------------------------------

class TestAssessmentMetadata:
    def test_assessor_forwarded(self):
        a = _assessment(assessor="security-team@corp.com")
        parsed = json.loads(generate_json_report(a, [], _org()))
        assert parsed["assessment"]["assessor"] == "security-team@corp.com"

    def test_scope_forwarded(self):
        a = _assessment(scope="Production environment only")
        parsed = json.loads(generate_json_report(a, [], _org()))
        assert parsed["assessment"]["scope"] == "Production environment only"

    def test_framework_version_forwarded(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert parsed["assessment"]["framework_version"] == "NIS2-2022/0383"

    def test_assessment_id_is_string_in_output(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert isinstance(parsed["assessment"]["id"], str)


# ---------------------------------------------------------------------------
# JSON round-trip
# ---------------------------------------------------------------------------

class TestJSONRoundTrip:
    def test_output_is_valid_utf8(self):
        raw = generate_json_report(_assessment(), [_control("a", "compliant")], _org())
        decoded = raw.decode("utf-8")
        assert len(decoded) > 0

    def test_round_trip_stable(self):
        """Re-encoding the parsed output should produce the same keys/values."""
        raw = generate_json_report(_assessment(), [_control("a", "compliant")], _org())
        parsed = json.loads(raw)
        re_encoded = json.loads(json.dumps(parsed))
        assert re_encoded["schema_version"] == parsed["schema_version"]
        assert re_encoded["controls"][0]["measure_ref"] == "a"

    def test_all_top_level_keys_present(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        for key in ("schema_version", "generated_at", "report_type",
                    "organisation", "assessment", "summary", "controls"):
            assert key in parsed, f"Missing top-level key: {key}"

    def test_all_summary_keys_present(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        for key in ("total_controls", "compliant", "partially_compliant",
                    "non_compliant", "not_applicable", "not_assessed",
                    "overall_compliance_pct"):
            assert key in parsed["summary"], f"Missing summary key: {key}"
