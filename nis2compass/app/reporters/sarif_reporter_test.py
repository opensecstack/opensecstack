"""
Tests for app/reporters/sarif_reporter.py — generate_sarif_report().

These tests focus on aspects NOT already covered by nis2compass/tests/test_reporters.py:
  - not_applicable maps to level "none"
  - Full rule shape: fullDescription, helpUri, properties (measure_ref, framework, article)
  - Invocation properties contain organisation_id, assessment_id, framework string
  - SARIF result properties carry risk_score, remediation_owner, remediation_due,
    external_ticket_url, assessment_title
  - Enum-valued measure_ref / status (hasattr .value branch)
  - Remediation plan appended to message text
  - Unknown status falls back to level "note" (default)
  - uriBaseId in artifactLocation
  - Driver informationUri and version fields
  - Runs array contains exactly one run
  - Rules array contains all 10 measures a–j
  - Each rule has the expected id prefix "NIS2-A21-"
  - Control with no gap / no remediation plan produces clean message (no trailing " | ")
  - out-of-range measure_ref not in NIS2_RULES produces fallback rule id
"""

from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.reporters.sarif_reporter import NIS2_RULES, STATUS_TO_LEVEL, generate_sarif_report

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _EnumLike:
    def __init__(self, value: str) -> None:
        self.value = value

    def __str__(self) -> str:
        return f"ENUM({self.value})"


def _org(
    *,
    name: str = "Omega GmbH",
    country: str = "AT",
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("cccccccc-0000-0000-0000-000000000003"),
        name=name,
        country=country,
    )


def _assessment(
    *,
    title: str = "SARIF Test Assessment",
    status: str = "in_progress",
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("dddddddd-0000-0000-0000-000000000004"),
        title=title,
        status=status,
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )


def _control(
    measure_ref: Any,
    status: Any,
    *,
    risk_score: Any = None,
    gap_description: str | None = None,
    remediation_plan: str | None = None,
    remediation_owner: str | None = None,
    external_ticket_url: str | None = None,
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
        external_ticket_url=external_ticket_url,
        remediation_due=remediation_due,
    )


def _parse(assessment=None, controls=None, org=None) -> dict:
    return json.loads(
        generate_sarif_report(
            assessment or _assessment(),
            controls if controls is not None else [],
            org or _org(),
        )
    )


# ---------------------------------------------------------------------------
# STATUS_TO_LEVEL constant coverage
# ---------------------------------------------------------------------------


class TestStatusToLevelMapping:
    def test_not_applicable_maps_to_none(self):
        ctrl = _control("e", "not_applicable")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "none"

    def test_partially_compliant_maps_to_warning(self):
        ctrl = _control("c", "partially_compliant")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "warning"

    def test_not_assessed_maps_to_note(self):
        ctrl = _control("d", "not_assessed")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "note"

    def test_non_compliant_maps_to_error(self):
        ctrl = _control("b", "non_compliant")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_compliant_maps_to_none(self):
        ctrl = _control("a", "compliant")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "none"

    def test_unknown_status_defaults_to_note(self):
        # STATUS_TO_LEVEL.get(status, "note") — unknown key → "note"
        ctrl = _control("a", "future_unknown_status")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "note"


# ---------------------------------------------------------------------------
# Enum-value branch
# ---------------------------------------------------------------------------


class TestEnumValueBranch:
    def test_status_enum_object_resolved_for_level(self):
        ctrl = _control("b", _EnumLike("non_compliant"))
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["level"] == "error"

    def test_measure_ref_enum_object_in_rule_id(self):
        ctrl = _control(_EnumLike("a"), "compliant")
        parsed = _parse(controls=[ctrl])
        result = parsed["runs"][0]["results"][0]
        assert result["ruleId"] == "NIS2-A21-a"

    def test_status_enum_in_properties(self):
        ctrl = _control("a", _EnumLike("compliant"))
        parsed = _parse(controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["status"] == "compliant"


# ---------------------------------------------------------------------------
# Full rule shape (all 10 rules a–j)
# ---------------------------------------------------------------------------


class TestRuleShape:
    def _rules(self) -> list[dict]:
        return _parse()["runs"][0]["tool"]["driver"]["rules"]

    def test_all_ten_rules_present(self):
        assert len(self._rules()) == 10

    def test_rule_ids_cover_a_through_j(self):
        ids = {r["id"] for r in self._rules()}
        for letter in "abcdefghij":
            assert f"NIS2-A21-{letter}" in ids

    def test_every_rule_has_full_description(self):
        for rule in self._rules():
            assert "fullDescription" in rule
            assert "text" in rule["fullDescription"]
            assert len(rule["fullDescription"]["text"]) > 0

    def test_full_description_references_article_and_measure(self):
        rules_by_id = {r["id"]: r for r in self._rules()}
        rule_a = rules_by_id["NIS2-A21-a"]
        text = rule_a["fullDescription"]["text"]
        assert "Article 21(2)(a)" in text

    def test_every_rule_has_help_uri(self):
        for rule in self._rules():
            assert "helpUri" in rule
            assert rule["helpUri"].startswith("https://")

    def test_help_uri_points_to_eur_lex(self):
        for rule in self._rules():
            assert "eur-lex.europa.eu" in rule["helpUri"]

    def test_rule_properties_contain_measure_ref(self):
        rules_by_id = {r["id"]: r for r in self._rules()}
        rule_b = rules_by_id["NIS2-A21-b"]
        assert rule_b["properties"]["measure_ref"] == "b"

    def test_rule_properties_contain_framework(self):
        for rule in self._rules():
            assert rule["properties"]["framework"] == "NIS2 Directive"

    def test_rule_properties_contain_article(self):
        for rule in self._rules():
            assert rule["properties"]["article"] == "Article 21(2)"

    def test_every_rule_has_short_description(self):
        for rule in self._rules():
            assert "shortDescription" in rule
            assert "text" in rule["shortDescription"]

    def test_every_rule_has_name(self):
        for rule in self._rules():
            assert "name" in rule
            assert len(rule["name"]) > 0


# ---------------------------------------------------------------------------
# Result properties
# ---------------------------------------------------------------------------


class TestResultProperties:
    def test_risk_score_in_properties(self):
        ctrl = _control("a", "non_compliant", risk_score=7.5)
        parsed = _parse(controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["risk_score"] == 7.5

    def test_risk_score_none_when_not_set(self):
        ctrl = _control("a", "non_compliant")
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["properties"]["risk_score"] is None

    def test_remediation_owner_in_properties(self):
        ctrl = _control("b", "non_compliant", remediation_owner="bob@example.com")
        parsed = _parse(controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["remediation_owner"] == "bob@example.com"

    def test_external_ticket_url_in_properties(self):
        ctrl = _control("b", "non_compliant", external_ticket_url="https://jira.example.com/T-99")
        parsed = _parse(controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["external_ticket_url"] == "https://jira.example.com/T-99"

    def test_assessment_title_in_properties(self):
        a = _assessment(title="My Custom Assessment")
        ctrl = _control("a", "compliant")
        parsed = _parse(assessment=a, controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["assessment_title"] == "My Custom Assessment"

    def test_organisation_name_in_properties(self):
        org = _org(name="SecureCo")
        ctrl = _control("a", "compliant")
        parsed = _parse(controls=[ctrl], org=org)
        assert parsed["runs"][0]["results"][0]["properties"]["organisation"] == "SecureCo"

    def test_remediation_due_date_serialised_in_properties(self):
        ctrl = _control("b", "non_compliant", remediation_due=date(2026, 9, 1))
        parsed = _parse(controls=[ctrl])
        props = parsed["runs"][0]["results"][0]["properties"]
        assert "2026-09-01" in props["remediation_due"]

    def test_remediation_due_none_serialised_as_empty_string(self):
        # Reporter: str(getattr(control, "remediation_due", "") or "") → ""
        ctrl = _control("a", "compliant", remediation_due=None)
        parsed = _parse(controls=[ctrl])
        assert parsed["runs"][0]["results"][0]["properties"]["remediation_due"] == ""


# ---------------------------------------------------------------------------
# Result message text
# ---------------------------------------------------------------------------


class TestResultMessage:
    def test_message_contains_measure_ref(self):
        ctrl = _control("f", "non_compliant")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "Article 21(2)(f)" in msg

    def test_message_contains_status(self):
        ctrl = _control("a", "non_compliant")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "non_compliant" in msg

    def test_gap_description_appended_to_message(self):
        ctrl = _control("b", "non_compliant", gap_description="No MFA enforced")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "No MFA enforced" in msg
        assert "Gap:" in msg

    def test_remediation_plan_appended_to_message(self):
        ctrl = _control("b", "non_compliant", remediation_plan="Enable MFA by Q3")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "Enable MFA by Q3" in msg
        assert "Remediation:" in msg

    def test_no_gap_no_remediation_message_no_trailing_pipe(self):
        ctrl = _control("a", "compliant")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert not msg.endswith(" | ")
        assert " | " not in msg  # only one part — no pipe at all

    def test_gap_without_remediation_has_single_pipe(self):
        ctrl = _control("b", "non_compliant", gap_description="Gap exists")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert msg.count(" | ") == 1

    def test_gap_and_remediation_have_two_pipes(self):
        ctrl = _control("b", "non_compliant", gap_description="Gap exists", remediation_plan="Fix it")
        parsed = _parse(controls=[ctrl])
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert msg.count(" | ") == 2


# ---------------------------------------------------------------------------
# Location shape
# ---------------------------------------------------------------------------


class TestLocationShape:
    def test_uri_base_id_is_NIS2COMPASS(self):
        ctrl = _control("a", "compliant")
        parsed = _parse(controls=[ctrl])
        loc = parsed["runs"][0]["results"][0]["locations"][0]
        assert loc["physicalLocation"]["artifactLocation"]["uriBaseId"] == "NIS2COMPASS"

    def test_uri_contains_assessment_id(self):
        a = _assessment()
        ctrl = _control("a", "compliant")
        parsed = _parse(assessment=a, controls=[ctrl])
        uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert str(a.id) in uri

    def test_uri_contains_measure_ref(self):
        ctrl = _control("g", "non_compliant")
        parsed = _parse(controls=[ctrl])
        uri = parsed["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "/controls/g" in uri


# ---------------------------------------------------------------------------
# Out-of-range / unknown measure_ref
# ---------------------------------------------------------------------------


class TestUnknownMeasureRef:
    def test_unknown_ref_produces_fallback_rule_id(self):
        # NIS2_RULES only has a–j; ref "z" falls back to f"NIS2-A21-{ref}"
        ctrl = _control("z", "non_compliant")
        parsed = _parse(controls=[ctrl])
        result = parsed["runs"][0]["results"][0]
        assert result["ruleId"] == "NIS2-A21-z"


# ---------------------------------------------------------------------------
# Invocations block
# ---------------------------------------------------------------------------


class TestInvocations:
    def test_invocations_has_one_entry(self):
        parsed = _parse()
        assert len(parsed["runs"][0]["invocations"]) == 1

    def test_invocation_execution_successful_true(self):
        parsed = _parse()
        assert parsed["runs"][0]["invocations"][0]["executionSuccessful"] is True

    def test_invocation_properties_organisation_id(self):
        org = _org()
        parsed = _parse(org=org)
        props = parsed["runs"][0]["invocations"][0]["properties"]
        assert props["organisation_id"] == str(org.id)

    def test_invocation_properties_assessment_id(self):
        a = _assessment()
        parsed = _parse(assessment=a)
        props = parsed["runs"][0]["invocations"][0]["properties"]
        assert props["assessment_id"] == str(a.id)

    def test_invocation_properties_framework(self):
        parsed = _parse()
        props = parsed["runs"][0]["invocations"][0]["properties"]
        assert "NIS2" in props["framework"]
        assert "Article 21(2)" in props["framework"]

    def test_invocation_has_end_time_utc(self):
        parsed = _parse()
        assert "endTimeUtc" in parsed["runs"][0]["invocations"][0]


# ---------------------------------------------------------------------------
# Driver metadata
# ---------------------------------------------------------------------------


class TestDriverMetadata:
    def test_driver_version(self):
        parsed = _parse()
        assert parsed["runs"][0]["tool"]["driver"]["version"] == "0.1.0"

    def test_driver_information_uri(self):
        parsed = _parse()
        uri = parsed["runs"][0]["tool"]["driver"]["informationUri"]
        assert uri.startswith("https://")

    def test_schema_field_contains_sarif(self):
        parsed = _parse()
        assert "sarif" in parsed["$schema"].lower()


# ---------------------------------------------------------------------------
# Output is bytes and valid JSON
# ---------------------------------------------------------------------------


class TestOutputFormat:
    def test_returns_bytes(self):
        assert isinstance(generate_sarif_report(_assessment(), [], _org()), bytes)

    def test_decodeable_utf8(self):
        raw = generate_sarif_report(_assessment(), [], _org())
        decoded = raw.decode("utf-8")
        assert len(decoded) > 0

    def test_all_top_level_sarif_keys_present(self):
        parsed = _parse()
        for key in ("$schema", "version", "runs"):
            assert key in parsed
