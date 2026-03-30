"""Tests for app/reporters/json_reporter.py and app/reporters/sarif_reporter.py."""
from __future__ import annotations

import json
import uuid
from datetime import date, datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.reporters import generate_json_report, generate_sarif_report


# ---------------------------------------------------------------------------
# Fixtures / mock helpers
# ---------------------------------------------------------------------------

def _org(
    *,
    name: str = "Acme GmbH",
    country: str = "DE",
    sector: str = "Finance",
    entity_type: str = "essential",
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("00000000-0000-0000-0000-000000000001"),
        name=name,
        country=country,
        sector=sector,
        entity_type=entity_type,
    )


def _assessment(
    *,
    title: str = "Q1 2026 NIS2 Assessment",
    status: str = "completed",
    framework_version: str = "2.0",
    assessor: str = "alice@example.com",
    scope: str = "Cloud Infrastructure",
    due_date: date | None = None,
    completed_at: datetime | None = None,
) -> Any:
    return SimpleNamespace(
        id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        title=title,
        status=status,
        framework_version=framework_version,
        assessor=assessor,
        scope=scope,
        due_date=due_date,
        completed_at=completed_at or datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc),
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        updated_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
    )


def _control(
    measure_ref: str,
    status: str,
    *,
    risk_score: float | None = None,
    gap_description: str | None = None,
    remediation_plan: str | None = None,
    remediation_owner: str | None = None,
    remediation_status: str | None = None,
    external_ticket_url: str | None = None,
    assessed_by: str | None = None,
    assessed_at: datetime | None = None,
    nist_category: str = "protect",
    title: str | None = None,
    description: str | None = None,
    artifacts: list | None = None,
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
        assessed_by=assessed_by or "alice@example.com",
        assessed_at=assessed_at,
        nist_category=nist_category,
        title=title or f"NIS2 A21(2)({measure_ref})",
        description=description or f"Control {measure_ref} description",
        evidence={},
        remediation_due=None,
        artifacts=artifacts or [],
    )


def _all_controls() -> list[Any]:
    statuses = [
        ("a", "compliant"),
        ("b", "non_compliant"),
        ("c", "partially_compliant"),
        ("d", "not_assessed"),
        ("e", "not_applicable"),
        ("f", "compliant"),
        ("g", "non_compliant"),
        ("h", "partially_compliant"),
        ("i", "compliant"),
        ("j", "compliant"),
    ]
    return [_control(ref, status) for ref, status in statuses]


# ---------------------------------------------------------------------------
# JSON reporter tests
# ---------------------------------------------------------------------------


class TestJSONReporter:
    def test_returns_bytes(self):
        result = generate_json_report(_assessment(), _all_controls(), _org())
        assert isinstance(result, bytes)

    def test_valid_json(self):
        result = generate_json_report(_assessment(), _all_controls(), _org())
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_schema_version(self):
        parsed = json.loads(generate_json_report(_assessment(), _all_controls(), _org()))
        assert parsed["schema_version"] == "1.0"

    def test_report_type(self):
        parsed = json.loads(generate_json_report(_assessment(), _all_controls(), _org()))
        assert parsed["report_type"] == "nis2_compliance"

    def test_organisation_fields(self):
        parsed = json.loads(generate_json_report(_assessment(), _all_controls(), _org()))
        org = parsed["organisation"]
        assert org["name"] == "Acme GmbH"
        assert org["country"] == "DE"
        assert org["entity_type"] == "essential"

    def test_assessment_fields(self):
        parsed = json.loads(generate_json_report(_assessment(), _all_controls(), _org()))
        a = parsed["assessment"]
        assert a["title"] == "Q1 2026 NIS2 Assessment"
        assert a["status"] == "completed"
        assert a["framework_version"] == "2.0"

    def test_summary_total(self):
        controls = _all_controls()  # 10 controls
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["total_controls"] == 10

    def test_summary_counts_match_controls(self):
        controls = _all_controls()
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        s = parsed["summary"]
        # From _all_controls: compliant=4, non_compliant=2, partial=2, not_assessed=1, not_applicable=1
        assert s["compliant"] == 4
        assert s["non_compliant"] == 2
        assert s["partially_compliant"] == 2
        assert s["not_assessed"] == 1
        assert s["not_applicable"] == 1

    def test_compliance_pct_calculation(self):
        controls = _all_controls()  # 4 compliant out of 10
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert parsed["summary"]["overall_compliance_pct"] == 40.0

    def test_controls_list_length(self):
        controls = _all_controls()
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        assert len(parsed["controls"]) == 10

    def test_control_fields(self):
        controls = [_control("a", "compliant", risk_score=2.0)]
        parsed = json.loads(generate_json_report(_assessment(), controls, _org()))
        ctrl = parsed["controls"][0]
        assert ctrl["measure_ref"] == "a"
        assert ctrl["status"] == "compliant"
        assert ctrl["risk_score"] == 2.0

    def test_empty_controls(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert parsed["summary"]["total_controls"] == 0
        assert parsed["summary"]["overall_compliance_pct"] == 0.0
        assert parsed["controls"] == []

    def test_generated_at_is_present(self):
        parsed = json.loads(generate_json_report(_assessment(), [], _org()))
        assert "generated_at" in parsed

    def test_control_with_remediation_fields(self):
        ctrl = _control(
            "b",
            "non_compliant",
            gap_description="Missing incident response plan",
            remediation_plan="Draft IRP by Q2",
            remediation_owner="bob@example.com",
            external_ticket_url="https://jira.example.com/TICKET-1",
        )
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        c = parsed["controls"][0]
        assert c["gap_description"] == "Missing incident response plan"
        assert c["remediation_plan"] == "Draft IRP by Q2"
        assert c["remediation_owner"] == "bob@example.com"
        assert c["external_ticket_url"] == "https://jira.example.com/TICKET-1"

    def test_artifact_count_in_control(self):
        from types import SimpleNamespace as NS
        ctrl = _control("a", "compliant", artifacts=[NS(id=uuid.uuid4()), NS(id=uuid.uuid4())])
        parsed = json.loads(generate_json_report(_assessment(), [ctrl], _org()))
        assert parsed["controls"][0]["artifact_count"] == 2


# ---------------------------------------------------------------------------
# SARIF reporter tests
# ---------------------------------------------------------------------------


class TestSARIFReporter:
    def test_returns_bytes(self):
        result = generate_sarif_report(_assessment(), _all_controls(), _org())
        assert isinstance(result, bytes)

    def test_valid_json(self):
        result = generate_sarif_report(_assessment(), _all_controls(), _org())
        parsed = json.loads(result)
        assert isinstance(parsed, dict)

    def test_sarif_version(self):
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        assert parsed["version"] == "2.1.0"

    def test_schema_field(self):
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        assert "sarif-schema-2.1.0.json" in parsed["$schema"]

    def test_single_run(self):
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        assert len(parsed["runs"]) == 1

    def test_tool_name(self):
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        assert parsed["runs"][0]["tool"]["driver"]["name"] == "NIS2 Compass"

    def test_rules_count(self):
        # 10 NIS2 A21(2) measures (a-j)
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        assert len(parsed["runs"][0]["tool"]["driver"]["rules"]) == 10

    def test_rule_ids_are_nis2(self):
        parsed = json.loads(generate_sarif_report(_assessment(), _all_controls(), _org()))
        rule_ids = [r["id"] for r in parsed["runs"][0]["tool"]["driver"]["rules"]]
        assert "NIS2-A21-a" in rule_ids
        assert "NIS2-A21-j" in rule_ids

    def test_results_count_matches_controls(self):
        controls = _all_controls()
        parsed = json.loads(generate_sarif_report(_assessment(), controls, _org()))
        assert len(parsed["runs"][0]["results"]) == len(controls)

    def test_non_compliant_maps_to_error(self):
        ctrl = _control("b", "non_compliant")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "error"

    def test_partially_compliant_maps_to_warning(self):
        ctrl = _control("c", "partially_compliant")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "warning"

    def test_compliant_maps_to_none(self):
        ctrl = _control("a", "compliant")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "none"

    def test_not_assessed_maps_to_note(self):
        ctrl = _control("d", "not_assessed")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        result = parsed["runs"][0]["results"][0]
        assert result["level"] == "note"

    def test_location_uri_format(self):
        ctrl = _control("a", "compliant")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        loc = parsed["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri.startswith("nis2://assessments/")
        assert "/controls/a" in uri

    def test_result_properties_include_org_name(self):
        ctrl = _control("a", "compliant")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org(name="TestOrg")))
        props = parsed["runs"][0]["results"][0]["properties"]
        assert props["organisation"] == "TestOrg"

    def test_gap_description_in_message(self):
        ctrl = _control("b", "non_compliant", gap_description="No IRP exists")
        parsed = json.loads(generate_sarif_report(_assessment(), [ctrl], _org()))
        msg = parsed["runs"][0]["results"][0]["message"]["text"]
        assert "No IRP exists" in msg

    def test_empty_controls(self):
        parsed = json.loads(generate_sarif_report(_assessment(), [], _org()))
        assert parsed["runs"][0]["results"] == []

    def test_invocations_execution_successful(self):
        parsed = json.loads(generate_sarif_report(_assessment(), [], _org()))
        invocation = parsed["runs"][0]["invocations"][0]
        assert invocation["executionSuccessful"] is True
