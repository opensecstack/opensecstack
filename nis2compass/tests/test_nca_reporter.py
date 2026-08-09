"""
Unit tests for app/reporters/nca_reporter.py — generate_nca_report().

Pure function: builds an XML document from plain objects. No database
required — inputs are SimpleNamespace stand-ins, matching the house style
used in tests/test_reporters.py.
"""
from __future__ import annotations

import uuid
import xml.etree.ElementTree as ET
from datetime import date, datetime, timezone
from types import SimpleNamespace
from typing import Any

import pytest

from app.reporters.nca_reporter import _isoformat, _sanitise, generate_nca_report


def _org(name="Acme GmbH"):
    return SimpleNamespace(name=name)


def _assessment(
    *,
    title="Q1 2026 NIS2 Assessment",
    status="completed",
    compliance_score=87.5,
    created_at=None,
    completed_at=None,
    due_date=None,
    gap_report=None,
):
    return SimpleNamespace(
        id=uuid.UUID("00000000-0000-0000-0000-000000000002"),
        title=title,
        status=status,
        compliance_score=compliance_score,
        created_at=created_at or datetime(2026, 1, 1, tzinfo=timezone.utc),
        completed_at=completed_at,
        due_date=due_date,
        gap_report=gap_report,
    )


def _control(
    measure_ref="A.5.1",
    title="Access control policy",
    status="compliant",
    notes="",
    evidence=None,
    remediation_due=None,
):
    return SimpleNamespace(
        measure_ref=measure_ref,
        title=title,
        status=status,
        notes=notes,
        evidence=evidence if evidence is not None else {},
        remediation_due=remediation_due,
    )


def _parse(xml_bytes: bytes) -> ET.Element:
    return ET.fromstring(xml_bytes)


class TestSanitise:
    def test_none_returns_empty_string(self):
        assert _sanitise(None) == ""

    def test_strips_control_characters(self):
        assert _sanitise("hello\x00world\x07") == "helloworld"

    def test_keeps_tab_lf_cr(self):
        assert _sanitise("a\tb\nc\rd") == "a\tb\nc\rd"

    def test_truncates_to_max_length(self):
        long_text = "x" * 600
        result = _sanitise(long_text)
        assert len(result) == 500

    def test_enum_like_value_uses_dot_value(self):
        enum_like = SimpleNamespace(value="compliant")
        assert _sanitise(enum_like) == "compliant"

    def test_plain_string_passthrough(self):
        assert _sanitise("plain text") == "plain text"

    def test_non_string_coerced_to_string(self):
        assert _sanitise(42) == "42"


class TestIsoformat:
    def test_none_returns_empty_string(self):
        assert _isoformat(None) == ""

    def test_datetime_uses_isoformat(self):
        dt = datetime(2026, 1, 1, 12, 30, tzinfo=timezone.utc)
        assert _isoformat(dt) == dt.isoformat()

    def test_date_uses_isoformat(self):
        d = date(2026, 6, 15)
        assert _isoformat(d) == d.isoformat()

    def test_non_date_value_falls_back_to_str(self):
        assert _isoformat("already-a-string") == "already-a-string"


class TestGenerateNcaReport:
    def test_returns_valid_xml_bytes_with_declaration(self):
        xml_bytes = generate_nca_report(_assessment(), [], _org())
        assert xml_bytes.startswith(b'<?xml version="1.0" encoding="UTF-8"?>')
        root = _parse(xml_bytes)
        assert root.tag == "NCAReport"

    def test_root_attributes(self):
        xml_bytes = generate_nca_report(_assessment(), [], _org(name="Test Org"))
        root = _parse(xml_bytes)
        assert root.attrib["version"] == "1.0"
        assert root.attrib["organisation"] == "Test Org"
        assert "generated_at" in root.attrib

    def test_assessment_element_fields(self):
        assessment = _assessment(
            title="Annual Review",
            status="completed",
            compliance_score=92.0,
            completed_at=datetime(2026, 3, 1, tzinfo=timezone.utc),
        )
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        assessment_el = root.find("Assessment")
        assert assessment_el.attrib["id"] == str(assessment.id)
        assert assessment_el.attrib["title"] == "Annual Review"
        assert assessment_el.attrib["status"] == "completed"
        assert assessment_el.attrib["compliance_score"] == "92.0"
        assert assessment_el.attrib["period_end"] == assessment.completed_at.isoformat()

    def test_compliance_score_none_becomes_empty_string(self):
        assessment = _assessment(compliance_score=None)
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        assert root.find("Assessment").attrib["compliance_score"] == ""

    def test_period_end_falls_back_to_due_date_when_no_completed_at(self):
        due = date(2026, 12, 31)
        assessment = _assessment(completed_at=None, due_date=due)
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        assert root.find("Assessment").attrib["period_end"] == due.isoformat()

    def test_controls_are_serialised(self):
        controls = [
            _control("A.5.1", "Policy A", "compliant", evidence={"file1": "x"}),
            _control("A.5.2", "Policy B", "non_compliant", evidence={}),
        ]
        xml_bytes = generate_nca_report(_assessment(), controls, _org())
        root = _parse(xml_bytes)
        control_els = root.find("Controls").findall("Control")
        assert len(control_els) == 2
        assert control_els[0].attrib["ref"] == "A.5.1"
        assert control_els[0].attrib["status"] == "compliant"
        assert control_els[0].attrib["evidence_count"] == "1"
        assert control_els[1].attrib["evidence_count"] == "0"

    def test_control_evidence_non_dict_counts_as_zero(self):
        controls = [_control(evidence="not-a-dict")]
        xml_bytes = generate_nca_report(_assessment(), controls, _org())
        root = _parse(xml_bytes)
        assert root.find("Controls").find("Control").attrib["evidence_count"] == "0"

    def test_control_remediation_due_serialised(self):
        due = datetime(2026, 6, 1, tzinfo=timezone.utc)
        controls = [_control(remediation_due=due)]
        xml_bytes = generate_nca_report(_assessment(), controls, _org())
        root = _parse(xml_bytes)
        assert root.find("Controls").find("Control").attrib["remediation_due_date"] == due.isoformat()

    def test_empty_controls_list_produces_empty_controls_element(self):
        xml_bytes = generate_nca_report(_assessment(), [], _org())
        root = _parse(xml_bytes)
        assert len(root.find("Controls").findall("Control")) == 0

    def test_no_gap_report_produces_empty_gaps_element(self):
        xml_bytes = generate_nca_report(_assessment(gap_report=None), [], _org())
        root = _parse(xml_bytes)
        assert len(root.find("Gaps").findall("Gap")) == 0

    def test_gap_report_with_gaps_is_serialised(self):
        gap_report = {
            "gaps": [
                {
                    "measure_ref": "A.5.3",
                    "title": "Missing MFA",
                    "status": "non_compliant",
                    "severity": "high",
                    "gap_description": "MFA not enforced",
                    "remediation_due": "2026-09-01",
                }
            ]
        }
        assessment = _assessment(gap_report=gap_report)
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        gap_els = root.find("Gaps").findall("Gap")
        assert len(gap_els) == 1
        assert gap_els[0].attrib["measure_ref"] == "A.5.3"
        assert gap_els[0].attrib["severity"] == "high"

    def test_gap_report_missing_keys_default_to_empty_string(self):
        assessment = _assessment(gap_report={"gaps": [{}]})
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        gap_el = root.find("Gaps").findall("Gap")[0]
        assert gap_el.attrib["measure_ref"] == ""
        assert gap_el.attrib["severity"] == ""

    def test_gap_report_non_dict_is_ignored(self):
        assessment = _assessment(gap_report="not-a-dict")
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        assert len(root.find("Gaps").findall("Gap")) == 0

    def test_control_characters_stripped_from_title(self):
        controls = [_control(title="bad\x00title\x01")]
        xml_bytes = generate_nca_report(_assessment(), controls, _org())
        root = _parse(xml_bytes)
        assert root.find("Controls").find("Control").attrib["title"] == "badtitle"

    def test_enum_like_status_uses_value_attribute(self):
        status_enum = SimpleNamespace(value="in_progress")
        assessment = _assessment(status=status_enum)
        xml_bytes = generate_nca_report(assessment, [], _org())
        root = _parse(xml_bytes)
        assert root.find("Assessment").attrib["status"] == "in_progress"
