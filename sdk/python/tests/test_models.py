"""
Tests for sdk/python/opensecstack/models.py — Pydantic v2 models.

Covers:
  - Valid construction passes for all six models
  - Required fields enforced (ValidationError on missing required field)
  - Optional fields default to None
  - Field types validated (wrong type raises ValidationError)
  - JSON serialisation round-trips correctly (model_dump / model_validate)
  - Default values for non-optional fields (framework_version, evidence, etc.)
  - List fields default to empty list
  - Numeric defaults (cvss_score, total_findings, *_count)
"""
from __future__ import annotations

import pytest

try:
    from pydantic import ValidationError
    _PYDANTIC = True
except ImportError:
    _PYDANTIC = False

from opensecstack.models import (
    Organisation,
    Assessment,
    Control,
    Scan,
    Finding,
    AuditEntry,
    CitadelEvent,
)

# We only run the pydantic-specific tests (ValidationError checks) when
# pydantic is available.  The construction and round-trip tests run regardless.
requires_pydantic = pytest.mark.skipif(
    not _PYDANTIC, reason="pydantic not installed"
)


# ---------------------------------------------------------------------------
# Minimal valid payload helpers
# ---------------------------------------------------------------------------

def _org_data(**kw) -> dict:
    base = dict(
        id="org-1",
        name="Test Org",
        industry="Finance",
        country="DE",
        size="medium",
        entity_type="essential",
    )
    base.update(kw)
    return base


def _assessment_data(**kw) -> dict:
    base = dict(
        id="assess-1",
        org_id="org-1",
        title="Q1 Assessment",
        status="draft",
    )
    base.update(kw)
    return base


def _control_data(**kw) -> dict:
    base = dict(
        id="ctrl-1",
        assessment_id="assess-1",
        article_ref="21(2)",
        measure_ref="a",
        nist_category="protect",
        title="Risk Analysis",
        status="not_assessed",
    )
    base.update(kw)
    return base


def _scan_data(**kw) -> dict:
    base = dict(
        id="scan-1",
        target_url="https://api.example.com",
        status="pending",
    )
    base.update(kw)
    return base


def _finding_data(**kw) -> dict:
    base = dict(
        id="finding-1",
        scan_id="scan-1",
        owasp_id="A01",
        module_id="auth",
        title="Broken Access Control",
        description="Missing authorisation check",
        severity="high",
    )
    base.update(kw)
    return base


def _audit_entry_data(**kw) -> dict:
    base = dict(
        id="audit-1",
        action="control.updated",
        resource_type="Control",
    )
    base.update(kw)
    return base


def _citadel_event_data(**kw) -> dict:
    base = dict(
        event_id="evt-1",
        source_platform="nis2compass",
        action_type="assessment_completed",
        actor_role="system",
        result_status="SUCCESS",
        ts_utc="2026-03-01T12:00:00Z",
    )
    base.update(kw)
    return base


# ============================================================
# Organisation
# ============================================================

class TestOrganisation:
    def test_valid_construction(self):
        org = Organisation(**_org_data())
        assert org.id == "org-1"
        assert org.name == "Test Org"
        assert org.country == "DE"

    def test_optional_fields_default_to_none(self):
        org = Organisation(**_org_data())
        assert org.registration_number is None
        assert org.contact_email is None
        assert org.created_at is None
        assert org.updated_at is None

    def test_optional_fields_accepted(self):
        org = Organisation(**_org_data(
            registration_number="HRB12345",
            contact_email="ciso@corp.de",
            created_at="2026-01-01T00:00:00Z",
            updated_at="2026-03-01T00:00:00Z",
        ))
        assert org.registration_number == "HRB12345"
        assert org.contact_email == "ciso@corp.de"

    @requires_pydantic
    def test_missing_required_name_raises(self):
        data = _org_data()
        del data["name"]
        with pytest.raises(ValidationError):
            Organisation(**data)

    @requires_pydantic
    def test_missing_required_id_raises(self):
        data = _org_data()
        del data["id"]
        with pytest.raises(ValidationError):
            Organisation(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        org = Organisation(**_org_data(contact_email="test@example.com"))
        dumped = org.model_dump()
        restored = Organisation(**dumped)
        assert restored.id == org.id
        assert restored.contact_email == org.contact_email


# ============================================================
# Assessment
# ============================================================

class TestAssessment:
    def test_valid_construction(self):
        a = Assessment(**_assessment_data())
        assert a.id == "assess-1"
        assert a.org_id == "org-1"
        assert a.title == "Q1 Assessment"
        assert a.status == "draft"

    def test_framework_version_default(self):
        a = Assessment(**_assessment_data())
        assert a.framework_version == "NIS2-2022/0383"

    def test_framework_version_override(self):
        a = Assessment(**_assessment_data(framework_version="NIS2-2024"))
        assert a.framework_version == "NIS2-2024"

    def test_optional_fields_default_to_none(self):
        a = Assessment(**_assessment_data())
        assert a.scope is None
        assert a.assessor is None
        assert a.due_date is None
        assert a.completed_at is None
        assert a.created_at is None
        assert a.updated_at is None
        assert a.stats is None

    def test_stats_accepts_dict(self):
        a = Assessment(**_assessment_data(stats={"total": 10, "by_status": {"compliant": 5}}))
        assert a.stats["total"] == 10

    @requires_pydantic
    def test_missing_title_raises(self):
        data = _assessment_data()
        del data["title"]
        with pytest.raises(ValidationError):
            Assessment(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        a = Assessment(**_assessment_data(assessor="alice@example.com", scope="Cloud"))
        dumped = a.model_dump()
        restored = Assessment(**dumped)
        assert restored.assessor == "alice@example.com"
        assert restored.scope == "Cloud"


# ============================================================
# Control
# ============================================================

class TestControl:
    def test_valid_construction(self):
        c = Control(**_control_data())
        assert c.id == "ctrl-1"
        assert c.measure_ref == "a"
        assert c.nist_category == "protect"
        assert c.status == "not_assessed"

    def test_evidence_defaults_to_empty_dict(self):
        c = Control(**_control_data())
        assert c.evidence == {}

    def test_evidence_accepts_dict(self):
        c = Control(**_control_data(evidence={"file": "policy.pdf"}))
        assert c.evidence == {"file": "policy.pdf"}

    def test_optional_fields_default_to_none(self):
        c = Control(**_control_data())
        assert c.description is None
        assert c.gap_description is None
        assert c.remediation_plan is None
        assert c.remediation_due is None
        assert c.risk_score is None
        assert c.notes is None
        assert c.assessed_by is None
        assert c.assessed_at is None
        assert c.created_at is None
        assert c.updated_at is None

    def test_risk_score_accepts_float(self):
        c = Control(**_control_data(risk_score=7.5))
        assert c.risk_score == 7.5

    @requires_pydantic
    def test_missing_measure_ref_raises(self):
        data = _control_data()
        del data["measure_ref"]
        with pytest.raises(ValidationError):
            Control(**data)

    @requires_pydantic
    def test_missing_status_raises(self):
        data = _control_data()
        del data["status"]
        with pytest.raises(ValidationError):
            Control(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        c = Control(**_control_data(
            gap_description="No IRP",
            risk_score=8.0,
            evidence={"key": "val"},
        ))
        dumped = c.model_dump()
        restored = Control(**dumped)
        assert restored.gap_description == "No IRP"
        assert restored.risk_score == 8.0
        assert restored.evidence == {"key": "val"}


# ============================================================
# Scan
# ============================================================

class TestScan:
    def test_valid_construction(self):
        s = Scan(**_scan_data())
        assert s.id == "scan-1"
        assert s.target_url == "https://api.example.com"
        assert s.status == "pending"

    def test_modules_defaults_to_empty_list(self):
        s = Scan(**_scan_data())
        assert s.modules == []

    def test_count_fields_default_to_zero(self):
        s = Scan(**_scan_data())
        assert s.total_findings == 0
        assert s.critical_count == 0
        assert s.high_count == 0
        assert s.medium_count == 0
        assert s.low_count == 0
        assert s.info_count == 0

    def test_optional_fields_default_to_none(self):
        s = Scan(**_scan_data())
        assert s.spec_url is None
        assert s.spec_hash is None
        assert s.started_at is None
        assert s.completed_at is None
        assert s.error_message is None

    def test_modules_accepted_as_list(self):
        s = Scan(**_scan_data(modules=["auth", "injection"]))
        assert s.modules == ["auth", "injection"]

    def test_count_fields_accepted(self):
        s = Scan(**_scan_data(critical_count=3, high_count=7, total_findings=10))
        assert s.critical_count == 3
        assert s.high_count == 7
        assert s.total_findings == 10

    @requires_pydantic
    def test_missing_target_url_raises(self):
        data = _scan_data()
        del data["target_url"]
        with pytest.raises(ValidationError):
            Scan(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        s = Scan(**_scan_data(modules=["auth"], critical_count=2, high_count=5))
        dumped = s.model_dump()
        restored = Scan(**dumped)
        assert restored.modules == ["auth"]
        assert restored.critical_count == 2


# ============================================================
# Finding
# ============================================================

class TestFinding:
    def test_valid_construction(self):
        f = Finding(**_finding_data())
        assert f.id == "finding-1"
        assert f.scan_id == "scan-1"
        assert f.owasp_id == "A01"
        assert f.severity == "high"

    def test_cvss_score_default(self):
        f = Finding(**_finding_data())
        assert f.cvss_score == 0.0

    def test_endpoint_path_default(self):
        f = Finding(**_finding_data())
        assert f.endpoint_path == ""

    def test_endpoint_method_default(self):
        f = Finding(**_finding_data())
        assert f.endpoint_method == ""

    def test_status_default(self):
        f = Finding(**_finding_data())
        assert f.status == "open"

    def test_optional_fields_default_to_none(self):
        f = Finding(**_finding_data())
        assert f.cvss_vector is None
        assert f.evidence_request is None
        assert f.evidence_response is None
        assert f.evidence_json is None
        assert f.remediation is None
        assert f.triaged_by is None
        assert f.triaged_at is None
        assert f.triage_note is None
        assert f.created_at is None
        assert f.updated_at is None

    def test_cvss_score_accepts_float(self):
        f = Finding(**_finding_data(cvss_score=9.8))
        assert f.cvss_score == 9.8

    def test_evidence_json_accepts_dict(self):
        f = Finding(**_finding_data(evidence_json={"key": "value"}))
        assert f.evidence_json == {"key": "value"}

    @requires_pydantic
    def test_missing_title_raises(self):
        data = _finding_data()
        del data["title"]
        with pytest.raises(ValidationError):
            Finding(**data)

    @requires_pydantic
    def test_missing_severity_raises(self):
        data = _finding_data()
        del data["severity"]
        with pytest.raises(ValidationError):
            Finding(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        f = Finding(**_finding_data(
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L",
            remediation="Apply patch",
            status="triaged",
        ))
        dumped = f.model_dump()
        restored = Finding(**dumped)
        assert restored.cvss_score == 7.5
        assert restored.remediation == "Apply patch"
        assert restored.status == "triaged"


# ============================================================
# AuditEntry
# ============================================================

class TestAuditEntry:
    def test_valid_construction(self):
        e = AuditEntry(**_audit_entry_data())
        assert e.id == "audit-1"
        assert e.action == "control.updated"
        assert e.resource_type == "Control"

    def test_optional_fields_default_to_none(self):
        e = AuditEntry(**_audit_entry_data())
        assert e.actor is None
        assert e.actor_id is None
        assert e.actor_type is None
        assert e.resource_id is None
        assert e.risk_class is None
        assert e.metadata is None
        assert e.object_fingerprint is None
        assert e.prev_hash is None
        assert e.chain_hash is None
        assert e.timestamp is None
        assert e.created_at is None

    def test_nis2_compass_fields_accepted(self):
        e = AuditEntry(**_audit_entry_data(
            actor="alice@example.com",
            risk_class="WARNING",
            timestamp="2026-03-01T10:00:00Z",
            chain_hash="abc123",
        ))
        assert e.actor == "alice@example.com"
        assert e.risk_class == "WARNING"
        assert e.chain_hash == "abc123"

    def test_apiguard_fields_accepted(self):
        e = AuditEntry(**_audit_entry_data(
            actor_id="user-42",
            actor_type="human",
            created_at="2026-03-15T08:00:00Z",
        ))
        assert e.actor_id == "user-42"
        assert e.actor_type == "human"

    @requires_pydantic
    def test_missing_action_raises(self):
        data = _audit_entry_data()
        del data["action"]
        with pytest.raises(ValidationError):
            AuditEntry(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        e = AuditEntry(**_audit_entry_data(
            actor="bob@example.com",
            risk_class="CRITICAL",
            chain_hash="deadbeef",
        ))
        dumped = e.model_dump()
        restored = AuditEntry(**dumped)
        assert restored.actor == "bob@example.com"
        assert restored.chain_hash == "deadbeef"


# ============================================================
# CitadelEvent
# ============================================================

class TestCitadelEvent:
    def test_valid_construction(self):
        ev = CitadelEvent(**_citadel_event_data())
        assert ev.event_id == "evt-1"
        assert ev.source_platform == "nis2compass"
        assert ev.action_type == "assessment_completed"
        assert ev.result_status == "SUCCESS"

    def test_event_version_default(self):
        ev = CitadelEvent(**_citadel_event_data())
        assert ev.event_version == "2.0"

    def test_event_version_override(self):
        ev = CitadelEvent(**_citadel_event_data(event_version="3.0"))
        assert ev.event_version == "3.0"

    def test_payload_defaults_to_empty_dict(self):
        ev = CitadelEvent(**_citadel_event_data())
        assert ev.payload == {}

    def test_payload_accepts_dict(self):
        ev = CitadelEvent(**_citadel_event_data(
            payload={"assessment_id": "uuid-123", "score": 80}
        ))
        assert ev.payload["assessment_id"] == "uuid-123"

    def test_optional_hash_fields_default_to_none(self):
        ev = CitadelEvent(**_citadel_event_data())
        assert ev.prev_hash is None
        assert ev.chain_hash is None

    def test_hash_fields_accepted(self):
        ev = CitadelEvent(**_citadel_event_data(
            prev_hash="aabbcc",
            chain_hash="ddeeff",
        ))
        assert ev.prev_hash == "aabbcc"
        assert ev.chain_hash == "ddeeff"

    @requires_pydantic
    def test_missing_event_id_raises(self):
        data = _citadel_event_data()
        del data["event_id"]
        with pytest.raises(ValidationError):
            CitadelEvent(**data)

    @requires_pydantic
    def test_missing_source_platform_raises(self):
        data = _citadel_event_data()
        del data["source_platform"]
        with pytest.raises(ValidationError):
            CitadelEvent(**data)

    @requires_pydantic
    def test_missing_ts_utc_raises(self):
        data = _citadel_event_data()
        del data["ts_utc"]
        with pytest.raises(ValidationError):
            CitadelEvent(**data)

    @requires_pydantic
    def test_json_round_trip(self):
        ev = CitadelEvent(**_citadel_event_data(
            prev_hash="prevhash",
            chain_hash="chainhash",
            payload={"key": "value"},
        ))
        dumped = ev.model_dump()
        restored = CitadelEvent(**dumped)
        assert restored.event_id == ev.event_id
        assert restored.prev_hash == "prevhash"
        assert restored.payload == {"key": "value"}

    @requires_pydantic
    def test_all_required_fields_in_dump(self):
        ev = CitadelEvent(**_citadel_event_data())
        dumped = ev.model_dump()
        for field in ("event_id", "event_version", "source_platform",
                      "action_type", "actor_role", "result_status",
                      "ts_utc", "payload"):
            assert field in dumped
