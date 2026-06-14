from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from advisory.csaf import (
    IncidentInput,
    ProductIdentifier,
    Publisher,
    TrackingId,
    build_csaf,
    to_jsonable,
)


def _publisher() -> Publisher:
    return Publisher(
        category="coordinator",
        name="OpenCSIRT",
        namespace="https://opencsirt.test",
        contact_details="csirt@opencsirt.test",
    )


def test_tracking_id_validates_charset() -> None:
    TrackingId(text="OPENCSIRT-2026-0001")
    with pytest.raises(ValidationError):
        TrackingId(text="invalid id with spaces")
    with pytest.raises(ValidationError):
        TrackingId(text="")


def test_build_csaf_minimal_incident() -> None:
    incident = IncidentInput(
        title="Test incident",
        summary="One-line summary",
    )
    doc = build_csaf(
        incident, publisher=_publisher(), now=datetime(2026, 5, 9, tzinfo=UTC)
    )
    rendered = to_jsonable(doc)
    assert rendered["document"]["category"] == "csaf_security_incident_response"
    assert rendered["document"]["csaf_version"] == "2.0"
    assert rendered["document"]["distribution"]["tlp"]["label"] == "AMBER"
    assert rendered["document"]["tracking"]["id"].startswith("OPENCSIRT-20260509-")
    assert rendered["document"]["tracking"]["revision_history"][0]["number"] == "1"


def test_build_csaf_with_cves_and_iocs() -> None:
    incident = IncidentInput(
        title="CVE round-up",
        summary="Multiple",
        cve_ids=["CVE-2026-1111", "CVE-2026-2222"],
        iocs=["198.51.100.7", "evil.example.com"],
        affected_products=[ProductIdentifier(product_id="P1", name="WidgetCo Server 1.2")],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2026-1111"],
        tlp="GREEN",
    )
    doc = build_csaf(incident, publisher=_publisher())
    rendered = to_jsonable(doc)
    assert len(rendered["vulnerabilities"]) == 2
    assert rendered["vulnerabilities"][0]["cve"] == "CVE-2026-1111"
    assert rendered["product_tree"]["full_product_names"][0]["product_id"] == "P1"
    notes = {n["category"] for n in rendered["document"]["notes"]}
    assert {"summary", "details"}.issubset(notes)
    assert rendered["document"]["distribution"]["tlp"]["label"] == "GREEN"


def test_build_csaf_honours_advisory_id_override() -> None:
    incident = IncidentInput(
        title="title",
        summary="summary",
        advisory_id="VENDOR-2026-0001",
    )
    doc = build_csaf(incident, publisher=_publisher())
    assert doc.document.tracking.id == "VENDOR-2026-0001"


def test_build_csaf_rejects_invalid_advisory_id() -> None:
    incident = IncidentInput(
        title="title",
        summary="summary",
        advisory_id="not valid because spaces",
    )
    with pytest.raises(ValidationError):
        build_csaf(incident, publisher=_publisher())


def test_build_csaf_rejects_invalid_tlp() -> None:
    with pytest.raises(ValidationError):
        IncidentInput(title="title", summary="summary", tlp="ORANGE")  # type: ignore[arg-type]
