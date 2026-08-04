"""NCA (National Competent Authority) XML report generator for NIS2 Compass assessments."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

# Strip ASCII control characters except TAB (0x09) and LF (0x0a) and CR (0x0d)
_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_FIELD_LEN = 500


def _sanitise(s: object) -> str:
    """Remove control characters and truncate to _MAX_FIELD_LEN chars."""
    if s is None:
        return ""
    text = str(s.value if hasattr(s, "value") else s)
    text = _CTRL_CHAR_RE.sub("", text)
    return text[:_MAX_FIELD_LEN]


def _isoformat(val) -> str:
    if val is None:
        return ""
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


def generate_nca_report(assessment: Any, controls: list[Any], organisation: Any) -> bytes:
    """
    Generate an NCA XML compliance report.

    Returns UTF-8 encoded XML bytes.
    """
    now = datetime.now(timezone.utc).isoformat()

    root = ET.Element(
        "NCAReport",
        attrib={
            "version": "1.0",
            "generated_at": now,
            "organisation": _sanitise(organisation.name),
        },
    )

    # ── Assessment element ────────────────────────────────────────────────────
    assessment_el = ET.SubElement(
        root,
        "Assessment",
        attrib={
            "id": str(assessment.id),
            "title": _sanitise(assessment.title),
            "status": _sanitise(assessment.status),
            "period_start": _isoformat(getattr(assessment, "created_at", None)),
            "period_end": _isoformat(
                getattr(assessment, "completed_at", None) or getattr(assessment, "due_date", None)
            ),
            "compliance_score": (
                str(float(assessment.compliance_score)) if assessment.compliance_score is not None else ""
            ),
        },
    )

    # ── Controls section ──────────────────────────────────────────────────────
    controls_el = ET.SubElement(root, "Controls")
    for c in controls:
        evidence_count = len(c.evidence) if isinstance(c.evidence, dict) else 0
        ET.SubElement(
            controls_el,
            "Control",
            attrib={
                "ref": _sanitise(c.measure_ref),
                "title": _sanitise(c.title),
                "status": _sanitise(c.status),
                "notes": _sanitise(c.notes),
                "evidence_count": str(evidence_count),
                "remediation_due_date": _isoformat(getattr(c, "remediation_due", None)),
            },
        )

    # ── Gaps section ──────────────────────────────────────────────────────────
    gaps_el = ET.SubElement(root, "Gaps")
    gap_report = getattr(assessment, "gap_report", None)
    if gap_report and isinstance(gap_report, dict):
        for gap in gap_report.get("gaps", []):
            ET.SubElement(
                gaps_el,
                "Gap",
                attrib={
                    "measure_ref": _sanitise(gap.get("measure_ref", "")),
                    "title": _sanitise(gap.get("title", "")),
                    "status": _sanitise(gap.get("status", "")),
                    "severity": _sanitise(gap.get("severity", "")),
                    "gap_description": _sanitise(gap.get("gap_description", "")),
                    "remediation_due": _sanitise(gap.get("remediation_due", "")),
                },
            )

    ET.indent(root, space="  ")
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode").encode("utf-8")
