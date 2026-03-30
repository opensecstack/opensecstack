"""JSON report generator for NIS2 Compass assessments."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


def generate_json_report(assessment: Any, controls: list[Any], organisation: Any) -> bytes:
    """
    Generate a JSON compliance report.

    Returns UTF-8 encoded JSON bytes.

    The report structure:
    {
        "schema_version": "1.0",
        "generated_at": "<ISO-8601 UTC>",
        "report_type": "nis2_compliance",
        "organisation": {
            "id": "<uuid>",
            "name": "<str>",
            "country": "<ISO-3166-1 alpha-2>",
            "sector": "<str>",
            "entity_type": "essential|important"
        },
        "assessment": {
            "id": "<uuid>",
            "title": "<str>",
            "status": "<str>",
            "framework_version": "<str>",
            "assessor": "<str>",
            "scope": "<str>",
            "due_date": "<ISO-8601 or null>",
            "completed_at": "<ISO-8601 or null>",
            "created_at": "<ISO-8601>",
            "updated_at": "<ISO-8601>"
        },
        "summary": {
            "total_controls": <int>,
            "compliant": <int>,
            "partially_compliant": <int>,
            "non_compliant": <int>,
            "not_applicable": <int>,
            "not_assessed": <int>,
            "overall_compliance_pct": <float 0-100>
        },
        "controls": [
            {
                "measure_ref": "a",
                "title": "<str>",
                "description": "<str>",
                "nist_category": "identify|protect|detect|respond|recover",
                "status": "<str>",
                "risk_score": <0-10 or null>,
                "gap_description": "<str or null>",
                "remediation_plan": "<str or null>",
                "remediation_due": "<ISO-8601 or null>",
                "remediation_owner": "<str or null>",
                "remediation_status": "<str or null>",
                "external_ticket_url": "<str or null>",
                "assessed_by": "<str or null>",
                "assessed_at": "<ISO-8601 or null>",
                "evidence": <object or null>,
                "artifact_count": <int>
            }
        ]
    }
    """
    now = datetime.now(timezone.utc).isoformat()

    # Tally statuses
    status_counts = {
        "compliant": 0,
        "partially_compliant": 0,
        "non_compliant": 0,
        "not_applicable": 0,
        "not_assessed": 0,
    }
    for c in controls:
        status = getattr(c, "status", None) or "not_assessed"
        key = str(status.value if hasattr(status, "value") else status)
        if key in status_counts:
            status_counts[key] += 1
        else:
            status_counts["not_assessed"] += 1

    assessed = status_counts["compliant"] + status_counts["partially_compliant"] + status_counts["non_compliant"]
    total = len(controls)
    compliance_pct = round((status_counts["compliant"] / total * 100) if total > 0 else 0.0, 1)

    def _isoformat(val) -> str | None:
        if val is None:
            return None
        if hasattr(val, "isoformat"):
            return val.isoformat()
        return str(val)

    def _str(val) -> str | None:
        if val is None:
            return None
        return str(val.value if hasattr(val, "value") else val)

    report = {
        "schema_version": "1.0",
        "generated_at": now,
        "report_type": "nis2_compliance",
        "organisation": {
            "id": str(organisation.id),
            "name": organisation.name,
            "country": getattr(organisation, "country", None),
            "sector": getattr(organisation, "sector", None),
            "entity_type": _str(getattr(organisation, "entity_type", None)),
        },
        "assessment": {
            "id": str(assessment.id),
            "title": assessment.title,
            "status": _str(assessment.status),
            "framework_version": getattr(assessment, "framework_version", None),
            "assessor": getattr(assessment, "assessor", None),
            "scope": getattr(assessment, "scope", None),
            "due_date": _isoformat(getattr(assessment, "due_date", None)),
            "completed_at": _isoformat(getattr(assessment, "completed_at", None)),
            "created_at": _isoformat(assessment.created_at),
            "updated_at": _isoformat(assessment.updated_at),
        },
        "summary": {
            "total_controls": total,
            **status_counts,
            "overall_compliance_pct": compliance_pct,
        },
        "controls": [
            {
                "measure_ref": _str(c.measure_ref),
                "title": getattr(c, "title", None),
                "description": getattr(c, "description", None),
                "nist_category": _str(getattr(c, "nist_category", None)),
                "status": _str(c.status),
                "risk_score": getattr(c, "risk_score", None),
                "gap_description": getattr(c, "gap_description", None),
                "remediation_plan": getattr(c, "remediation_plan", None),
                "remediation_due": _isoformat(getattr(c, "remediation_due", None)),
                "remediation_owner": getattr(c, "remediation_owner", None),
                "remediation_status": _str(getattr(c, "remediation_status", None)),
                "external_ticket_url": getattr(c, "external_ticket_url", None),
                "assessed_by": getattr(c, "assessed_by", None),
                "assessed_at": _isoformat(getattr(c, "assessed_at", None)),
                "evidence": c.evidence if isinstance(c.evidence, dict) else None,
                "artifact_count": len(getattr(c, "artifacts", []) or []),
            }
            for c in controls
        ],
    }

    return json.dumps(report, indent=2, default=str).encode("utf-8")
