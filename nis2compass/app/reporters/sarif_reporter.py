"""SARIF v2.1.0 report generator for NIS2 Compass assessments."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

# Maximum length for any user-supplied string embedded in a report (H11).
_MAX_FIELD_LEN = 500

# Strip ASCII control characters except TAB (0x09) and LF (0x0a) and CR (0x0d).
_CTRL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitise(s: object) -> str:
    """Remove control characters and truncate to _MAX_FIELD_LEN chars (H11)."""
    if s is None:
        return ""
    text = str(s.value if hasattr(s, "value") else s)
    text = _CTRL_CHAR_RE.sub("", text)
    return text[:_MAX_FIELD_LEN]


# Map NIS2 measure refs to SARIF rule IDs and metadata
NIS2_RULES = {
    "a": {
        "id": "NIS2-A21-a",
        "name": "RiskAnalysisAndSecurityPolicies",
        "short": "Risk Analysis & Information Security Policies",
    },
    "b": {"id": "NIS2-A21-b", "name": "IncidentHandling", "short": "Incident Handling"},
    "c": {"id": "NIS2-A21-c", "name": "BusinessContinuityAndDR", "short": "Business Continuity & Disaster Recovery"},
    "d": {"id": "NIS2-A21-d", "name": "AccessControlsAndAuthentication", "short": "Access Controls & Authentication"},
    "e": {"id": "NIS2-A21-e", "name": "Cryptography", "short": "Cryptography"},
    "f": {"id": "NIS2-A21-f", "name": "SupplyChainSecurity", "short": "Supply Chain Security"},
    "g": {"id": "NIS2-A21-g", "name": "LoggingAndMonitoring", "short": "Logging & Monitoring"},
    "h": {"id": "NIS2-A21-h", "name": "VulnerabilityManagement", "short": "Vulnerability Management"},
    "i": {"id": "NIS2-A21-i", "name": "SecurityTrainingAndAwareness", "short": "Security Training & Awareness"},
    "j": {"id": "NIS2-A21-j", "name": "TestingAndExercises", "short": "Testing & Exercises"},
}

# Map control status to SARIF level
STATUS_TO_LEVEL = {
    "non_compliant": "error",
    "partially_compliant": "warning",
    "not_assessed": "note",
    "compliant": "none",
    "not_applicable": "none",
}


def generate_sarif_report(assessment: Any, controls: list[Any], organisation: Any) -> bytes:
    """
    Generate a SARIF v2.1.0 compliance report.

    Non-compliant controls → level: error
    Partially compliant   → level: warning
    Not assessed          → level: note
    Compliant / N/A       → level: none (informational)

    Returns UTF-8 encoded JSON bytes.
    """

    def _str(val) -> str:
        """Convert enum/str to plain string; sanitise for injection safety (H11)."""
        if val is None:
            return ""
        return _sanitise(val)

    rules = []
    for ref, meta in NIS2_RULES.items():
        rules.append(
            {
                "id": meta["id"],
                "name": meta["name"],
                "shortDescription": {"text": meta["short"]},
                "fullDescription": {"text": f"NIS2 Article 21(2)({ref}) — {meta['short']}"},
                "helpUri": "https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555",
                "properties": {
                    "measure_ref": ref,
                    "framework": "NIS2 Directive",
                    "article": "Article 21(2)",
                },
            }
        )

    results = []
    for control in controls:
        ref = _str(getattr(control, "measure_ref", ""))
        status = _str(getattr(control, "status", "not_assessed"))
        level = STATUS_TO_LEVEL.get(status, "note")
        rule_meta = NIS2_RULES.get(ref, {"id": f"NIS2-A21-{ref}", "short": ref})

        message_parts = [f"NIS2 Article 21(2)({ref}): {rule_meta['short']} — status: {status}"]
        if gap := getattr(control, "gap_description", None):
            message_parts.append(f"Gap: {gap}")
        if plan := getattr(control, "remediation_plan", None):
            message_parts.append(f"Remediation: {plan}")

        result = {
            "ruleId": rule_meta["id"],
            "level": level,
            "message": {"text": " | ".join(message_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"nis2://assessments/{assessment.id}/controls/{ref}",
                            "uriBaseId": "NIS2COMPASS",
                        }
                    }
                }
            ],
            "properties": {
                "status": status,
                "risk_score": getattr(control, "risk_score", None),
                "remediation_owner": _sanitise(getattr(control, "remediation_owner", None)),
                "remediation_due": _sanitise(str(getattr(control, "remediation_due", "") or "")),
                "external_ticket_url": _sanitise(getattr(control, "external_ticket_url", None)),
                "organisation": _sanitise(organisation.name),
                "assessment_title": _sanitise(assessment.title),
            },
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "NIS2 Compass",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/opensecstack/opensecstack",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                        "properties": {
                            "organisation_id": str(organisation.id),
                            "assessment_id": str(assessment.id),
                            "framework": "NIS2 Directive Article 21(2)",
                        },
                    }
                ],
            }
        ],
    }

    return json.dumps(sarif, indent=2, default=str).encode("utf-8")
