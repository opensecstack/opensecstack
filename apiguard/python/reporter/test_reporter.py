"""Unit tests for the Python reporter modules."""

from __future__ import annotations

import json

import pytest

from html_reporter import generate, _severity_badge, _status_badge

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

MINIMAL_REPORT: dict = {
    "scan": {
        "id": "scan-001",
        "target": "https://api.example.com",
        "spec_hash": "abc123",
        "started_at": "2026-03-01T10:00:00Z",
        "completed_at": "2026-03-01T10:05:00Z",
        "status": "completed",
    },
    "summary": {
        "total": 2,
        "critical": 1,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
        "modules_enabled": ["a1_bola", "a2_auth"],
    },
    "findings": [
        {
            "id": "f-001",
            "owasp_id": "API1:2023",
            "module_id": "a1_bola",
            "title": "BOLA — ID Enumeration",
            "description": "Predictable IDs allow object enumeration.",
            "severity": "CRITICAL",
            "cvss_score": 9.1,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "endpoint": "/api/v1/users/{id}",
            "method": "GET",
            "evidence": {"request": "GET /api/v1/users/2", "response": "HTTP 200"},
            "remediation": "Implement object-level authorisation.",
            "status": "open",
        },
        {
            "id": "f-002",
            "owasp_id": "API2:2023",
            "module_id": "a2_auth",
            "title": "Broken Authentication — Token not invalidated",
            "description": "Expired token still returns 200.",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cvss_vector": "",
            "endpoint": "/api/v1/profile",
            "method": "GET",
            "evidence": {"request": "GET /api/v1/profile", "response": "HTTP 200"},
            "remediation": "Enforce token expiry server-side.",
            "status": "open",
        },
    ],
    "metadata": {
        "apiguard_version": "0.2.0",
        "scan_duration": "5m0s",
        "report_generated_at": "2026-03-01T10:05:01Z",
    },
}


# ---------------------------------------------------------------------------
# html_reporter tests
# ---------------------------------------------------------------------------


class TestHTMLReporter:
    def test_returns_valid_html_string(self):
        out = generate(MINIMAL_REPORT)
        assert isinstance(out, str)
        assert out.startswith("<!DOCTYPE html>")

    def test_contains_scan_id(self):
        out = generate(MINIMAL_REPORT)
        assert "scan-001" in out

    def test_contains_target(self):
        out = generate(MINIMAL_REPORT)
        assert "api.example.com" in out

    def test_contains_finding_titles(self):
        out = generate(MINIMAL_REPORT)
        assert "BOLA" in out
        assert "Broken Authentication" in out

    def test_contains_severity_counts(self):
        out = generate(MINIMAL_REPORT)
        # Critical count should appear somewhere in stats
        assert ">1<" in out  # critical stat value

    def test_severity_badge_critical(self):
        badge = _severity_badge("CRITICAL")
        assert "#ef4444" in badge
        assert "CRITICAL" in badge

    def test_severity_badge_unknown(self):
        badge = _severity_badge("UNKNOWN")
        assert "UNKNOWN" in badge  # should not crash

    def test_status_badge_completed(self):
        badge = _status_badge("completed")
        assert "#22c55e" in badge

    def test_xss_escaping_in_title(self):
        report = json.loads(json.dumps(MINIMAL_REPORT))
        report["findings"][0]["title"] = "<script>alert(1)</script>"
        out = generate(report)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_empty_findings(self):
        report = json.loads(json.dumps(MINIMAL_REPORT))
        report["findings"] = []
        report["summary"]["total"] = 0
        out = generate(report)
        assert "No findings" in out

    def test_apiguard_version_in_footer(self):
        out = generate(MINIMAL_REPORT)
        assert "0.2.0" in out

    def test_owasp_ids_present(self):
        out = generate(MINIMAL_REPORT)
        assert "API1:2023" in out
        assert "API2:2023" in out

    def test_no_unfilled_template_placeholders(self):
        out = generate(MINIMAL_REPORT)
        assert "{{" not in out
        assert "}}" not in out


# ---------------------------------------------------------------------------
# reporter CLI tests
# ---------------------------------------------------------------------------


class TestReporterCLI:
    def test_html_output_to_stdout(self, capsys, tmp_path):
        import sys
        from reporter import main

        report_path = tmp_path / "scan.json"
        report_path.write_text(json.dumps(MINIMAL_REPORT), encoding="utf-8")

        ret = main(["--format", "html", "--input", str(report_path)])
        assert ret == 0
        captured = capsys.readouterr()
        assert "<!DOCTYPE html>" in captured.out

    def test_html_output_to_file(self, tmp_path):
        from reporter import main

        report_path = tmp_path / "scan.json"
        out_path = tmp_path / "report.html"
        report_path.write_text(json.dumps(MINIMAL_REPORT), encoding="utf-8")

        ret = main(["--format", "html", "--input", str(report_path), "--output", str(out_path)])
        assert ret == 0
        content = out_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_invalid_json_returns_nonzero(self, tmp_path):
        from reporter import main

        bad = tmp_path / "bad.json"
        bad.write_text("not json", encoding="utf-8")
        ret = main(["--format", "html", "--input", str(bad)])
        assert ret == 1

    def test_missing_input_file_returns_nonzero(self, tmp_path):
        from reporter import main

        ret = main(["--format", "html", "--input", str(tmp_path / "nonexistent.json")])
        assert ret == 1
