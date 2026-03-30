"""HTML report generator for APIGuard scan results.

Reads the JSON report produced by the Go JSONReporter and renders a
self-contained HTML document.  All styles are inlined so the file can be
opened without a web server or any external assets.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS: dict[str, str] = {
    "CRITICAL": "#ef4444",
    "HIGH": "#f97316",
    "MEDIUM": "#eab308",
    "LOW": "#22c55e",
    "INFO": "#3b82f6",
}

STATUS_COLORS: dict[str, str] = {
    "completed": "#22c55e",
    "failed": "#ef4444",
    "running": "#818cf8",
    "pending": "#94a3b8",
    "cancelled": "#94a3b8",
}


def _badge(text: str, color: str) -> str:
    bg = color + "22"
    border = color + "66"
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {border};'
        f'border-radius:4px;padding:2px 8px;font-size:12px;font-weight:600;'
        f'text-transform:uppercase;letter-spacing:.05em">{html.escape(text)}</span>'
    )


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.upper(), "#94a3b8")
    return _badge(severity, color)


def _status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status.lower(), "#94a3b8")
    return _badge(status, color)


# ---------------------------------------------------------------------------
# Page sections
# ---------------------------------------------------------------------------

_STYLES = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0f172a; color: #e2e8f0; line-height: 1.6; }
.container { max-width: 1100px; margin: 0 auto; padding: 32px 24px; }
h1 { font-size: 28px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
h2 { font-size: 18px; font-weight: 600; color: #cbd5e1; margin: 32px 0 16px; }
h3 { font-size: 15px; font-weight: 600; color: #94a3b8; margin-bottom: 8px; }
.subtitle { color: #64748b; font-size: 14px; margin-bottom: 32px; }
.card { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
        padding: 20px; margin-bottom: 16px; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
         gap: 12px; margin-bottom: 32px; }
.stat { background: #1e293b; border: 1px solid #334155; border-radius: 8px;
        padding: 16px; text-align: center; }
.stat-value { font-size: 32px; font-weight: 700; }
.stat-label { font-size: 12px; color: #94a3b8; text-transform: uppercase;
              letter-spacing: .05em; margin-top: 4px; }
.stat.critical .stat-value { color: #ef4444; }
.stat.high     .stat-value { color: #f97316; }
.stat.medium   .stat-value { color: #eab308; }
.stat.low      .stat-value { color: #22c55e; }
.stat.info     .stat-value { color: #3b82f6; }
table { width: 100%; border-collapse: collapse; font-size: 14px; }
th { text-align: left; padding: 10px 12px; color: #64748b; font-size: 12px;
     text-transform: uppercase; letter-spacing: .05em;
     border-bottom: 1px solid #334155; }
td { padding: 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }
tr:last-child td { border-bottom: none; }
.finding-title { font-weight: 600; color: #f1f5f9; font-size: 14px; }
.finding-desc  { color: #94a3b8; font-size: 13px; margin-top: 4px; }
.finding-remediation { color: #64748b; font-size: 12px; margin-top: 6px;
                        font-style: italic; }
.endpoint { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 13px;
             color: #94a3b8; }
.method { font-weight: 700; margin-right: 6px; }
.meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.meta-item { font-size: 13px; }
.meta-item .label { color: #64748b; margin-bottom: 2px; font-size: 11px;
                     text-transform: uppercase; letter-spacing: .05em; }
.meta-item .value { color: #e2e8f0; font-family: monospace; }
.chain-ok   { color: #22c55e; }
.chain-fail { color: #ef4444; }
footer { margin-top: 48px; text-align: center; font-size: 12px; color: #334155; }
"""


def _render_meta(report: dict[str, Any]) -> str:
    scan = report.get("scan", {})
    meta = report.get("metadata", {})
    status_color = STATUS_COLORS.get(scan.get("status", "").lower(), "#94a3b8")
    items = [
        ("Scan ID", scan.get("id", "—")),
        ("Target", scan.get("target", "—")),
        ("Status", _status_badge(scan.get("status", "—"))),
        ("Started", scan.get("started_at", "—")),
        ("Completed", scan.get("completed_at", "—")),
        ("Duration", meta.get("scan_duration", "—")),
        ("Spec Hash", (scan.get("spec_hash") or "—")[:16] + "…" if scan.get("spec_hash") else "—"),
        ("APIGuard Version", meta.get("apiguard_version", "—")),
    ]
    cells = "".join(
        f'<div class="meta-item"><div class="label">{html.escape(label)}</div>'
        f'<div class="value">{value}</div></div>'
        for label, value in items
    )
    return f'<div class="card"><h2 style="margin-top:0">Scan Details</h2><div class="meta-grid">{cells}</div></div>'


def _render_summary(summary: dict[str, Any]) -> str:
    stats = [
        ("critical", "Critical", summary.get("critical", 0)),
        ("high",     "High",     summary.get("high", 0)),
        ("medium",   "Medium",   summary.get("medium", 0)),
        ("low",      "Low",      summary.get("low", 0)),
        ("info",     "Info",     summary.get("info", 0)),
    ]
    cells = "".join(
        f'<div class="stat {cls}">'
        f'<div class="stat-value">{count}</div>'
        f'<div class="stat-label">{label}</div>'
        f'</div>'
        for cls, label, count in stats
    )
    return f'<div class="stats">{cells}</div>'


def _render_finding_row(f: dict[str, Any]) -> str:
    sev = f.get("severity", "INFO").upper()
    endpoint = (
        f'<span class="method">{html.escape(f.get("method", ""))}</span>'
        f'{html.escape(f.get("endpoint", ""))}'
    )
    cvss = f.get("cvss_score", 0.0)
    cvss_str = f"{cvss:.1f}" if cvss else "—"

    return (
        f"<tr>"
        f"<td>{_severity_badge(sev)}</td>"
        f"<td>"
        f'<div class="finding-title">{html.escape(f.get("title", ""))}</div>'
        f'<div class="finding-desc">{html.escape(f.get("description", ""))}</div>'
        f'<div class="finding-remediation">{html.escape(f.get("remediation", ""))}</div>'
        f"</td>"
        f'<td><span class="endpoint">{endpoint}</span></td>'
        f"<td>{html.escape(f.get("owasp_id", ""))}</td>"
        f"<td>{cvss_str}</td>"
        f"</tr>"
    )


def _render_findings(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return '<div class="card" style="color:#64748b;text-align:center">No findings.</div>'

    # Sort by severity then CVSS descending.
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    sorted_findings = sorted(
        findings,
        key=lambda x: (order.get(x.get("severity", "INFO").upper(), 5), -(x.get("cvss_score") or 0)),
    )

    rows = "".join(_render_finding_row(f) for f in sorted_findings)
    return (
        '<div class="card" style="padding:0;overflow:hidden">'
        "<table>"
        "<thead><tr>"
        "<th>Severity</th><th>Finding</th><th>Endpoint</th>"
        "<th>OWASP ID</th><th>CVSS</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody>"
        "</table></div>"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate(report: dict[str, Any]) -> str:
    """Render *report* (parsed JSON from Go's JSONReporter) as an HTML string."""
    summary = report.get("summary", {})
    findings = report.get("findings", [])
    meta = report.get("metadata", {})
    generated_at = meta.get("report_generated_at", datetime.now(timezone.utc).isoformat())

    body = (
        f'<div class="container">'
        f'<h1>APIGuard Security Report</h1>'
        f'<p class="subtitle">Generated {html.escape(generated_at)}</p>'
        + _render_meta(report)
        + "<h2>Summary</h2>"
        + _render_summary(summary)
        + f"<h2>Findings ({summary.get('total', 0)})</h2>"
        + _render_findings(findings)
        + f'<footer>APIGuard {html.escape(meta.get("apiguard_version", ""))} &mdash; '
        f"OpenSecStack</footer>"
        f"</div>"
    )

    return (
        "<!DOCTYPE html>"
        '<html lang="en">'
        "<head>"
        '<meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>APIGuard Report</title>"
        f"<style>{_STYLES}</style>"
        "</head>"
        f"<body>{body}</body>"
        "</html>"
    )


def generate_from_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    return generate(report)
