"""PDF report generator for APIGuard scan results.

Converts the HTML produced by `html_reporter` to a PDF using WeasyPrint.
WeasyPrint renders HTML+CSS faithfully, so the PDF matches the HTML report.

Usage:
    from pdf_reporter import generate, generate_from_file

    pdf_bytes = generate(report_dict)          # report_dict from Go JSON output
    pdf_bytes = generate_from_file("scan.json")
"""

from __future__ import annotations

import json
from typing import Any

from html_reporter import generate as _html_generate


def generate(report: dict[str, Any]) -> bytes:
    """Return a PDF bytestring for *report* (parsed Go JSON output).

    Raises ``ImportError`` with a helpful message if WeasyPrint is not installed.
    """
    try:
        from weasyprint import HTML  # type: ignore[import]
    except ImportError as exc:  # pragma: no cover
        raise ImportError(
            "WeasyPrint is required for PDF generation. "
            "Install it with: pip install weasyprint"
        ) from exc

    html_str = _html_generate(report)
    return HTML(string=html_str).write_pdf()


def generate_from_file(path: str) -> bytes:
    """Load a JSON report from *path* and return a PDF bytestring."""
    with open(path, encoding="utf-8") as fh:
        report = json.load(fh)
    return generate(report)
