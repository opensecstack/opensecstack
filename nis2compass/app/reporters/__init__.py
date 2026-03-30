"""Report generators for NIS2 Compass assessments."""
from .json_reporter import generate_json_report
from .sarif_reporter import generate_sarif_report

__all__ = ["generate_json_report", "generate_sarif_report"]
