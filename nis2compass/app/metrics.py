"""
Prometheus metrics for NIS2 Compass.

Exposes HTTP request metrics (count, latency, in-flight) at GET /metrics.
Uses prometheus_flask_exporter for automatic Flask integration.
"""

from __future__ import annotations

from prometheus_flask_exporter import PrometheusMetrics

# Module-level singleton — initialised by init_metrics().
_metrics: PrometheusMetrics | None = None


def init_metrics(app) -> PrometheusMetrics:
    """Initialise and register Prometheus metrics on the Flask app.

    Call once from the application factory (create_app). Subsequent calls
    are no-ops and return the existing instance.
    """
    global _metrics
    if _metrics is not None:
        return _metrics

    _metrics = PrometheusMetrics(
        app,
        default_labels={"service": "nis2compass"},
        export_defaults=True,
        group_by="endpoint",
    )

    # Custom application metrics
    _metrics.info("nis2compass_info", "NIS2 Compass application info", version="0.1.0")

    return _metrics


def get_metrics() -> PrometheusMetrics | None:
    """Return the initialised metrics instance, or None if not yet initialised."""
    return _metrics
