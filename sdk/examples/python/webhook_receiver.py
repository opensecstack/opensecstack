"""
webhook_receiver.py — Flask server that receives signed webhook events from
the opensecstack platforms (APIGuard, NIS2 Compass, CITADEL).

Usage
-----
1. Install dependencies:
       pip install flask opensecstack

2. Set the shared secret (configured on the platform dashboard):
       export WEBHOOK_SECRET=my-webhook-secret

3. Run:
       python sdk/examples/python/webhook_receiver.py

4. The server listens on http://0.0.0.0:8080 (override with PORT env var).
   Configure the platform to POST events to http://<your-host>:8080/webhooks.

Sending a test event
--------------------
    SECRET=my-webhook-secret
    BODY='{"id":"evt_1","event_type":"apiguard.scan.completed","source":"apiguard",
           "timestamp":"2026-03-30T00:00:00Z","payload":{"scan_id":"test-scan"}}'
    SIG="sha256=$(echo -n "$BODY" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)"
    curl -s -X POST http://localhost:8080/webhooks \\
         -H "Content-Type: application/json" \\
         -H "X-APIGuard-Signature: $SIG" \\
         -d "$BODY"
"""

from __future__ import annotations

import logging
import os
import sys

from flask import Flask

from opensecstack.webhook import (
    APIGUARD_FINDING_CRITICAL,
    APIGUARD_SCAN_COMPLETED,
    APIGUARD_SCAN_FAILED,
    CITADEL_HARD_STOP,
    CITADEL_VIGIL_AMBER,
    CITADEL_VIGIL_RED,
    NIS2COMPASS_ASSESSMENT_COMPLETED,
    NIS2COMPASS_CONTROL_UPDATED,
    WebhookEvent,
    WebhookRouter,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
if not WEBHOOK_SECRET:
    log.error("WEBHOOK_SECRET environment variable is required")
    sys.exit(1)

PORT = int(os.environ.get("PORT", "8080"))

# ---------------------------------------------------------------------------
# WebhookRouter — register one handler per event type
# ---------------------------------------------------------------------------

router = WebhookRouter(secret=WEBHOOK_SECRET)


@router.on(APIGUARD_SCAN_COMPLETED)
def handle_scan_completed(event: WebhookEvent) -> None:
    p = event.payload
    stats = p.get("stats", {})
    log.info(
        "[apiguard.scan.completed] evt=%s scan=%s target=%s "
        "findings(crit=%d high=%d med=%d low=%d total=%d)",
        event.id,
        p.get("scan_id", ""),
        p.get("target", ""),
        stats.get("critical", 0),
        stats.get("high", 0),
        stats.get("medium", 0),
        stats.get("low", 0),
        stats.get("total", 0),
    )


@router.on(APIGUARD_SCAN_FAILED)
def handle_scan_failed(event: WebhookEvent) -> None:
    p = event.payload
    log.warning(
        "[apiguard.scan.failed] evt=%s scan=%s error=%s",
        event.id,
        p.get("scan_id", ""),
        p.get("error", "unknown"),
    )


@router.on(APIGUARD_FINDING_CRITICAL)
def handle_finding_critical(event: WebhookEvent) -> None:
    p = event.payload
    log.critical(
        "[apiguard.finding.critical] evt=%s scan=%s finding=%s owasp=%s title=%s endpoint=%s",
        event.id,
        p.get("scan_id", ""),
        p.get("finding_id", ""),
        p.get("owasp", ""),
        p.get("title", ""),
        p.get("endpoint", ""),
    )


@router.on(NIS2COMPASS_CONTROL_UPDATED)
def handle_control_updated(event: WebhookEvent) -> None:
    p = event.payload
    log.info(
        "[nis2compass.control.updated] evt=%s org=%s assessment=%s "
        "measure=%s %s -> %s by=%s",
        event.id,
        p.get("org_id", ""),
        p.get("assessment_id", ""),
        p.get("measure_ref", ""),
        p.get("previous_status", ""),
        p.get("new_status", ""),
        p.get("updated_by", ""),
    )


@router.on(NIS2COMPASS_ASSESSMENT_COMPLETED)
def handle_assessment_completed(event: WebhookEvent) -> None:
    p = event.payload
    stats = p.get("stats", {})
    log.info(
        "[nis2compass.assessment.completed] evt=%s org=%s assessment=%s "
        "compliant=%d partial=%d non_compliant=%d",
        event.id,
        p.get("org_id", ""),
        p.get("assessment_id", ""),
        stats.get("compliant", 0),
        stats.get("partially_compliant", 0),
        stats.get("non_compliant", 0),
    )


@router.on(CITADEL_HARD_STOP)
def handle_hard_stop(event: WebhookEvent) -> None:
    p = event.payload
    log.critical(
        "[CITADEL HARD STOP] evt=%s execution=%s actor=%s trigger=%s incident=%s",
        event.id,
        p.get("execution_id", ""),
        p.get("actor_user_id", ""),
        p.get("trigger", ""),
        p.get("irflow_incident_id", ""),
    )


@router.on(CITADEL_VIGIL_RED)
def handle_vigil_red(event: WebhookEvent) -> None:
    p = event.payload
    log.critical(
        "[CITADEL VIGIL RED] evt=%s previous=%s reason=%s active_hard_stops=%d",
        event.id,
        p.get("previous_state", ""),
        p.get("reason", ""),
        p.get("active_hard_stops", 0),
    )


@router.on(CITADEL_VIGIL_AMBER)
def handle_vigil_amber(event: WebhookEvent) -> None:
    p = event.payload
    log.warning(
        "[CITADEL VIGIL AMBER] evt=%s previous=%s reason=%s mirror=%s age=%ds",
        event.id,
        p.get("previous_state", ""),
        p.get("reason", ""),
        p.get("mirror_id", ""),
        p.get("age_seconds", 0),
    )


@router.on("*")
def handle_unknown(event: WebhookEvent) -> None:
    log.info("[webhook] unhandled event_type=%s id=%s source=%s", event.event_type, event.id, event.source)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

app = Flask(__name__)

# Mount the router under POST /webhooks.
# flask_view() returns a view function that calls router.handle() and
# returns the appropriate HTTP status (200/400/422).
app.add_url_rule(
    "/webhooks",
    view_func=router.flask_view(),
    methods=["POST"],
)


@app.get("/health")
def health():
    return {"status": "ok"}, 200


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("webhook_receiver listening on port %d  (POST /webhooks)", PORT)
    # Use Werkzeug's built-in dev server (not suitable for production).
    app.run(host="0.0.0.0", port=PORT, debug=False)
