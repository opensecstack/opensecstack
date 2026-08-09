"""
Notification dispatcher for NIS2 Compass.

Sends notifications via webhook POST and/or SMTP email.
Called from API handlers after key state changes.
All functions are synchronous and best-effort — failures are logged but never raised.
"""

import json
import logging
import smtplib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import Any

logger = logging.getLogger(__name__)


def _get_config() -> dict:
    """Return app config dict or empty dict if no app context."""
    try:
        from flask import current_app

        return current_app.config
    except RuntimeError:
        return {}


def notify_assessment_status_change(assessment: Any, old_status: str, new_status: str) -> None:
    """Send a webhook POST when an assessment status changes."""
    config = _get_config()
    url = config.get("NOTIFICATION_WEBHOOK_URL") or ""
    if not url:
        return

    payload = {
        "event": "assessment_status_changed",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "assessment_id": str(assessment.id),
        "old_status": old_status,
        "new_status": new_status,
    }
    _post_webhook(url, payload)


def notify_control_overdue(assessment: Any, control: Any) -> None:
    """Send a webhook POST when a control remediation is overdue."""
    config = _get_config()
    url = config.get("NOTIFICATION_WEBHOOK_URL") or ""
    if not url:
        return

    payload = {
        "event": "control_overdue",
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "assessment_id": str(assessment.id),
        "control_id": str(control.id),
        "measure_ref": control.measure_ref,
        "remediation_due": control.remediation_due.isoformat() if control.remediation_due else None,
    }
    _post_webhook(url, payload)


def send_email_notification(subject: str, body: str, to_address: str) -> None:
    """Send an email notification via SMTP. No-ops silently if SMTP_HOST is not configured."""
    config = _get_config()
    smtp_host = config.get("SMTP_HOST") or ""
    if not smtp_host:
        return

    smtp_port = int(config.get("SMTP_PORT") or 587)
    smtp_user = config.get("SMTP_USER") or ""
    smtp_password = config.get("SMTP_PASSWORD") or ""
    smtp_from = config.get("SMTP_FROM") or smtp_user

    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = to_address

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.ehlo()
            server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(smtp_from, [to_address], msg.as_string())
        logger.debug("Email notification sent to %s: %s", to_address, subject)
    except Exception as exc:
        logger.warning("Email notification failed (to=%s subject=%r): %s", to_address, subject, exc)


def _post_webhook(url: str, payload: dict) -> None:
    """POST JSON payload to the given URL. Logs failures, never raises."""
    try:
        body = json.dumps(payload, default=str, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "User-Agent": "NIS2Compass-Notifications/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            if not (200 <= resp.status < 300):
                logger.warning("Notification webhook returned HTTP %s for %s", resp.status, url)
    except urllib.error.HTTPError as exc:
        logger.warning("Notification webhook HTTP error %s for %s", exc.code, url)
    except Exception as exc:
        logger.warning("Notification webhook delivery error for %s: %s", url, exc)
