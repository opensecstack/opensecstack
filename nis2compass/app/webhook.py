"""
Webhook delivery for NIS2 Compass audit events.

When NIS2_WEBHOOK_URL is configured, every audit log entry is delivered
to the configured URL via an authenticated POST request. Delivery is
best-effort — failures are logged but do not affect the audit write.

Authentication uses HMAC-SHA256 of the JSON payload body, delivered in
the X-NIS2-Signature header (hex-encoded). The receiver should verify:

    import hmac, hashlib
    expected = hmac.new(secret.encode(), payload_bytes, hashlib.sha256).hexdigest()
    assert hmac.compare_digest(expected, request.headers['X-NIS2-Signature'])

Retry policy: 3 attempts with exponential backoff (1s, 2s, 4s).
Each delivery runs in a daemon thread so it never blocks the request.
"""
import hashlib
import hmac
import json
import logging
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 1.0  # seconds

# Bounded thread pool for webhook delivery — prevents unbounded thread growth
# under high load compared to spawning a new thread per event.
_webhook_executor = ThreadPoolExecutor(max_workers=10, thread_name_prefix='webhook')


def _sign_payload(secret: str, payload_bytes: bytes) -> str:
    """Return HMAC-SHA256 hex digest of payload_bytes using secret."""
    return hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256).hexdigest()


def _deliver_once(url: str, payload_bytes: bytes, signature: str) -> bool:
    """
    Attempt a single delivery. Returns True on 2xx response, False otherwise.
    """
    req = urllib.request.Request(
        url,
        data=payload_bytes,
        method='POST',
        headers={
            'Content-Type': 'application/json',
            'X-NIS2-Signature': signature,
            'X-NIS2-Event': 'audit_log',
            'User-Agent': 'NIS2Compass-Webhook/1.0',
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as exc:
        logger.warning('Webhook HTTP error %s for %s', exc.code, url)
        return False
    except Exception as exc:
        logger.warning('Webhook delivery error for %s: %s', url, exc)
        return False


def _deliver_with_retry(url: str, secret: str, event: dict) -> None:
    """Deliver the event with exponential backoff. Runs in a daemon thread."""
    payload_bytes = json.dumps(event, default=str, ensure_ascii=False).encode('utf-8')
    signature = _sign_payload(secret, payload_bytes)

    for attempt in range(1, _MAX_ATTEMPTS + 1):
        success = _deliver_once(url, payload_bytes, signature)
        if success:
            logger.debug('Webhook delivered on attempt %d to %s', attempt, url)
            return
        if attempt < _MAX_ATTEMPTS:
            backoff = _BACKOFF_BASE * (2 ** (attempt - 1))
            time.sleep(backoff)

    logger.error('Webhook delivery failed after %d attempts to %s', _MAX_ATTEMPTS, url)


def dispatch(audit_entry_dict: dict, url: str, secret: str) -> None:
    """
    Fire-and-forget webhook dispatch. Spawns a daemon thread so the
    calling request is not blocked.

    Args:
        audit_entry_dict: the audit log entry as returned by AuditLog.to_dict()
        url: the webhook target URL
        secret: the HMAC signing secret
    """
    if not url:
        return

    event = {
        'event': 'audit_log',
        'delivered_at': datetime.now(timezone.utc).isoformat(),
        'data': audit_entry_dict,
    }
    _webhook_executor.submit(_deliver_with_retry, url, secret, event)
