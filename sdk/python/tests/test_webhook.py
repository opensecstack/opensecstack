"""
pytest test suite for the opensecstack webhook module.

Tests cover HMAC-SHA256 signature verification and WebhookRouter dispatch.
No external network calls are made.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone

import pytest

from opensecstack.webhook import (
    APIGUARD_SCAN_COMPLETED,
    APIGUARD_SCAN_FAILED,
    CITADEL_HARD_STOP,
    InvalidSignatureError,
    WebhookEvent,
    WebhookRouter,
    verify_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign(body: bytes, secret: str) -> str:
    """Return the expected 'sha256=<hex>' HMAC-SHA256 signature."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _make_body(event_type: str = APIGUARD_SCAN_COMPLETED) -> bytes:
    return json.dumps(
        {
            "id": "evt_test_001",
            "event_type": event_type,
            "source": "apiguard",
            "timestamp": "2026-03-30T12:00:00Z",
            "payload": {"scan_id": "scan-abc123"},
            "signature": "",
        }
    ).encode()


# ---------------------------------------------------------------------------
# 1. verify_signature — valid signature succeeds without raising
# ---------------------------------------------------------------------------


def test_verify_signature_valid():
    secret = "my-webhook-secret"
    body = _make_body()
    sig = _sign(body, secret)

    # Should not raise.
    verify_signature(body, sig, secret)


# ---------------------------------------------------------------------------
# 2. verify_signature — wrong secret raises InvalidSignatureError
# ---------------------------------------------------------------------------


def test_verify_signature_invalid_secret():
    body = _make_body()
    sig = _sign(body, "correct-secret")

    with pytest.raises(InvalidSignatureError):
        verify_signature(body, sig, "wrong-secret")


def test_verify_signature_tampered_body():
    secret = "tamper-test-secret"
    original = _make_body(APIGUARD_SCAN_COMPLETED)
    sig = _sign(original, secret)

    tampered = _make_body(APIGUARD_SCAN_FAILED)
    with pytest.raises(InvalidSignatureError):
        verify_signature(tampered, sig, secret)


def test_verify_signature_missing_prefix():
    body = _make_body()
    # Provide raw hex without the 'sha256=' prefix.
    raw_hex = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    with pytest.raises(InvalidSignatureError):
        verify_signature(body, raw_hex, "secret")


# ---------------------------------------------------------------------------
# 3. WebhookRouter — dispatches to the correct registered handler
# ---------------------------------------------------------------------------


def test_webhook_router_dispatch():
    secret = "dispatch-secret"
    received: list[WebhookEvent] = []

    router = WebhookRouter(secret=secret)

    @router.on(APIGUARD_SCAN_COMPLETED)
    def handle_scan(event: WebhookEvent) -> None:
        received.append(event)

    @router.on(CITADEL_HARD_STOP)
    def handle_hard_stop(event: WebhookEvent) -> None:
        pytest.fail("wrong handler called: hard_stop should not fire")

    body = _make_body(APIGUARD_SCAN_COMPLETED)
    sig = _sign(body, secret)

    router.handle(body, sig)

    assert len(received) == 1
    assert received[0].event_type == APIGUARD_SCAN_COMPLETED
    assert received[0].id == "evt_test_001"
    assert received[0].payload == {"scan_id": "scan-abc123"}


def test_webhook_router_catch_all():
    secret = "catchall-secret"
    received: list[WebhookEvent] = []

    router = WebhookRouter(secret=secret)

    @router.on("*")
    def catch_all(event: WebhookEvent) -> None:
        received.append(event)

    body = _make_body("nis2compass.control.updated")
    sig = _sign(body, secret)

    router.handle(body, sig)

    assert len(received) == 1
    assert received[0].event_type == "nis2compass.control.updated"


# ---------------------------------------------------------------------------
# 4. WebhookRouter — raises InvalidSignatureError on bad signature
# ---------------------------------------------------------------------------


def test_webhook_router_bad_signature_raises():
    router = WebhookRouter(secret="real-secret")

    @router.on(APIGUARD_SCAN_COMPLETED)
    def handle(event: WebhookEvent) -> None:
        pytest.fail("handler must not be called with bad signature")

    body = _make_body()
    bad_sig = _sign(body, "not-the-real-secret")

    with pytest.raises(InvalidSignatureError):
        router.handle(body, bad_sig)


# ---------------------------------------------------------------------------
# 5. WebhookRouter — no handler registered still acks (no exception)
# ---------------------------------------------------------------------------


def test_webhook_router_no_handler_is_silent():
    secret = "silent-secret"
    router = WebhookRouter(secret=secret)
    # No handlers registered.

    body = _make_body(CITADEL_HARD_STOP)
    sig = _sign(body, secret)

    # Should complete without raising.
    router.handle(body, sig)
