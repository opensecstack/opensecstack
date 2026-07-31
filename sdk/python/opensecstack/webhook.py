"""
opensecstack webhook support.

Provides HMAC-SHA256 signature verification and an event router that
integrates with Flask, FastAPI, Django, or any WSGI/ASGI framework.

Quick start (Flask)
-------------------
>>> import os
>>> from flask import Flask, request
>>> from opensecstack.webhook import WebhookRouter, APIGUARD_SCAN_COMPLETED
>>>
>>> app = Flask(__name__)
>>> router = WebhookRouter(secret=os.environ["WEBHOOK_SECRET"])
>>>
>>> @router.on(APIGUARD_SCAN_COMPLETED)
... def handle_scan(event):
...     print(f"Scan complete: {event.payload}")
>>>
>>> app.add_url_rule("/webhooks", view_func=router.flask_view(), methods=["POST"])
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional

# ---------------------------------------------------------------------------
# Event type constants
# ---------------------------------------------------------------------------

APIGUARD_SCAN_COMPLETED: str = "apiguard.scan.completed"
APIGUARD_SCAN_FAILED: str = "apiguard.scan.failed"
APIGUARD_FINDING_CRITICAL: str = "apiguard.finding.critical"
NIS2COMPASS_CONTROL_UPDATED: str = "nis2compass.control.updated"
NIS2COMPASS_ASSESSMENT_COMPLETED: str = "nis2compass.assessment.completed"
CITADEL_HARD_STOP: str = "citadel.hard_stop"
CITADEL_VIGIL_RED: str = "citadel.vigil_red"
CITADEL_VIGIL_AMBER: str = "citadel.vigil_amber"


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class InvalidSignatureError(Exception):
    """Raised when webhook HMAC-SHA256 signature verification fails."""


# ---------------------------------------------------------------------------
# Event envelope
# ---------------------------------------------------------------------------


@dataclass
class WebhookEvent:
    """Parsed envelope for all incoming platform webhook events."""

    id: str
    event_type: str
    source: str
    timestamp: datetime
    payload: Dict[str, Any]
    signature: str = field(default="")


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def verify_signature(body: bytes, signature: str, secret: str) -> None:
    """Verify the HMAC-SHA256 signature of a webhook request body.

    Args:
        body:      The raw (undecoded) request body bytes.
        signature: The value of the X-APIGuard-Signature or
                   X-Citadel-Signature header, in the format
                   ``"sha256=<hex_digest>"``.
        secret:    The shared webhook secret configured on the platform.

    Raises:
        InvalidSignatureError: If the signature does not match or is
                               not in the expected ``sha256=…`` format.
    """
    if not signature.startswith("sha256="):
        raise InvalidSignatureError(
            "signature must start with 'sha256=', got: " + repr(signature[:20])
        )
    expected = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    # Constant-time comparison prevents timing-oracle attacks.
    if not hmac.compare_digest(signature, expected):
        raise InvalidSignatureError("webhook signature mismatch")


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------


class WebhookRouter:
    """Routes incoming webhook events to registered Python handlers.

    Designed to integrate with Flask, FastAPI, Django, or any
    WSGI/ASGI framework via :meth:`handle`, :meth:`flask_view`, or
    :meth:`fastapi_endpoint`.

    Example (Flask)::

        router = WebhookRouter(secret=os.environ["WEBHOOK_SECRET"])

        @router.on(APIGUARD_SCAN_COMPLETED)
        def handle_scan(event: WebhookEvent):
            print(f"Scan complete: {event.payload}")

        @app.post("/webhooks")
        def webhook():
            router.handle(request.data,
                          request.headers.get("X-APIGuard-Signature", ""))
            return "", 200

    Example (FastAPI)::

        router = WebhookRouter(secret=os.environ["WEBHOOK_SECRET"])

        @router.on(CITADEL_HARD_STOP)
        def handle_hard_stop(event: WebhookEvent):
            alert_oncall(event.payload)

        app.post("/webhooks")(router.fastapi_endpoint())
    """

    def __init__(self, secret: str) -> None:
        self._secret = secret
        self._handlers: Dict[str, Callable[["WebhookEvent"], Any]] = {}
        self._catch_all: Optional[Callable[["WebhookEvent"], Any]] = None

    # ------------------------------------------------------------------
    # Handler registration
    # ------------------------------------------------------------------

    def on(self, event_type: str) -> Callable:
        """Decorator — register a handler for *event_type*.

        Use ``"*"`` to register a catch-all handler that receives every
        event whose type has no specific handler.

        Args:
            event_type: One of the ``APIGUARD_*``, ``NIS2COMPASS_*``, or
                        ``CITADEL_*`` constants, or ``"*"`` for catch-all.

        Returns:
            The original function, unchanged (decorator pass-through).
        """

        def decorator(func: Callable) -> Callable:
            if event_type == "*":
                self._catch_all = func
            else:
                self._handlers[event_type] = func
            return func

        return decorator

    # ------------------------------------------------------------------
    # Core dispatch
    # ------------------------------------------------------------------

    def handle(self, body: bytes, signature: str) -> None:
        """Verify *signature*, parse the event envelope, and dispatch.

        Args:
            body:      Raw request body bytes.
            signature: Value of the ``X-APIGuard-Signature`` or
                       ``X-Citadel-Signature`` header.

        Raises:
            InvalidSignatureError: If HMAC verification fails.
            ValueError:            If the body is not valid JSON or the
                                   envelope is missing required fields.
        """
        verify_signature(body, signature, self._secret)

        try:
            data: Dict[str, Any] = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ValueError(f"webhook body is not valid JSON: {exc}") from exc

        # Parse the timestamp — accept both "timestamp" (spec) and
        # "ts_utc" (events.md legacy field name).
        raw_ts = data.get("timestamp") or data.get("ts_utc")
        try:
            if isinstance(raw_ts, str):
                ts = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            elif isinstance(raw_ts, (int, float)):
                ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            else:
                ts = datetime.now(tz=timezone.utc)
        except (ValueError, OSError):
            ts = datetime.now(tz=timezone.utc)

        event = WebhookEvent(
            id=data.get("id", ""),
            event_type=data.get("event_type", ""),
            source=data.get("source", ""),
            timestamp=ts,
            payload=data.get("payload", {}),
            signature=data.get("signature", ""),
        )

        handler = self._handlers.get(event.event_type) or self._catch_all
        if handler is not None:
            handler(event)

    # ------------------------------------------------------------------
    # Framework integrations
    # ------------------------------------------------------------------

    def flask_view(self) -> Callable:
        """Return a Flask view function that handles webhook POST requests.

        Mount it with::

            app.add_url_rule("/webhooks", view_func=router.flask_view(),
                             methods=["POST"])

        Returns:
            A zero-argument callable suitable for use as a Flask view.
        """

        def view():
            # Import Flask here so it remains an optional dependency.
            try:
                from flask import Response, request
            except ImportError as exc:
                raise ImportError(
                    "Flask must be installed to use flask_view(): " "pip install flask"
                ) from exc

            body: bytes = request.data
            sig: str = (
                request.headers.get("X-APIGuard-Signature")
                or request.headers.get("X-Citadel-Signature")
                or ""
            )
            try:
                self.handle(body, sig)
            except InvalidSignatureError as exc:
                return Response(str(exc), status=400)
            except ValueError as exc:
                return Response(str(exc), status=422)
            return Response("", status=200)

        # Give each router a unique endpoint name so Flask won't complain
        # if multiple routers are registered.
        view.__name__ = f"opensecstack_webhook_{id(self)}"
        return view

    def fastapi_endpoint(self) -> Callable:
        """Return an async FastAPI endpoint handler.

        Mount it with::

            app.post("/webhooks")(router.fastapi_endpoint())

        Returns:
            An async callable compatible with FastAPI's dependency system.
        """

        async def endpoint(request: Any) -> Any:
            # Import FastAPI types here so they remain optional dependencies.
            try:
                from fastapi.responses import Response
            except ImportError as exc:
                raise ImportError(
                    "FastAPI must be installed to use fastapi_endpoint(): "
                    "pip install fastapi"
                ) from exc

            body: bytes = await request.body()
            sig: str = (
                request.headers.get("x-apiguard-signature")
                or request.headers.get("x-citadel-signature")
                or ""
            )
            try:
                self.handle(body, sig)
            except InvalidSignatureError as exc:
                return Response(content=str(exc), status_code=400)
            except ValueError as exc:
                return Response(content=str(exc), status_code=422)
            return Response(status_code=200)

        return endpoint
