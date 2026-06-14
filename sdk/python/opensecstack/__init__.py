"""
opensecstack SDK — Python client library.

Provides typed clients for the NIS2 Compass, APIGuard, and CITADEL platform
APIs, plus shared models, the CITADEL inter-platform event schema, and webhook
support for receiving signed events from all three platforms.

Quick start
-----------
>>> from opensecstack import NIS2CompassClient, APIGuardClient, CitadelEvent
>>> from opensecstack import CITADELClient, AsyncCITADELClient, SecurityEvent
>>> from opensecstack import WebhookRouter, APIGUARD_SCAN_COMPLETED
"""

from .apiguard import APIGuardClient, AsyncAPIGuardClient
from .nis2compass import NIS2CompassClient, AsyncNIS2CompassClient
from .citadel import CITADELClient, SecurityEvent, GetEventsOptions

# AsyncCITADELClient is only available when httpx is installed.
try:
    from .citadel import AsyncCITADELClient
except ImportError:
    pass

from .models import (
    Organisation,
    Assessment,
    Control,
    Scan,
    Finding,
    AuditEntry,
    CitadelEvent,
)
from .exceptions import (
    OpenSecStackError,
    APIError,
    AuthenticationError,
    NotFoundError,
    RateLimitError,
)
from .webhook import (
    # Router and event envelope
    WebhookRouter,
    WebhookEvent,
    verify_signature,
    InvalidSignatureError,
    # Event type constants — APIGuard
    APIGUARD_SCAN_COMPLETED,
    APIGUARD_SCAN_FAILED,
    APIGUARD_FINDING_CRITICAL,
    # Event type constants — NIS2 Compass
    NIS2COMPASS_CONTROL_UPDATED,
    NIS2COMPASS_ASSESSMENT_COMPLETED,
    # Event type constants — CITADEL
    CITADEL_HARD_STOP,
    CITADEL_VIGIL_RED,
    CITADEL_VIGIL_AMBER,
)

__version__ = "1.0.0"

__all__ = [
    # Clients
    "NIS2CompassClient",
    "APIGuardClient",
    "AsyncNIS2CompassClient",
    "AsyncAPIGuardClient",
    "CITADELClient",
    "AsyncCITADELClient",
    # CITADEL types
    "SecurityEvent",
    "GetEventsOptions",
    # Models
    "Organisation",
    "Assessment",
    "Control",
    "Scan",
    "Finding",
    "AuditEntry",
    "CitadelEvent",
    # Exceptions
    "OpenSecStackError",
    "APIError",
    "AuthenticationError",
    "NotFoundError",
    "RateLimitError",
    # Webhook
    "WebhookRouter",
    "WebhookEvent",
    "verify_signature",
    "InvalidSignatureError",
    # Webhook event type constants
    "APIGUARD_SCAN_COMPLETED",
    "APIGUARD_SCAN_FAILED",
    "APIGUARD_FINDING_CRITICAL",
    "NIS2COMPASS_CONTROL_UPDATED",
    "NIS2COMPASS_ASSESSMENT_COMPLETED",
    "CITADEL_HARD_STOP",
    "CITADEL_VIGIL_RED",
    "CITADEL_VIGIL_AMBER",
]
