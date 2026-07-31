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
from .citadel import CITADELClient, GetEventsOptions, SecurityEvent
from .nis2compass import AsyncNIS2CompassClient, NIS2CompassClient

# AsyncCITADELClient is only available when httpx is installed.
try:
    from .citadel import AsyncCITADELClient
except ImportError:
    pass

from .exceptions import (
    APIError,
    AuthenticationError,
    NotFoundError,
    OpenSecStackError,
    RateLimitError,
)
from .models import (
    Assessment,
    AuditEntry,
    CitadelEvent,
    Control,
    Finding,
    Organisation,
    Scan,
)

# Router and event envelope, plus event type constants for APIGuard,
# NIS2 Compass, and CITADEL.
from .webhook import (
    APIGUARD_FINDING_CRITICAL,
    APIGUARD_SCAN_COMPLETED,
    APIGUARD_SCAN_FAILED,
    CITADEL_HARD_STOP,
    CITADEL_VIGIL_AMBER,
    CITADEL_VIGIL_RED,
    NIS2COMPASS_ASSESSMENT_COMPLETED,
    NIS2COMPASS_CONTROL_UPDATED,
    InvalidSignatureError,
    WebhookEvent,
    WebhookRouter,
    verify_signature,
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
