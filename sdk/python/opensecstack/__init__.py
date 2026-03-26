"""
opensecstack SDK — Python client library.

Provides typed clients for the NIS2 Compass and APIGuard platform APIs,
plus shared models and the CITADEL inter-platform event schema.

Quick start
-----------
>>> from opensecstack import NIS2CompassClient, APIGuardClient, CitadelEvent
"""

from .apiguard import APIGuardClient
from .nis2compass import NIS2CompassClient
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

__version__ = "0.1.0"

__all__ = [
    # Clients
    "NIS2CompassClient",
    "APIGuardClient",
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
]
