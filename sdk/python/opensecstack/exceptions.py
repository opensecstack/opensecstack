"""
opensecstack SDK — exception hierarchy.
"""

from __future__ import annotations

from typing import Any


class OpenSecStackError(Exception):
    """Base class for all opensecstack SDK errors."""


class APIError(OpenSecStackError):
    """
    Raised when the platform API returns an unexpected HTTP status code.

    Attributes
    ----------
    status_code: int
        HTTP status code returned by the server.
    detail: Any
        Parsed JSON body or raw text from the response.
    """

    def __init__(self, status_code: int, detail: Any) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


class AuthenticationError(OpenSecStackError):
    """Raised when authentication fails (HTTP 401)."""


class NotFoundError(OpenSecStackError):
    """Raised when a requested resource does not exist (HTTP 404)."""
