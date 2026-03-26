"""
opensecstack SDK — exception hierarchy.
"""

from __future__ import annotations

from typing import Any, Optional


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


class RateLimitError(APIError):
    """
    Raised when the server returns HTTP 429 Too Many Requests.

    Attributes
    ----------
    retry_after: Optional[int]
        Number of seconds to wait before retrying, parsed from the
        ``Retry-After`` response header.  ``None`` when the header is absent
        or cannot be parsed as an integer.
    """

    def __init__(self, detail: Any = "rate limited", retry_after: Optional[int] = None) -> None:
        super().__init__(429, detail)
        self.retry_after = retry_after
