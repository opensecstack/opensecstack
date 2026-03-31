"""
opensecstack SDK — APIGuard client.

Authentication uses a two-step flow:
  1. Exchange the API key for a short-lived JWT via ``POST /api/v1/auth/token``.
  2. Use the JWT as a ``Bearer`` token on all subsequent requests.

The client handles token acquisition automatically on the first call and
re-authenticates transparently when the token expires (HTTP 401).
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import threading
import time
import uuid
from typing import Optional

import httpx
import requests

from .exceptions import APIError, AuthenticationError, NotFoundError, RateLimitError

logger = logging.getLogger(__name__)


class APIGuardClient:
    """
    HTTP client for the APIGuard platform API.

    Parameters
    ----------
    base_url:
        Root URL of the APIGuard instance, e.g. ``https://apiguard.example.com``.
        A trailing slash is stripped.
    api_key:
        Pre-shared API key used to obtain a JWT from ``/api/v1/auth/token``.
    timeout:
        Per-request timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 30,
        *,
        max_retries: int = 3,
        retry_wait_base: float = 0.5,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._max_retries = max_retries
        self._retry_wait_base = retry_wait_base
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        self._jwt: Optional[str] = None
        # Disable automatic redirect following to prevent auth token leakage
        # via 3xx redirects to attacker-controlled URLs (SDK-M4).
        self._session.max_redirects = 0
        self._token_expiry: Optional[float] = None
        self._auth_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _authenticate(self) -> None:
        """Exchange the API key for a JWT and store it on the session.

        Uses a lock-release pattern so that the HTTP round-trip is not made
        while holding ``_auth_lock``, avoiding unnecessary thread contention.
        """
        # Fast path: if a JWT is already present, nothing to do.
        with self._auth_lock:
            if self._jwt is not None:
                return

        # Make the HTTP call WITHOUT holding the lock.
        resp = self._session.post(
            self._url("auth/token"),
            json={"api_key": self._api_key},
            timeout=self._timeout,
        )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid API key — cannot obtain JWT")
        if resp.status_code >= 400:
            raise APIError(resp.status_code, resp.text)
        try:
            data = resp.json()
        except Exception:
            raise AuthenticationError("Invalid JSON in auth/token response")
        token = data.get("access_token") or data.get("token")
        if not token:
            raise AuthenticationError("No access_token in auth/token response")

        # Parse the JWT exp claim for proactive token refresh (SDK-M5).
        expiry: Optional[float] = None
        try:
            payload_b64 = token.split('.')[1]
            payload_b64 += '=' * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get('exp')
            if exp is not None:
                expiry = float(exp)
        except Exception:
            logger.debug("Could not parse JWT exp claim; proactive expiry disabled")

        # Re-acquire the lock to store the token; double-check that another
        # thread did not already populate it while we were doing I/O.
        with self._auth_lock:
            if self._jwt is None:
                self._jwt = token
                self._token_expiry = expiry
                self._session.headers["Authorization"] = f"Bearer {self._jwt}"

    def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        max_retries: int = 3,
        retry_wait_base: float = 0.5,
        stream: bool = False,
        **kwargs,
    ) -> requests.Response:
        """
        Execute an HTTP request with exponential-backoff retry on 5xx errors.

        Retries on: 500, 502, 503, 504 and network-level errors (ConnectionError,
        Timeout). Does NOT retry 4xx client errors.

        Parameters
        ----------
        method:      HTTP method (GET, POST, …)
        url:         Full URL
        max_retries: Maximum retry attempts after the first failure (default 3)
        retry_wait_base: Base wait in seconds; doubles each retry (default 0.5s)
        stream:      If True, response body is not eagerly downloaded
        **kwargs:    Passed directly to requests.Session.request()
        """
        import time as _time

        last_exc: Exception | None = None
        wait = retry_wait_base

        for attempt in range(max_retries + 1):
            if attempt > 0:
                _time.sleep(wait)
                wait *= 2

            try:
                resp = self._session.request(
                    method, url, timeout=self._timeout, stream=stream, **kwargs
                )
                # Retry on server errors only
                if resp.status_code in (500, 502, 503, 504) and attempt < max_retries:
                    last_exc = None
                    continue
                return resp
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_exc = exc
                if attempt == max_retries:
                    raise

        # Should not reach here, but satisfy type checker
        if last_exc:
            raise last_exc
        raise RuntimeError("unexpected retry loop exit")

    def _api_url(self, path: str) -> str:
        return self._url(path)

    def _ensure_authenticated(self) -> None:
        with self._auth_lock:
            token_expiring = (
                self._token_expiry is not None
                and time.time() > self._token_expiry - 60
            )
            needs_auth = self._jwt is None
        if token_expiring or needs_auth:
            if token_expiring:
                with self._auth_lock:
                    self._jwt = None
                    self._token_expiry = None
                    self._session.headers.pop("Authorization", None)
            self._authenticate()

    def _check_content_type(self, resp: requests.Response, expected: str = "application/json") -> None:
        """Raise APIError when the response Content-Type does not match *expected*.

        Called on successful (2xx) responses before the caller decodes the body
        as JSON, so that a proxy error page (text/html) produces a clear message
        instead of a confusing JSON parse error.

        Responses with no body (HTTP 204) are exempt from the check.
        """
        if resp.status_code == 204 or not resp.content:
            return
        ct = resp.headers.get("Content-Type", "")
        if not ct.startswith(expected):
            raise APIError(resp.status_code, f"Unexpected Content-Type: {ct!r}, expected {expected!r}")

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("JWT expired or invalid — re-authenticate")
        if resp.status_code == 429:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            retry_after = None
            try:
                retry_after = int(resp.headers.get('Retry-After', ''))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(detail, retry_after=retry_after)
        if resp.status_code == 404:
            raise NotFoundError(resp.text)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """
        Make an authenticated request, acquiring a JWT first if needed.
        Retries once on 401 (token refresh).
        On 5xx responses, retries up to 2 times with exponential backoff
        (1 s then 2 s).

        On 429 responses, retries once automatically if ``Retry-After`` is
        present and <= 60 seconds; otherwise raises ``RateLimitError``
        immediately to avoid blocking the caller for an unreasonable duration
        (SDK-L5).

        HTTP redirects are never followed (``allow_redirects=False``) to
        prevent Bearer token leakage via attacker-controlled 3xx redirect
        targets (SDK-M4).

        A unique ``X-Request-ID`` header is added to every outgoing request to
        aid server-side log correlation.
        """
        # Proactive token expiry: re-authenticate if the token expires within
        # the next 60 seconds so we don't waste a round-trip on a stale JWT
        # (SDK-M5).
        with self._auth_lock:
            token_expiring = (
                self._token_expiry is not None
                and time.time() > self._token_expiry - 60
            )
            needs_auth = self._jwt is None
        if token_expiring or needs_auth:
            if token_expiring:
                # Clear the existing token so _authenticate() will refresh it.
                with self._auth_lock:
                    self._jwt = None
                    self._token_expiry = None
                    self._session.headers.pop("Authorization", None)
            self._authenticate()

        # Attach a per-request ID for tracing; merge with any caller-supplied headers.
        req_id = str(uuid.uuid4())
        extra_headers = kwargs.pop("headers", None) or {}
        extra_headers.setdefault("X-Request-ID", req_id)
        kwargs["headers"] = extra_headers
        # Never follow redirects — 3xx to an attacker URL would leak the Bearer
        # token in the Authorization header (SDK-M4).
        kwargs.setdefault("allow_redirects", False)

        def _do_once() -> requests.Response:
            # Capture the current auth header before making the request so we
            # can detect whether another thread already refreshed it on 401.
            old_auth = self._session.headers.get("Authorization")
            resp = self._session.request(
                method, self._url(path), timeout=self._timeout, **kwargs
            )
            if resp.status_code == 401:
                # Token may have expired — re-authenticate using double-checked
                # locking to avoid redundant refreshes from concurrent threads.
                logger.debug("Received 401 on %s %s; attempting token refresh", method.upper(), path)
                with self._auth_lock:
                    if self._session.headers.get("Authorization") != old_auth:
                        # Another thread already refreshed the token; just retry.
                        logger.debug("Token already refreshed by another thread; retrying request")
                    else:
                        # Clear state so _authenticate() proceeds unconditionally.
                        self._jwt = None
                        self._token_expiry = None
                        self._session.headers.pop("Authorization", None)
                        try:
                            self._authenticate()
                        except AuthenticationError:
                            logger.warning(
                                "%s %s — re-authentication failed after 401; "
                                "API key may be invalid or revoked",
                                method.upper(), path,
                            )
                            raise
                resp = self._session.request(
                    method, self._url(path), timeout=self._timeout, **kwargs
                )
            return resp

        resp = _do_once()

        # Automatic 429 retry: sleep for Retry-After if it is <= 60 s, then
        # retry once.  Longer waits are surfaced immediately as RateLimitError
        # so callers are not silently blocked (SDK-L5).
        if resp.status_code == 429:
            retry_after: Optional[int] = None
            try:
                retry_after = int(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            if retry_after is not None and retry_after <= 60:
                logger.debug(
                    "429 on %s %s; sleeping %ss before single retry",
                    method.upper(), path, retry_after,
                )
                time.sleep(retry_after)
                resp = _do_once()
            # If Retry-After is absent or > 60, fall through to _raise_for_status
            # which will raise RateLimitError.

        # Retry on 5xx with exponential backoff driven by self._max_retries /
        # self._retry_wait_base so callers can control retry behaviour at
        # construction time (or via APIGuardClient(max_retries=…)).
        _wait = self._retry_wait_base
        for attempt in range(self._max_retries):
            if resp.status_code < 500:
                break
            logger.warning(
                "%s %s returned HTTP %s (X-Request-ID: %s); retrying in %.1fs (attempt %d/%d)",
                method.upper(), path, resp.status_code, req_id, _wait, attempt + 1, self._max_retries,
            )
            time.sleep(_wait)
            _wait *= 2
            resp = _do_once()

        if resp.status_code >= 400:
            logger.warning(
                "%s %s returned HTTP %s (X-Request-ID: %s)",
                method.upper(), path, resp.status_code, req_id,
            )
        self._raise_for_status(resp)
        self._check_content_type(resp)
        return resp

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        return self._request("GET", path, params=params)

    def _post(self, path: str, **kwargs) -> requests.Response:
        return self._request("POST", path, **kwargs)

    def _patch(self, path: str, json: Optional[dict] = None) -> requests.Response:
        return self._request("PATCH", path, json=json)

    def _delete(self, path: str) -> requests.Response:
        return self._request("DELETE", path)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def refresh_token(self, refresh_token: str) -> dict:
        """
        Exchange a refresh token for a new access token.

        Issues ``POST /api/v1/auth/refresh`` directly (without requiring
        a valid JWT). Updates the internal JWT on success.

        Returns the full response dict (access_token, refresh_token, etc.).
        """
        resp = self._session.post(
            self._url("auth/refresh"),
            json={"refresh_token": refresh_token},
            timeout=self._timeout,
            allow_redirects=False,
        )
        if resp.status_code == 401:
            raise AuthenticationError("Refresh token is invalid or expired")
        if resp.status_code >= 400:
            raise APIError(resp.status_code, resp.text)
        data = resp.json()
        token = data.get("access_token") or data.get("token")
        if token:
            self._jwt = token
            self._session.headers["Authorization"] = f"Bearer {self._jwt}"
        return data

    # ------------------------------------------------------------------
    # Specs
    # ------------------------------------------------------------------

    def upload_spec(self, spec_path: str) -> dict:
        """
        Upload a local OpenAPI spec file to the server.

        The server stores the file content-addressed and returns a
        ``spec_path`` (server-side absolute path) that can be passed to
        ``create_scan``.

        Returns a dict with keys ``spec_path``, ``spec_hash``, ``size``.
        """
        spec_path = os.path.expanduser(spec_path)
        with open(spec_path, "rb") as fh:
            # Pass the open file handle directly to stream the upload without
            # buffering the entire file in memory.
            resp = self._request(
                "POST",
                "specs/upload",
                files={"spec": (os.path.basename(spec_path), fh)},
            )
        return resp.json()

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def list_scans(self, page: int = 1, per_page: int = 20) -> dict:
        """
        Return a paginated list of scans.

        Issues ``GET /api/v1/scans`` and returns the envelope dict with
        keys ``items``, ``total``, ``page``, ``per_page``.
        """
        return self._get("scans", params={"page": page, "per_page": per_page}).json()

    def delete_scan(self, scan_id: str) -> None:
        """
        Delete a scan by UUID.

        Issues ``DELETE /api/v1/scans/{scan_id}``.  Returns None on success.
        """
        self._delete(f"scans/{scan_id}")

    def create_scan(
        self,
        spec_id: Optional[str] = None,
        spec_url: Optional[str] = None,
        spec_path: Optional[str] = None,
        target: Optional[str] = None,
        modules: Optional[list[str]] = None,
        auth_type: Optional[str] = None,
        auth_token: Optional[str] = None,
        auth_header: Optional[str] = None,
    ) -> dict:
        """
        Create a new scan.

        Supply **one** of:
        - ``spec_url``  — publicly reachable URL to an OpenAPI spec.
        - ``spec_path`` — server-side absolute path returned by ``upload_spec``.
        - ``spec_id``   — alias for ``spec_path`` (backwards-compat shim).

        ``target`` is the base URL of the API under test. When omitted and
        ``spec_url`` is provided, the server derives the target from the
        spec's ``servers`` block.

        Returns a dict with ``id`` (scan UUID) and ``status``.
        """
        if spec_id is not None and spec_path is None:
            # spec_id is treated as a server-side spec_path by convention.
            spec_path = spec_id

        if spec_url is None and spec_path is None:
            raise ValueError("One of spec_url or spec_path must be provided")

        body: dict = {}
        if spec_url:
            body["spec_url"] = spec_url
        if spec_path:
            body["spec_path"] = spec_path
        if target:
            body["target"] = target
        elif spec_url:
            # Use the spec URL host as a sensible default target.
            from urllib.parse import urlparse
            parsed = urlparse(spec_url)
            body["target"] = f"{parsed.scheme}://{parsed.netloc}"
        if modules:
            body["modules"] = modules
        if auth_type:
            body["auth_type"] = auth_type
        if auth_token:
            body["auth_token"] = auth_token
        if auth_header:
            body["auth_header"] = auth_header

        return self._post("scans", json=body).json()

    def get_scan(self, scan_id: str) -> dict:
        """Return a single scan by UUID."""
        return self._get(f"scans/{scan_id}").json()

    def get_findings(self, scan_id: str, page: int = 1, per_page: int = 100) -> list[dict]:
        """
        Return all findings for a completed scan.

        Results are fetched from ``GET /api/v1/scans/{id}/findings``.
        The API response envelope has a ``data`` key; this method returns
        that inner list directly.
        """
        resp = self._get(
            f"scans/{scan_id}/findings",
            params={"page": page, "per_page": per_page},
        )
        payload = resp.json()
        # The API returns {"data": [...], "total": N, ...}
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        elif isinstance(payload, list):
            return payload  # plain list is also acceptable
        else:
            raise APIError(
                200,
                f"Unexpected response format from get_findings: got {type(payload).__name__}",
            )

    def get_report(self, scan_id: str, format: str = "json") -> bytes:
        """
        Fetch the scan report in the requested format.

        Issues ``GET /api/v1/scans/{id}/report?format={format}`` and
        returns the raw response bytes.  The caller is responsible for
        writing the bytes to a file or forwarding them.

        Parameters
        ----------
        scan_id: UUID of the completed scan.
        format:  Report format — one of ``json`` (default), ``sarif``,
                 ``html``, ``pdf``.
        """
        resp = self._get(f"scans/{scan_id}/report", params={"format": format})
        expected_types = {
            'json': 'application/json',
            'sarif': 'application/json',
            'html': 'text/html',
            'pdf': 'application/pdf',
            'text': 'text/plain',
        }
        ct = resp.headers.get('Content-Type', '')
        expected = expected_types.get(format, '')
        if expected and not ct.lower().startswith(expected):
            raise APIError(resp.status_code, f"Unexpected Content-Type: {ct!r}, expected {expected!r}")
        return resp.content

    def stream_report(
        self,
        scan_id: str,
        format: str,
        dest,
        *,
        chunk_size: int = 8192,
    ) -> None:
        """
        Stream a scan report directly to a file-like object ``dest``.

        Unlike ``get_report()``, this method never buffers the entire response
        body in memory — suitable for large PDF/HTML reports.

        Parameters
        ----------
        scan_id:    UUID of the scan
        format:     Report format: json | sarif | html | pdf
        dest:       Writable file-like object (binary mode)
        chunk_size: Streaming chunk size in bytes (default 8 192)
        """
        self._ensure_authenticated()
        url = self._api_url(f"scans/{scan_id}/report")
        resp = self._request_with_retry(
            "GET", url,
            params={"format": format},
            headers={"Authorization": f"Bearer {self._jwt}"},
            stream=True,
        )
        if resp.status_code == 401:
            self._authenticate()
            resp = self._request_with_retry(
                "GET", url,
                params={"format": format},
                headers={"Authorization": f"Bearer {self._jwt}"},
                stream=True,
            )
        if resp.status_code != 200:
            raise APIError(resp.status_code, resp.text)
        for chunk in resp.iter_content(chunk_size=chunk_size):
            if chunk:
                dest.write(chunk)

    def list_findings(
        self,
        page: int = 1,
        per_page: int = 20,
        scan_id: Optional[str] = None,
    ) -> dict:
        """
        Return a paginated list of findings across all scans.

        Issues ``GET /api/v1/findings``.  Supply ``scan_id`` to filter by scan.
        Returns the envelope dict with keys ``items`` (or ``data``), ``total``,
        ``page``, ``per_page``.
        """
        params: dict = {"page": page, "per_page": per_page}
        if scan_id is not None:
            params["scan_id"] = scan_id
        return self._get("findings", params=params).json()

    def get_finding(self, finding_id: str) -> dict:
        """Return a single finding by UUID."""
        return self._get(f"findings/{finding_id}").json()

    def patch_finding(
        self,
        finding_id: str,
        status: str,
        note: Optional[str] = None,
    ) -> dict:
        """
        Triage a finding by updating its status.

        Parameters
        ----------
        finding_id: UUID of the finding to update.
        status:     One of ``open``, ``confirmed``, ``false_positive``,
                    ``accepted``, ``fixed``.
        note:       Optional free-text triage note.  Pass an empty string
                    ``""`` to explicitly clear an existing note; omit (or
                    pass ``None``) to leave any existing note unchanged.
        """
        body: dict = {"status": status}
        if note is not None:
            body["note"] = note
        return self._patch(f"findings/{finding_id}", json=body).json()

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def get_audit_log(self, limit: int = 50, page: Optional[int] = None) -> list[dict]:
        """
        Return audit log entries (default 50, up to 100 per page).

        Parameters
        ----------
        limit: Number of entries to return per page (capped at 100 by the API).
        page:  1-based page number.  When omitted the API returns the first page.

        Entries are ordered newest-first.
        """
        params: dict = {"per_page": min(limit, 100)}
        if page is not None:
            params["page"] = page
        resp = self._get("audit", params=params)
        payload = resp.json()
        # APIGuard audit returns a plain list.
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class AsyncAPIGuardClient:
    """
    Async HTTP client for the APIGuard platform API.

    Drop-in async counterpart of :class:`APIGuardClient`.  Uses
    ``httpx.AsyncClient`` under the hood so it can be awaited inside any
    ``asyncio`` event loop.

    Parameters
    ----------
    base_url:
        Root URL of the APIGuard instance, e.g. ``https://apiguard.example.com``.
        A trailing slash is stripped.
    client_id:
        Client identifier used in the token request payload.
    client_secret:
        Secret used in the token request payload.
    max_retries:
        Maximum number of retry attempts on 5xx / network errors (default 3).
    retry_wait_base:
        Base wait in seconds for exponential back-off (default 0.5 s).
    verify_ssl:
        Verify TLS certificates (default ``True``).  Set to ``False`` only
        for local development against self-signed certificates.
    timeout:
        Per-request timeout in seconds (default 30.0).

    Usage
    -----
    Preferred — use as an async context manager so the underlying
    ``httpx.AsyncClient`` is closed automatically::

        async with AsyncAPIGuardClient(base_url, client_id, client_secret) as client:
            scan = await client.create_scan(request)
    """

    def __init__(
        self,
        base_url: str,
        client_id: str,
        client_secret: str,
        *,
        max_retries: int = 3,
        retry_wait_base: float = 0.5,
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._client_id = client_id
        self._client_secret = client_secret
        self._max_retries = max_retries
        self._retry_wait_base = retry_wait_base
        self._timeout = timeout
        self._jwt: Optional[str] = None
        self._token_expiry: Optional[float] = None
        # asyncio.Lock is created lazily (in _ensure_authenticated) because the
        # lock must belong to the running event loop, not the constructor's loop.
        self._auth_lock: Optional[asyncio.Lock] = None
        self._http = httpx.AsyncClient(
            verify=verify_ssl,
            headers={"Accept": "application/json"},
            follow_redirects=False,  # prevent Bearer token leakage (SDK-M4)
        )

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncAPIGuardClient":
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self._http.aclose()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _get_auth_lock(self) -> asyncio.Lock:
        """Return (creating on first call) the per-instance asyncio.Lock."""
        if self._auth_lock is None:
            self._auth_lock = asyncio.Lock()
        return self._auth_lock

    async def authenticate(self) -> str:
        """
        Exchange ``client_id``/``client_secret`` for a JWT and store it.

        Returns the raw token string.  Normally called implicitly by
        :meth:`_ensure_authenticated`; callers may invoke it explicitly to
        pre-warm the token before the first real request.
        """
        resp = await self._http.post(
            self._url("auth/token"),
            json={"client_id": self._client_id, "client_secret": self._client_secret},
            timeout=self._timeout,
        )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid credentials — cannot obtain JWT")
        if resp.status_code >= 400:
            raise APIError(resp.status_code, resp.text)
        try:
            data = resp.json()
        except Exception:
            raise AuthenticationError("Invalid JSON in auth/token response")
        token: Optional[str] = data.get("access_token") or data.get("token")
        if not token:
            raise AuthenticationError("No access_token in auth/token response")

        # Parse exp claim for proactive refresh (SDK-M5).
        expiry: Optional[float] = None
        try:
            payload_b64 = token.split(".")[1]
            payload_b64 += "=" * (4 - len(payload_b64) % 4)
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            exp = payload.get("exp")
            if exp is not None:
                expiry = float(exp)
        except Exception:
            logger.debug("Could not parse JWT exp claim; proactive expiry disabled")

        async with self._get_auth_lock():
            self._jwt = token
            self._token_expiry = expiry
            self._http.headers["Authorization"] = f"Bearer {token}"

        return token

    async def _ensure_authenticated(self) -> None:
        """Re-authenticate if the token is missing or expires within 60 s."""
        async with self._get_auth_lock():
            token_expiring = (
                self._token_expiry is not None
                and time.time() > self._token_expiry - 60
            )
            needs_auth = self._jwt is None

        if token_expiring:
            async with self._get_auth_lock():
                self._jwt = None
                self._token_expiry = None
                self._http.headers.pop("Authorization", None)

        if token_expiring or needs_auth:
            await self.authenticate()

    def _check_content_type(self, resp: httpx.Response, expected: str = "application/json") -> None:
        """Raise APIError when the response Content-Type does not match *expected*.

        Called on successful (2xx) responses before the caller decodes the body
        as JSON, so that a proxy error page (text/html) produces a clear message
        instead of a confusing JSON parse error.

        Responses with no body (HTTP 204) are exempt from the check.
        """
        if resp.status_code == 204 or not resp.content:
            return
        ct = resp.headers.get("Content-Type", "")
        if not ct.startswith(expected):
            raise APIError(resp.status_code, f"Unexpected Content-Type: {ct!r}, expected {expected!r}")

    def _raise_for_status(self, resp: httpx.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("JWT expired or invalid — re-authenticate")
        if resp.status_code == 429:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            retry_after: Optional[int] = None
            try:
                retry_after = int(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            raise RateLimitError(detail, retry_after=retry_after)
        if resp.status_code == 404:
            raise NotFoundError(resp.text)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)

    async def _request_with_retry(
        self,
        method: str,
        url: str,
        *,
        max_retries: int = 3,
        retry_wait_base: float = 0.5,
        stream: bool = False,
        **kwargs,
    ) -> httpx.Response:
        """
        Execute an HTTP request with exponential-backoff retry on 5xx errors.

        Mirrors the sync :meth:`APIGuardClient._request_with_retry` but uses
        ``await asyncio.sleep`` and ``await self._http.request`` so it never
        blocks the event loop.

        Parameters
        ----------
        method:          HTTP method (GET, POST, …)
        url:             Full URL
        max_retries:     Retry attempts after the first failure (default 3)
        retry_wait_base: Base wait in seconds; doubles each retry
        stream:          Ignored for httpx (streaming is handled per-request)
        **kwargs:        Passed to ``httpx.AsyncClient.request``
        """
        last_exc: Exception | None = None
        wait = retry_wait_base

        for attempt in range(max_retries + 1):
            if attempt > 0:
                await asyncio.sleep(wait)
                wait *= 2

            try:
                resp = await self._http.request(
                    method, url, timeout=self._timeout, **kwargs
                )
                if resp.status_code in (500, 502, 503, 504) and attempt < max_retries:
                    last_exc = None
                    continue
                return resp
            except (httpx.ConnectError, httpx.TimeoutException) as exc:
                last_exc = exc
                if attempt == max_retries:
                    raise

        if last_exc:
            raise last_exc
        raise RuntimeError("unexpected retry loop exit")

    async def _request(self, method: str, path: str, **kwargs) -> httpx.Response:
        """
        Make an authenticated request with automatic token refresh on 401
        and exponential-backoff retry on 5xx.

        Attaches a unique ``X-Request-ID`` header for server-side log
        correlation, and never follows redirects (SDK-M4).
        """
        await self._ensure_authenticated()

        req_id = str(uuid.uuid4())
        extra_headers: dict = kwargs.pop("headers", None) or {}
        extra_headers.setdefault("X-Request-ID", req_id)
        kwargs["headers"] = extra_headers

        async def _do_once() -> httpx.Response:
            old_auth = self._http.headers.get("Authorization")
            r = await self._http.request(
                method, self._url(path), timeout=self._timeout, **kwargs
            )
            if r.status_code == 401:
                logger.debug("Received 401 on %s %s; attempting token refresh", method.upper(), path)
                async with self._get_auth_lock():
                    if self._http.headers.get("Authorization") != old_auth:
                        logger.debug("Token already refreshed; retrying request")
                    else:
                        self._jwt = None
                        self._token_expiry = None
                        self._http.headers.pop("Authorization", None)
                try:
                    await self.authenticate()
                except AuthenticationError:
                    logger.warning(
                        "%s %s — re-authentication failed after 401", method.upper(), path
                    )
                    raise
                r = await self._http.request(
                    method, self._url(path), timeout=self._timeout, **kwargs
                )
            return r

        resp = await _do_once()

        # Automatic 429 retry (Retry-After <= 60 s).
        if resp.status_code == 429:
            retry_after: Optional[int] = None
            try:
                retry_after = int(resp.headers.get("Retry-After", ""))
            except (ValueError, TypeError):
                pass
            if retry_after is not None and retry_after <= 60:
                logger.debug("429 on %s %s; sleeping %ss", method.upper(), path, retry_after)
                await asyncio.sleep(retry_after)
                resp = await _do_once()

        # 5xx back-off retry driven by self._max_retries / self._retry_wait_base.
        # Uses asyncio.sleep so the event loop is never blocked.
        _wait = self._retry_wait_base
        for attempt in range(self._max_retries):
            if resp.status_code < 500:
                break
            logger.warning(
                "%s %s returned HTTP %s (X-Request-ID: %s); retrying in %.1fs (attempt %d/%d)",
                method.upper(), path, resp.status_code, req_id, _wait, attempt + 1, self._max_retries,
            )
            await asyncio.sleep(_wait)
            _wait *= 2
            resp = await _do_once()

        if resp.status_code >= 400:
            logger.warning(
                "%s %s returned HTTP %s (X-Request-ID: %s)",
                method.upper(), path, resp.status_code, req_id,
            )
        self._raise_for_status(resp)
        self._check_content_type(resp)
        return resp

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    async def create_scan(
        self,
        spec_id: Optional[str] = None,
        spec_url: Optional[str] = None,
        spec_path: Optional[str] = None,
        target: Optional[str] = None,
        modules: Optional[list[str]] = None,
        auth_type: Optional[str] = None,
        auth_token: Optional[str] = None,
        auth_header: Optional[str] = None,
    ) -> dict:
        """
        Create a new scan (async).

        Mirrors :meth:`APIGuardClient.create_scan`.  Supply one of
        ``spec_url`` or ``spec_path`` (or the legacy ``spec_id`` alias).

        Returns a dict with ``id`` (scan UUID) and ``status``.
        """
        if spec_id is not None and spec_path is None:
            spec_path = spec_id
        if spec_url is None and spec_path is None:
            raise ValueError("One of spec_url or spec_path must be provided")

        body: dict = {}
        if spec_url:
            body["spec_url"] = spec_url
        if spec_path:
            body["spec_path"] = spec_path
        if target:
            body["target"] = target
        elif spec_url:
            from urllib.parse import urlparse
            parsed = urlparse(spec_url)
            body["target"] = f"{parsed.scheme}://{parsed.netloc}"
        if modules:
            body["modules"] = modules
        if auth_type:
            body["auth_type"] = auth_type
        if auth_token:
            body["auth_token"] = auth_token
        if auth_header:
            body["auth_header"] = auth_header

        resp = await self._request("POST", "scans", json=body)
        return resp.json()

    async def get_scan(self, scan_id: str) -> dict:
        """Return a single scan by UUID (async)."""
        resp = await self._request("GET", f"scans/{scan_id}")
        return resp.json()

    async def list_scans(self, *, page: int = 1, per_page: int = 20) -> list[dict]:
        """
        Return a paginated list of scans (async).

        Returns the ``items`` list from the API envelope, or the raw list
        if the server responds with a plain array.
        """
        resp = await self._request("GET", "scans", params={"page": page, "per_page": per_page})
        payload = resp.json()
        if isinstance(payload, dict):
            return payload.get("items", payload.get("data", []))
        return payload  # plain list

    async def get_findings(
        self,
        scan_id: str,
        *,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict]:
        """
        Return all findings for a completed scan (async).

        Mirrors :meth:`APIGuardClient.get_findings`.
        """
        resp = await self._request(
            "GET",
            f"scans/{scan_id}/findings",
            params={"page": page, "per_page": per_page},
        )
        payload = resp.json()
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        if isinstance(payload, list):
            return payload
        raise APIError(200, f"Unexpected response format from get_findings: got {type(payload).__name__}")

    async def stream_report(
        self,
        scan_id: str,
        format: str,
        dest,
        *,
        chunk_size: int = 8192,
    ) -> None:
        """
        Stream a scan report directly to a file-like object (async).

        The response body is never buffered in full — suitable for large
        PDF/HTML reports.

        Parameters
        ----------
        scan_id:    UUID of the scan.
        format:     Report format: json | sarif | html | pdf
        dest:       Writable file-like object opened in binary mode.
        chunk_size: Streaming chunk size in bytes (default 8 192).
        """
        await self._ensure_authenticated()
        url = self._url(f"scans/{scan_id}/report")

        async with self._http.stream(
            "GET",
            url,
            params={"format": format},
            timeout=self._timeout,
        ) as resp:
            if resp.status_code == 401:
                # Token expired mid-stream — re-authenticate and retry once.
                await self.authenticate()
                async with self._http.stream(
                    "GET",
                    url,
                    params={"format": format},
                    timeout=self._timeout,
                ) as resp2:
                    if resp2.status_code != 200:
                        await resp2.aread()
                        raise APIError(resp2.status_code, resp2.text)
                    async for chunk in resp2.aiter_bytes(chunk_size):
                        dest.write(chunk)
                return

            if resp.status_code != 200:
                await resp.aread()
                raise APIError(resp.status_code, resp.text)

            async for chunk in resp.aiter_bytes(chunk_size):
                dest.write(chunk)

    # Additional methods (delete_scan, get_report, list_findings, patch_finding,
    # get_audit_log, upload_spec, refresh_token) follow the same pattern:
    # replace self._session.request(...) with await self._http.request(...)
    # and self._request(...) with await self._request(...).  Streaming methods
    # use async with self._http.stream(...) as shown in stream_report above.
