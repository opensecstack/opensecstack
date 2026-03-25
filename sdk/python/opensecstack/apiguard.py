"""
opensecstack SDK — APIGuard client.

Authentication uses a two-step flow:
  1. Exchange the API key for a short-lived JWT via ``POST /api/v1/auth/token``.
  2. Use the JWT as a ``Bearer`` token on all subsequent requests.

The client handles token acquisition automatically on the first call and
re-authenticates transparently when the token expires (HTTP 401).
"""

from __future__ import annotations

import os
import threading
from typing import Optional

import requests

from .exceptions import APIError, AuthenticationError, NotFoundError


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

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})
        self._jwt: Optional[str] = None
        self._auth_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _authenticate(self) -> None:
        """Exchange the API key for a JWT and store it on the session."""
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
            raise APIError(resp.status_code, "No access_token in auth response")
        self._jwt = token
        self._session.headers["Authorization"] = f"Bearer {self._jwt}"

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("JWT expired or invalid — re-authenticate")
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
        """
        with self._auth_lock:
            if self._jwt is None:
                self._authenticate()
        resp = self._session.request(
            method, self._url(path), timeout=self._timeout, **kwargs
        )
        if resp.status_code == 401:
            # Token may have expired — try to re-authenticate once.
            with self._auth_lock:
                self._authenticate()
            resp = self._session.request(
                method, self._url(path), timeout=self._timeout, **kwargs
            )
        self._raise_for_status(resp)
        return resp

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        return self._request("GET", path, params=params)

    def _post(self, path: str, **kwargs) -> requests.Response:
        return self._request("POST", path, **kwargs)

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
            content = fh.read()
        resp = self._request(
            "POST",
            "specs/upload",
            files={"spec": (os.path.basename(spec_path), content)},
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

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
        return payload  # defensive: return as-is if shape differs

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        """
        Return the *limit* most-recent audit log entries (default 50).

        Entries are ordered newest-first.
        """
        resp = self._get("audit", params={"per_page": min(limit, 100)})
        payload = resp.json()
        # APIGuard audit returns a plain list.
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload
