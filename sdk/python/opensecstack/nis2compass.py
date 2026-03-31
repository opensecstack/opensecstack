"""
opensecstack SDK — NIS2 Compass client.

Authentication uses a two-step flow: the API key is exchanged for a
short-lived JWT via ``POST /api/v1/auth/token``.  The JWT is cached in
the session and refreshed automatically on HTTP 401.
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


class NIS2CompassClient:
    """
    HTTP client for the NIS2 Compass platform API.

    Parameters
    ----------
    base_url:
        Root URL of the NIS2 Compass instance, e.g.
        ``https://nis2.example.com``.  A trailing slash is stripped.
    api_key:
        API key issued by the platform (see ``POST /api/v1/api-keys``).
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
        self._session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
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
        """Exchange the API key for a JWT and store it in the session.

        Uses a lock-release pattern so that the HTTP round-trip is not made
        while holding ``_auth_lock``, avoiding unnecessary thread contention.
        """
        # Fast path: if a token is already present, nothing to do.
        with self._auth_lock:
            if "Authorization" in self._session.headers:
                return

        # Make the HTTP call WITHOUT holding the lock.
        logger.debug("Authenticating with NIS2 Compass API at %s", self._base)
        resp = self._session.post(
            self._url("auth/token"),
            json={"api_key": self._api_key},
            timeout=self._timeout,
        )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing API key")
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)
        try:
            data = resp.json()
        except Exception:
            raise AuthenticationError("Invalid JSON in auth/token response")
        token = data.get("token") or data.get("access_token")
        if not token:
            raise AuthenticationError("No token received from auth/token endpoint")

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
            if "Authorization" not in self._session.headers:
                self._session.headers["Authorization"] = f"Bearer {token}"
                self._token_expiry = expiry
                logger.debug("Authentication successful; JWT acquired")

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
            needs_auth = "Authorization" not in self._session.headers
        if token_expiring or needs_auth:
            if token_expiring:
                with self._auth_lock:
                    self._session.headers.pop("Authorization", None)
                    self._token_expiry = None
            self._authenticate()

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
        """Execute a request, authenticating (and retrying once on 401).

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
            needs_auth = "Authorization" not in self._session.headers
        if token_expiring or needs_auth:
            if token_expiring:
                # Clear the existing token so _authenticate() will refresh it.
                with self._auth_lock:
                    self._session.headers.pop("Authorization", None)
                    self._token_expiry = None
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
            resp = getattr(self._session, method)(self._url(path), timeout=self._timeout, **kwargs)
            if resp.status_code == 401:
                # Token expired — re-authenticate and retry once, using
                # double-checked locking to avoid redundant refreshes.
                # NOTE: _authenticate() must be called OUTSIDE the lock because
                # it also acquires _auth_lock (threading.Lock is not reentrant).
                logger.debug("Received 401 on %s %s; attempting token refresh", method.upper(), path)
                _should_refresh = False
                with self._auth_lock:
                    if self._session.headers.get("Authorization") != old_auth:
                        # Another thread already refreshed the token; just retry.
                        logger.debug("Token already refreshed by another thread; retrying request")
                    else:
                        # Clear expiry so _authenticate() proceeds unconditionally.
                        self._token_expiry = None
                        self._session.headers.pop("Authorization", None)
                        _should_refresh = True
                if _should_refresh:
                    try:
                        self._authenticate()
                    except AuthenticationError:
                        logger.warning(
                            "%s %s — re-authentication failed after 401; "
                            "API key may be invalid or revoked",
                            method.upper(), path,
                        )
                        raise
                resp = getattr(self._session, method)(self._url(path), timeout=self._timeout, **kwargs)
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
        # construction time (or via NIS2CompassClient(max_retries=…)).
        _wait = self._retry_wait_base
        for attempt in range(self._max_retries):
            if resp.status_code < 500:
                break
            logger.warning(
                "Received HTTP %s on %s %s; retrying in %.1fs (attempt %d/%d)",
                resp.status_code, method.upper(), path, _wait, attempt + 1, self._max_retries,
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
        return resp

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        return self._request("get", path, params=params)

    def _post(self, path: str, json: Optional[dict] = None) -> requests.Response:
        return self._request("post", path, json=json)

    def _patch(self, path: str, json: Optional[dict] = None) -> requests.Response:
        return self._request("patch", path, json=json)

    def _delete(self, path: str) -> requests.Response:
        return self._request("delete", path)

    # ------------------------------------------------------------------
    # Organisations
    # ------------------------------------------------------------------

    def get_organisations(self, page: int = 1, per_page: int = 20) -> list[dict]:
        """
        Return a list of organisations.

        The raw API supports pagination; this method returns the page
        requested (default: first page, 20 items).
        """
        resp = self._get("organisations", params={"page": page, "per_page": per_page})
        return resp.json()

    def get_organisation(self, org_id: str) -> dict:
        """Return a single organisation by UUID."""
        return self._get(f"organisations/{org_id}").json()

    def create_organisation(
        self,
        name: str,
        industry: str,
        country: str,
        size: str = "medium",
        entity_type: str = "important",
        registration_number: Optional[str] = None,
        contact_email: Optional[str] = None,
    ) -> dict:
        """
        Create a new organisation.

        Parameters
        ----------
        name:        Display name (must be unique).
        industry:    Free-text industry label.
        country:     ISO 3166-1 alpha-2 country code (e.g. ``"DE"``).
        size:        One of ``micro``, ``small``, ``medium``, ``large``.
        entity_type: One of ``essential``, ``important``.
        """
        body: dict = {
            "name": name,
            "industry": industry,
            "country": country,
            "size": size,
            "entity_type": entity_type,
        }
        if registration_number is not None:
            body["registration_number"] = registration_number
        if contact_email is not None:
            body["contact_email"] = contact_email
        return self._post("organisations", json=body).json()

    def patch_organisation(
        self,
        org_id: str,
        name: Optional[str] = None,
        industry: Optional[str] = None,
        country: Optional[str] = None,
        size: Optional[str] = None,
        entity_type: Optional[str] = None,
        registration_number: Optional[str] = None,
        contact_email: Optional[str] = None,
    ) -> dict:
        """
        Update an existing organisation (partial update).

        Parameters
        ----------
        org_id:    UUID of the organisation to update.
        name:      New display name.
        industry:  New industry label.
        country:   ISO 3166-1 alpha-2 country code (e.g. ``"DE"``).
        size:      One of ``micro``, ``small``, ``medium``, ``large``.
        entity_type: One of ``essential``, ``important``.
        """
        body: dict = {}
        if name is not None:
            body["name"] = name
        if industry is not None:
            body["industry"] = industry
        if country is not None:
            body["country"] = country
        if size is not None:
            body["size"] = size
        if entity_type is not None:
            body["entity_type"] = entity_type
        if registration_number is not None:
            body["registration_number"] = registration_number
        if contact_email is not None:
            body["contact_email"] = contact_email
        return self._patch(f"organisations/{org_id}", json=body).json()

    def delete_organisation(self, org_id: str) -> None:
        """
        Permanently delete an organisation and all its assessments.

        Parameters
        ----------
        org_id: UUID of the organisation to delete.
        """
        self._delete(f"organisations/{org_id}")

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    def create_assessment(
        self,
        org_id: str,
        title: str,
        framework_version: str = "NIS2-2022/0383",
        scope: Optional[str] = None,
        assessor: Optional[str] = None,
        due_date: Optional[str] = None,
    ) -> dict:
        """
        Create a new NIS2 assessment under an organisation.

        Parameters
        ----------
        org_id:   UUID of the parent organisation.
        title:    Assessment title (required by the API).
        due_date: Optional ISO date string ``"YYYY-MM-DD"``.
        """
        body: dict = {
            "title": title,
            "framework_version": framework_version,
        }
        if scope is not None:
            body["scope"] = scope
        if assessor is not None:
            body["assessor"] = assessor
        if due_date is not None:
            body["due_date"] = due_date
        return self._post(f"organisations/{org_id}/assessments", json=body).json()

    def get_assessment(self, assessment_id: str) -> dict:
        """Return a single assessment by UUID (includes control stats)."""
        return self._get(f"assessments/{assessment_id}").json()

    def patch_assessment(
        self,
        assessment_id: str,
        status: Optional[str] = None,
        title: Optional[str] = None,
        scope: Optional[str] = None,
        assessor: Optional[str] = None,
        due_date: Optional[str] = None,
    ) -> dict:
        """
        Update fields on an existing assessment (partial update).

        Parameters
        ----------
        assessment_id: UUID of the assessment to update.
        status:        Target lifecycle status.  Allowed transitions:
                       ``draft`` → ``in_progress`` → ``under_review``
                       → ``completed`` → ``archived``.
        title:         New assessment title.
        scope:         Scope description (free text).
        assessor:      Name or identifier of the assessor.
        due_date:      ISO date string ``"YYYY-MM-DD"``.
        """
        body: dict = {}
        if status is not None:
            body["status"] = status
        if title is not None:
            body["title"] = title
        if scope is not None:
            body["scope"] = scope
        if assessor is not None:
            body["assessor"] = assessor
        if due_date is not None:
            body["due_date"] = due_date
        return self._patch(f"assessments/{assessment_id}", json=body).json()

    def delete_assessment(self, assessment_id: str) -> None:
        """
        Permanently delete an assessment and all its controls.

        Parameters
        ----------
        assessment_id: UUID of the assessment to delete.
        """
        self._delete(f"assessments/{assessment_id}")

    def list_assessments(
        self,
        org_id: str,
        *,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> list[dict]:
        """
        Return a list of assessments for an organisation.

        Issues ``GET /organisations/{org_id}/assessments`` with optional
        server-side filtering and pagination.

        Parameters
        ----------
        org_id:   UUID of the parent organisation.
        status:   Optional filter by assessment lifecycle status.  One of
                  ``draft``, ``in_progress``, ``under_review``,
                  ``completed``, ``archived``.
        page:     1-based page number (default: 1).
        per_page: Items per page, max 100 (default: 20).
        """
        params: dict = {"page": page, "per_page": per_page}
        if status is not None:
            params["status"] = status
        return self._get(f"organisations/{org_id}/assessments", params=params).json()

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def list_controls(
        self,
        assessment_id: str,
        status: Optional[str] = None,
        nist_category: Optional[str] = None,
        measure_ref: Optional[str] = None,
    ) -> list[dict]:
        """
        Return all controls for an assessment.

        Parameters
        ----------
        assessment_id: UUID of the assessment.
        status:        Filter by control status (e.g. ``"non_compliant"``).
        nist_category: Filter by NIST CSF category (e.g. ``"protect"``).
        measure_ref:   Filter by a specific measure letter ``a``–``j``.
        """
        params: dict = {}
        if status is not None:
            params["status"] = status
        if nist_category is not None:
            params["nist_category"] = nist_category
        if measure_ref is not None:
            params["measure_ref"] = measure_ref
        resp = self._get(f"assessments/{assessment_id}/controls", params=params or None)
        return resp.json()

    def get_control(self, assessment_id: str, measure_ref: str) -> dict:
        """
        Return a single control by its measure reference letter (``a``–``j``).

        Parameters
        ----------
        assessment_id: UUID of the assessment.
        measure_ref:   Single letter ``a``–``j`` (NIS2 Art.21 measure).
        """
        return self._get(f"assessments/{assessment_id}/controls/{measure_ref}").json()

    def patch_control(
        self,
        assessment_id: str,
        measure_ref: str,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        gap_description: Optional[str] = None,
        remediation_plan: Optional[str] = None,
        risk_score: Optional[float] = None,
        evidence: Optional[dict] = None,
        remediation_due: Optional[str] = None,
        remediation_owner: Optional[str] = None,
        remediation_status: Optional[str] = None,
        external_ticket_url: Optional[str] = None,
        remediation_notes: Optional[str] = None,
    ) -> dict:
        """
        Update a control within an assessment (partial update).

        Parameters
        ----------
        assessment_id:      UUID of the assessment.
        measure_ref:        Single letter ``a``–``j`` (NIS2 Art.21 measure).
        status:             One of ``not_assessed``, ``compliant``,
                            ``partially_compliant``, ``non_compliant``,
                            ``not_applicable``.
        notes:              Free-text notes.
        gap_description:    Description of the identified compliance gap.
        remediation_plan:   Plan to address the gap.
        risk_score:         Numeric risk score between 0.0 and 10.0.
        evidence:           JSON object of evidence artefacts.
        remediation_due:    ISO date string ``"YYYY-MM-DD"`` for the
                            remediation deadline.
        remediation_owner:  Name or identifier of the remediation owner.
        remediation_status: One of ``not_started``, ``in_progress``,
                            ``blocked``, ``completed``.
        external_ticket_url: URL to an external issue tracker ticket
                             (must start with ``http://`` or ``https://``).
        remediation_notes:  Free-text notes about remediation progress.
        """
        body: dict = {}
        if status is not None:
            body["status"] = status
        if notes is not None:
            body["notes"] = notes
        if gap_description is not None:
            body["gap_description"] = gap_description
        if remediation_plan is not None:
            body["remediation_plan"] = remediation_plan
        if risk_score is not None:
            body["risk_score"] = risk_score
        if evidence is not None:
            body["evidence"] = evidence
        if remediation_due is not None:
            body["remediation_due"] = remediation_due
        if remediation_owner is not None:
            body["remediation_owner"] = remediation_owner
        if remediation_status is not None:
            body["remediation_status"] = remediation_status
        if external_ticket_url is not None:
            body["external_ticket_url"] = external_ticket_url
        if remediation_notes is not None:
            body["remediation_notes"] = remediation_notes
        return self._patch(
            f"assessments/{assessment_id}/controls/{measure_ref}", json=body
        ).json()

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def list_artifacts(self, assessment_id: str) -> list[dict]:
        """
        Return all artifacts attached to an assessment.

        Parameters
        ----------
        assessment_id: UUID of the assessment.
        """
        return self._get(f"assessments/{assessment_id}/artifacts").json()

    def upload_artifact(
        self,
        assessment_id: str,
        file_path: str,
        artifact_type: str,
        control_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> dict:
        """
        Upload a file as an artifact attached to an assessment.

        The ``file`` field is sent as multipart/form-data.

        Parameters
        ----------
        assessment_id:  UUID of the assessment.
        file_path:      Local path to the file to upload.
        artifact_type:  One of ``policy``, ``procedure``, ``evidence``,
                        ``report``, ``screenshot``, ``log``,
                        ``certificate``, ``contract``.
        control_id:     Optional UUID of a control to link the artifact to.
        description:    Optional free-text description.
        """
        file_path = os.path.expanduser(file_path)
        form_data: dict = {"type": artifact_type}
        if control_id is not None:
            form_data["control_id"] = control_id
        if description is not None:
            form_data["description"] = description
        with open(file_path, "rb") as fh:
            # Pass the open file handle directly so the multipart body is
            # sent while the file is still open, avoiding a use-after-close bug.
            # Set Content-Type to None so requests can replace the session-level
            # 'application/json' header with the correct multipart boundary.
            resp = self._request(
                "post",
                f"assessments/{assessment_id}/artifacts",
                files={"file": (os.path.basename(file_path), fh)},
                data=form_data,
                headers={"Content-Type": None},
            )
        return resp.json()

    def get_artifact(self, artifact_id: str) -> dict:
        """
        Return artifact metadata by UUID.

        Parameters
        ----------
        artifact_id: UUID of the artifact.
        """
        return self._get(f"artifacts/{artifact_id}").json()

    def download_artifact(self, artifact_id: str, dest_path: str) -> None:
        """
        Download an artifact's file content and save it to *dest_path*.

        Parameters
        ----------
        artifact_id: UUID of the artifact.
        dest_path:   Local filesystem path where the file will be written.
        """
        dest_path = os.path.expanduser(dest_path)
        # Ensure we have a valid token before the streamed request.
        _needs_auth = False
        with self._auth_lock:
            if "Authorization" not in self._session.headers:
                _needs_auth = True
        if _needs_auth:
            self._authenticate()

        def _stream() -> requests.Response:
            return self._session.get(
                self._url(f"artifacts/{artifact_id}/download"),
                timeout=self._timeout,
                stream=True,
                allow_redirects=False,
            )

        old_auth = self._session.headers.get("Authorization")
        resp = _stream()
        if resp.status_code == 401:
            _should_refresh = False
            with self._auth_lock:
                if self._session.headers.get("Authorization") == old_auth:
                    self._session.headers.pop("Authorization", None)
                    self._token_expiry = None
                    _should_refresh = True
            if _should_refresh:
                self._authenticate()
            resp = _stream()

        self._raise_for_status(resp)
        content_type = resp.headers.get("Content-Type", "")
        if "application/pdf" not in content_type and "application/octet-stream" not in content_type:
            resp.close()
            raise APIError(
                resp.status_code,
                f"Unexpected Content-Type for report: {content_type!r}",
            )
        # Use the response as a context manager so it is always closed, even
        # when an exception occurs during streaming or writing (H12).
        with resp:
            with open(dest_path, "wb") as fh:
                for chunk in resp.iter_content(chunk_size=65536):
                    fh.write(chunk)

    def delete_artifact(self, artifact_id: str) -> None:
        """
        Permanently delete an artifact and its stored file.

        Parameters
        ----------
        artifact_id: UUID of the artifact.
        """
        self._delete(f"artifacts/{artifact_id}")

    # ------------------------------------------------------------------
    # API key management
    # ------------------------------------------------------------------

    def list_api_keys(self) -> list[dict]:
        """Return all API keys belonging to the current actor."""
        return self._get("api-keys").json()

    def create_api_key(self, label: Optional[str] = None, scope: str = "read_write") -> dict:
        """
        Create a new API key.

        The plaintext key is returned once in the response ``key`` field
        and is never stored by the server.

        Parameters
        ----------
        label: Optional human-readable label for the key.
        scope: One of ``read``, ``read_write`` (default: ``read_write``).
        """
        body: dict = {"scope": scope}
        if label is not None:
            body["label"] = label
        return self._post("api-keys", json=body).json()

    def revoke_api_key(self, key_id: str) -> None:
        """
        Revoke (deactivate) an API key.

        Parameters
        ----------
        key_id: UUID of the API key to revoke.
        """
        self._delete(f"api-keys/{key_id}")

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def generate_report(self, assessment_id: str, output_path: str) -> None:
        """
        Download the PDF compliance report for an assessment and save it
        to *output_path* on the local filesystem.

        The directory containing *output_path* must already exist.
        """
        # Ensure we have a valid token before the long-running streamed request.
        # _authenticate() must be called outside any lock (Lock is not reentrant).
        _needs_auth = False
        with self._auth_lock:
            if "Authorization" not in self._session.headers:
                _needs_auth = True
        if _needs_auth:
            self._authenticate()

        report_timeout = max(self._timeout, 120)

        def _stream_report() -> requests.Response:
            return self._session.post(
                self._url(f"assessments/{assessment_id}/report"),
                timeout=report_timeout,
                stream=True,
                allow_redirects=False,
            )

        old_auth = self._session.headers.get("Authorization")
        resp = _stream_report()
        if resp.status_code == 401:
            # Token expired — re-authenticate and retry once.
            logger.debug("Received 401 on report generation for %s; refreshing token", assessment_id)
            _should_refresh = False
            with self._auth_lock:
                if self._session.headers.get("Authorization") == old_auth:
                    self._session.headers.pop("Authorization", None)
                    self._token_expiry = None
                    _should_refresh = True
            if _should_refresh:
                self._authenticate()
            resp = _stream_report()

        self._raise_for_status(resp)
        content_type = resp.headers.get("Content-Type", "")
        if "application/pdf" not in content_type and "application/octet-stream" not in content_type:
            raise APIError(
                resp.status_code,
                f"Unexpected Content-Type for report: {content_type!r}",
            )
        output_path = os.path.expanduser(output_path)
        with resp, open(output_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)

    def stream_report(
        self,
        assessment_id: str,
        format: str,
        dest,
        *,
        chunk_size: int = 8192,
    ) -> None:
        """
        Stream an assessment report to a file-like object.

        Parameters
        ----------
        assessment_id: UUID of the assessment
        format:        pdf | json | sarif
        dest:          Writable file-like object (binary mode)
        chunk_size:    Streaming chunk size in bytes
        """
        resp = self._request(
            "post",
            f"assessments/{assessment_id}/report",
            params={"format": format},
            stream=True,
        )
        with resp:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    dest.write(chunk)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def get_audit_log(self, limit: int = 50, page: int = 1) -> list[dict]:
        """
        Return audit log entries (default 50, up to 100 per page).

        The API caps ``per_page`` at 100 items per request.  Use ``page`` to
        retrieve subsequent pages of results when more than 100 entries exist.

        Parameters
        ----------
        limit: Number of entries to return per page (capped at 100 by the API).
        page:  1-based page number (default: 1).

        Entries are ordered newest-first.
        """
        resp = self._get("audit", params={"per_page": min(limit, 100), "page": page})
        return resp.json()

    def get_audit_entry(self, entry_id: str) -> dict:
        """
        Return a single audit log entry by UUID.

        Parameters
        ----------
        entry_id: UUID of the audit log entry.
        """
        return self._get(f"audit/{entry_id}").json()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def get_health(self) -> dict:
        """
        Return the aggregate platform health status.

        Does not require authentication.  Returns ``{"status": "ok"}`` on
        success or ``{"status": "degraded"}`` with HTTP 503 when a dependency
        is unhealthy.
        """
        resp = self._session.get(self._url("health"), timeout=self._timeout)
        self._raise_for_status(resp)
        return resp.json()

    def get_health_detail(self) -> dict:
        """
        Return detailed health information including per-dependency status.

        Requires a valid Bearer JWT (calls ``_ensure_authenticated`` first).
        Returns a dict with ``status``, ``version``, ``db``, and ``redis``
        keys.
        """
        resp = self._request("get", "health/detail")
        return resp.json()


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------

class AsyncNIS2CompassClient:
    """
    Async HTTP client for the NIS2 Compass platform API.

    Drop-in async counterpart of :class:`NIS2CompassClient`.  Uses
    ``httpx.AsyncClient`` under the hood so it can be awaited inside any
    ``asyncio`` event loop.

    Parameters
    ----------
    base_url:
        Root URL of the NIS2 Compass instance, e.g. ``https://nis2.example.com``.
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
        Verify TLS certificates (default ``True``).
    timeout:
        Per-request timeout in seconds (default 30.0).

    Usage
    -----
    Preferred — use as an async context manager::

        async with AsyncNIS2CompassClient(base_url, client_id, client_secret) as client:
            org = await client.create_organisation(...)
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
        self._auth_lock: Optional[asyncio.Lock] = None
        self._http = httpx.AsyncClient(
            verify=verify_ssl,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            follow_redirects=False,  # prevent Bearer token leakage (SDK-M4)
        )

    # ------------------------------------------------------------------
    # Async context manager
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "AsyncNIS2CompassClient":
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
        logger.debug("Authenticating with NIS2 Compass API at %s", self._base)
        resp = await self._http.post(
            self._url("auth/token"),
            json={"client_id": self._client_id, "client_secret": self._client_secret},
            timeout=self._timeout,
        )
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing credentials")
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)
        try:
            data = resp.json()
        except Exception:
            raise AuthenticationError("Invalid JSON in auth/token response")
        token: Optional[str] = data.get("token") or data.get("access_token")
        if not token:
            raise AuthenticationError("No token received from auth/token endpoint")

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
            logger.debug("Authentication successful; JWT acquired")

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

        Mirrors the sync :meth:`NIS2CompassClient._request_with_retry` but uses
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

        Attaches a unique ``X-Request-ID`` header and never follows
        redirects (SDK-M4).
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
        return resp

    # ------------------------------------------------------------------
    # Organisations
    # ------------------------------------------------------------------

    async def create_organisation(
        self,
        name: str,
        industry: str,
        country: str,
        size: str = "medium",
        entity_type: str = "important",
        registration_number: Optional[str] = None,
        contact_email: Optional[str] = None,
    ) -> dict:
        """
        Create a new organisation (async).

        Mirrors :meth:`NIS2CompassClient.create_organisation`.
        Returns the server response dict (includes ``id``).
        """
        body: dict = {
            "name": name,
            "industry": industry,
            "country": country,
            "size": size,
            "entity_type": entity_type,
        }
        if registration_number is not None:
            body["registration_number"] = registration_number
        if contact_email is not None:
            body["contact_email"] = contact_email
        resp = await self._request("POST", "organisations", json=body)
        return resp.json()

    async def get_organisation(self, org_id: str) -> dict:
        """Return a single organisation by UUID (async)."""
        resp = await self._request("GET", f"organisations/{org_id}")
        return resp.json()

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    async def create_assessment(
        self,
        org_id: str,
        title: str,
        framework_version: str = "NIS2-2022/0383",
        scope: Optional[str] = None,
        assessor: Optional[str] = None,
        due_date: Optional[str] = None,
    ) -> dict:
        """
        Create a new NIS2 assessment under an organisation (async).

        Mirrors :meth:`NIS2CompassClient.create_assessment`.
        Returns the server response dict (includes ``id``).
        """
        body: dict = {
            "title": title,
            "framework_version": framework_version,
        }
        if scope is not None:
            body["scope"] = scope
        if assessor is not None:
            body["assessor"] = assessor
        if due_date is not None:
            body["due_date"] = due_date
        resp = await self._request("POST", f"organisations/{org_id}/assessments", json=body)
        return resp.json()

    async def get_assessment(self, assessment_id: str) -> dict:
        """Return a single assessment by UUID (async)."""
        resp = await self._request("GET", f"assessments/{assessment_id}")
        return resp.json()

    async def stream_report(
        self,
        assessment_id: str,
        format: str,
        dest,
        *,
        chunk_size: int = 8192,
    ) -> None:
        """
        Stream an assessment report to a file-like object (async).

        The response body is never buffered in full — suitable for large
        PDF reports.

        Parameters
        ----------
        assessment_id: UUID of the assessment.
        format:        pdf | json | sarif
        dest:          Writable file-like object opened in binary mode.
        chunk_size:    Streaming chunk size in bytes (default 8 192).
        """
        await self._ensure_authenticated()
        url = self._url(f"assessments/{assessment_id}/report")

        async with self._http.stream(
            "POST",
            url,
            params={"format": format},
            timeout=max(self._timeout, 120),
        ) as resp:
            if resp.status_code == 401:
                # Token expired mid-stream — re-authenticate and retry once.
                await self.authenticate()
                async with self._http.stream(
                    "POST",
                    url,
                    params={"format": format},
                    timeout=max(self._timeout, 120),
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

    async def get_organisations(self, page: int = 1, per_page: int = 20) -> list[dict]:
        """Return a list of organisations (async)."""
        resp = await self._request("GET", "organisations", params={"page": page, "per_page": per_page})
        return resp.json()

    async def patch_organisation(
        self,
        org_id: str,
        name: Optional[str] = None,
        industry: Optional[str] = None,
        country: Optional[str] = None,
        size: Optional[str] = None,
        entity_type: Optional[str] = None,
        registration_number: Optional[str] = None,
        contact_email: Optional[str] = None,
    ) -> dict:
        """Update an existing organisation (partial update, async)."""
        body: dict = {}
        if name is not None:
            body["name"] = name
        if industry is not None:
            body["industry"] = industry
        if country is not None:
            body["country"] = country
        if size is not None:
            body["size"] = size
        if entity_type is not None:
            body["entity_type"] = entity_type
        if registration_number is not None:
            body["registration_number"] = registration_number
        if contact_email is not None:
            body["contact_email"] = contact_email
        resp = await self._request("PATCH", f"organisations/{org_id}", json=body)
        return resp.json()

    async def delete_organisation(self, org_id: str) -> None:
        """Permanently delete an organisation and all its assessments (async)."""
        await self._request("DELETE", f"organisations/{org_id}")

    # ------------------------------------------------------------------
    # Assessments
    # ------------------------------------------------------------------

    async def list_assessments(
        self,
        org_id: str,
        *,
        status: Optional[str] = None,
        page: int = 1,
        per_page: int = 20,
    ) -> list[dict]:
        """Return a list of assessments for an organisation (async)."""
        params: dict = {"page": page, "per_page": per_page}
        if status is not None:
            params["status"] = status
        resp = await self._request("GET", f"organisations/{org_id}/assessments", params=params)
        return resp.json()

    async def patch_assessment(
        self,
        assessment_id: str,
        status: Optional[str] = None,
        title: Optional[str] = None,
        scope: Optional[str] = None,
        assessor: Optional[str] = None,
        due_date: Optional[str] = None,
    ) -> dict:
        """Update fields on an existing assessment (partial update, async)."""
        body: dict = {}
        if status is not None:
            body["status"] = status
        if title is not None:
            body["title"] = title
        if scope is not None:
            body["scope"] = scope
        if assessor is not None:
            body["assessor"] = assessor
        if due_date is not None:
            body["due_date"] = due_date
        resp = await self._request("PATCH", f"assessments/{assessment_id}", json=body)
        return resp.json()

    async def delete_assessment(self, assessment_id: str) -> None:
        """Permanently delete an assessment and all its controls (async)."""
        await self._request("DELETE", f"assessments/{assessment_id}")

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    async def list_controls(
        self,
        assessment_id: str,
        status: Optional[str] = None,
        nist_category: Optional[str] = None,
        measure_ref: Optional[str] = None,
    ) -> list[dict]:
        """Return all controls for an assessment (async)."""
        params: dict = {}
        if status is not None:
            params["status"] = status
        if nist_category is not None:
            params["nist_category"] = nist_category
        if measure_ref is not None:
            params["measure_ref"] = measure_ref
        resp = await self._request(
            "GET", f"assessments/{assessment_id}/controls", params=params or None
        )
        return resp.json()

    async def get_control(self, assessment_id: str, measure_ref: str) -> dict:
        """Return a single control by its measure reference letter (async)."""
        resp = await self._request("GET", f"assessments/{assessment_id}/controls/{measure_ref}")
        return resp.json()

    async def patch_control(
        self,
        assessment_id: str,
        measure_ref: str,
        status: Optional[str] = None,
        notes: Optional[str] = None,
        gap_description: Optional[str] = None,
        remediation_plan: Optional[str] = None,
        risk_score: Optional[float] = None,
        evidence: Optional[dict] = None,
        remediation_due: Optional[str] = None,
        remediation_owner: Optional[str] = None,
        remediation_status: Optional[str] = None,
        external_ticket_url: Optional[str] = None,
        remediation_notes: Optional[str] = None,
    ) -> dict:
        """Update a control within an assessment (partial update, async)."""
        body: dict = {}
        if status is not None:
            body["status"] = status
        if notes is not None:
            body["notes"] = notes
        if gap_description is not None:
            body["gap_description"] = gap_description
        if remediation_plan is not None:
            body["remediation_plan"] = remediation_plan
        if risk_score is not None:
            body["risk_score"] = risk_score
        if evidence is not None:
            body["evidence"] = evidence
        if remediation_due is not None:
            body["remediation_due"] = remediation_due
        if remediation_owner is not None:
            body["remediation_owner"] = remediation_owner
        if remediation_status is not None:
            body["remediation_status"] = remediation_status
        if external_ticket_url is not None:
            body["external_ticket_url"] = external_ticket_url
        if remediation_notes is not None:
            body["remediation_notes"] = remediation_notes
        resp = await self._request(
            "PATCH", f"assessments/{assessment_id}/controls/{measure_ref}", json=body
        )
        return resp.json()

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    async def list_artifacts(self, assessment_id: str) -> list[dict]:
        """Return all artifacts attached to an assessment (async)."""
        resp = await self._request("GET", f"assessments/{assessment_id}/artifacts")
        return resp.json()

    async def upload_artifact(
        self,
        assessment_id: str,
        file_path: str,
        artifact_type: str,
        control_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> dict:
        """Upload a file as an artifact attached to an assessment (async)."""
        file_path = os.path.expanduser(file_path)
        form_data: dict = {"type": artifact_type}
        if control_id is not None:
            form_data["control_id"] = control_id
        if description is not None:
            form_data["description"] = description
        with open(file_path, "rb") as fh:
            resp = await self._request(
                "POST",
                f"assessments/{assessment_id}/artifacts",
                files={"file": (os.path.basename(file_path), fh)},
                data=form_data,
                headers={"Content-Type": None},
            )
        return resp.json()

    async def get_artifact(self, artifact_id: str) -> dict:
        """Return artifact metadata by UUID (async)."""
        resp = await self._request("GET", f"artifacts/{artifact_id}")
        return resp.json()

    async def download_artifact(self, artifact_id: str, dest_path: str) -> None:
        """Download an artifact's file content and save it to *dest_path* (async)."""
        dest_path = os.path.expanduser(dest_path)
        await self._ensure_authenticated()
        url = self._url(f"artifacts/{artifact_id}/download")

        async def _stream() -> httpx.Response:
            return await self._http.get(url, timeout=self._timeout)

        resp = await _stream()
        if resp.status_code == 401:
            await self.authenticate()
            resp = await _stream()

        self._raise_for_status(resp)
        with open(dest_path, "wb") as fh:
            fh.write(resp.content)

    async def delete_artifact(self, artifact_id: str) -> None:
        """Permanently delete an artifact and its stored file (async)."""
        await self._request("DELETE", f"artifacts/{artifact_id}")

    # ------------------------------------------------------------------
    # API key management
    # ------------------------------------------------------------------

    async def list_api_keys(self) -> list[dict]:
        """Return all API keys belonging to the current actor (async)."""
        resp = await self._request("GET", "api-keys")
        return resp.json()

    async def create_api_key(self, label: Optional[str] = None, scope: str = "read_write") -> dict:
        """Create a new API key (async)."""
        body: dict = {"scope": scope}
        if label is not None:
            body["label"] = label
        resp = await self._request("POST", "api-keys", json=body)
        return resp.json()

    async def revoke_api_key(self, key_id: str) -> None:
        """Revoke (deactivate) an API key (async)."""
        await self._request("DELETE", f"api-keys/{key_id}")

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    async def generate_report(self, assessment_id: str, output_path: str) -> None:
        """
        Download the PDF compliance report for an assessment and save it
        to *output_path* on the local filesystem (async).
        """
        output_path = os.path.expanduser(output_path)
        await self._ensure_authenticated()
        url = self._url(f"assessments/{assessment_id}/report")

        async with self._http.stream(
            "POST", url, timeout=max(self._timeout, 120)
        ) as resp:
            if resp.status_code == 401:
                await self.authenticate()
                async with self._http.stream(
                    "POST", url, timeout=max(self._timeout, 120)
                ) as resp2:
                    if resp2.status_code != 200:
                        await resp2.aread()
                        raise APIError(resp2.status_code, resp2.text)
                    with open(output_path, "wb") as fh:
                        async for chunk in resp2.aiter_bytes(65536):
                            fh.write(chunk)
                return

            if resp.status_code != 200:
                await resp.aread()
                self._raise_for_status(resp)

            with open(output_path, "wb") as fh:
                async for chunk in resp.aiter_bytes(65536):
                    fh.write(chunk)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    async def get_audit_log(self, limit: int = 50, page: int = 1) -> list[dict]:
        """Return audit log entries (async). Entries are ordered newest-first."""
        resp = await self._request(
            "GET", "audit", params={"per_page": min(limit, 100), "page": page}
        )
        return resp.json()

    async def get_audit_entry(self, entry_id: str) -> dict:
        """Return a single audit log entry by UUID (async)."""
        resp = await self._request("GET", f"audit/{entry_id}")
        return resp.json()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def get_health(self) -> dict:
        """
        Return the aggregate platform health status (async).

        Does not require authentication.
        """
        resp = await self._http.get(self._url("health"), timeout=self._timeout)
        self._raise_for_status(resp)
        return resp.json()

    async def get_health_detail(self) -> dict:
        """
        Return detailed health information including per-dependency status (async).

        Requires a valid Bearer JWT.
        """
        resp = await self._request("GET", "health/detail")
        return resp.json()
