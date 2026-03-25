"""
opensecstack SDK — NIS2 Compass client.

Authentication uses a two-step flow: the API key is exchanged for a
short-lived JWT via ``POST /api/v1/auth/token``.  The JWT is cached in
the session and refreshed automatically on HTTP 401.
"""

from __future__ import annotations

import os
import threading
from typing import Optional

import requests

from .exceptions import APIError, AuthenticationError, NotFoundError


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

    def __init__(self, base_url: str, api_key: str, timeout: int = 30) -> None:
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )
        self._auth_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _authenticate(self) -> None:
        """Exchange the API key for a JWT and store it in the session."""
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
        self._session.headers["Authorization"] = f"Bearer {token}"

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 404:
            raise NotFoundError(resp.text)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        """Execute a request, authenticating (and retrying once on 401)."""
        with self._auth_lock:
            if "Authorization" not in self._session.headers:
                self._authenticate()
        resp = getattr(self._session, method)(self._url(path), timeout=self._timeout, **kwargs)
        if resp.status_code == 401:
            # Token expired — re-authenticate and retry once.
            with self._auth_lock:
                self._authenticate()
            resp = getattr(self._session, method)(self._url(path), timeout=self._timeout, **kwargs)
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
    # Reports
    # ------------------------------------------------------------------

    def generate_report(self, assessment_id: str, output_path: str) -> None:
        """
        Download the PDF compliance report for an assessment and save it
        to *output_path* on the local filesystem.

        The directory containing *output_path* must already exist.
        """
        # Ensure we have a valid token before the long-running streamed request.
        with self._auth_lock:
            if "Authorization" not in self._session.headers:
                self._authenticate()

        report_timeout = max(self._timeout, 120)

        def _stream_report() -> requests.Response:
            return self._session.post(
                self._url(f"assessments/{assessment_id}/report"),
                timeout=report_timeout,
                stream=True,
            )

        resp = _stream_report()
        if resp.status_code == 401:
            # Token expired — re-authenticate and retry once.
            with self._auth_lock:
                self._authenticate()
            resp = _stream_report()

        self._raise_for_status(resp)
        output_path = os.path.expanduser(output_path)
        with open(output_path, "wb") as fh:
            for chunk in resp.iter_content(chunk_size=65536):
                fh.write(chunk)

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------

    def get_audit_log(self, limit: int = 50) -> list[dict]:
        """
        Return the *limit* most-recent audit log entries (default 50).

        Entries are ordered newest-first.
        """
        resp = self._get("audit", params={"per_page": min(limit, 100)})
        return resp.json()
