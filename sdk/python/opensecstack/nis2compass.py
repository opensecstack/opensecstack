"""
opensecstack SDK — NIS2 Compass client.

All requests are authenticated with a static API key passed in the
``X-API-Key`` header, matching the NIS2 Compass middleware contract.
"""

from __future__ import annotations

import os
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
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "X-API-Key": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _raise_for_status(self, resp: requests.Response) -> None:
        if resp.status_code == 401:
            raise AuthenticationError("Invalid or missing API key")
        if resp.status_code == 404:
            raise NotFoundError(resp.text)
        if resp.status_code >= 400:
            try:
                detail = resp.json()
            except Exception:
                detail = resp.text
            raise APIError(resp.status_code, detail)

    def _get(self, path: str, params: Optional[dict] = None) -> requests.Response:
        resp = self._session.get(self._url(path), params=params, timeout=self._timeout)
        self._raise_for_status(resp)
        return resp

    def _post(self, path: str, json: Optional[dict] = None) -> requests.Response:
        resp = self._session.post(self._url(path), json=json, timeout=self._timeout)
        self._raise_for_status(resp)
        return resp

    def _patch(self, path: str, json: Optional[dict] = None) -> requests.Response:
        resp = self._session.patch(self._url(path), json=json, timeout=self._timeout)
        self._raise_for_status(resp)
        return resp

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

    # ------------------------------------------------------------------
    # Controls
    # ------------------------------------------------------------------

    def patch_control(
        self,
        assessment_id: str,
        measure_ref: str,
        status: str,
        notes: str = "",
        gap_description: Optional[str] = None,
        remediation_plan: Optional[str] = None,
        risk_score: Optional[float] = None,
    ) -> dict:
        """
        Update a control within an assessment.

        Parameters
        ----------
        assessment_id: UUID of the assessment.
        measure_ref:   Single letter ``a``–``j`` (NIS2 Art.21 measure).
        status:        One of ``not_assessed``, ``compliant``,
                       ``partially_compliant``, ``non_compliant``,
                       ``not_applicable``.
        notes:         Optional free-text notes.
        """
        body: dict = {"status": status}
        if notes:
            body["notes"] = notes
        if gap_description is not None:
            body["gap_description"] = gap_description
        if remediation_plan is not None:
            body["remediation_plan"] = remediation_plan
        if risk_score is not None:
            body["risk_score"] = risk_score
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
        resp = self._session.get(
            self._url(f"assessments/{assessment_id}/report"),
            params={"format": "pdf"},
            timeout=max(self._timeout, 120),  # PDF generation may take longer
            stream=True,
        )
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
