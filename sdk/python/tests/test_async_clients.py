"""
pytest-asyncio test suite for AsyncAPIGuardClient and AsyncNIS2CompassClient.

Uses ``respx`` to intercept httpx calls so that no real network traffic is
generated.  Each test is self-contained: mocks are declared inline so intent
is immediately obvious.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional

import httpx
import pytest
import pytest_asyncio
import respx

from opensecstack import AsyncAPIGuardClient, AsyncNIS2CompassClient
from opensecstack.exceptions import AuthenticationError, RateLimitError

BASE_URL = "http://localhost"
CLIENT_ID = "test-client-id"
CLIENT_SECRET = "test-client-secret"
AUTH_URL = f"{BASE_URL}/api/v1/auth/token"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_jwt(exp: Optional[int] = None) -> str:
    """Build a syntactically valid (but unsigned) JWT with the given exp."""
    header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
    payload_dict: dict = {"sub": "test", "iat": int(time.time())}
    if exp is not None:
        payload_dict["exp"] = exp
    payload = (
        base64.urlsafe_b64encode(json.dumps(payload_dict).encode())
        .rstrip(b"=")
        .decode()
    )
    return f"{header}.{payload}.fakesig"


def _fresh_jwt() -> str:
    return _make_jwt(exp=int(time.time()) + 3600)


# ---------------------------------------------------------------------------
# 1. test_async_authenticate_success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_authenticate_success() -> None:
    """POST /auth/token → 200: token is stored and set as Authorization header."""
    token = _fresh_jwt()
    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.get(f"{BASE_URL}/api/v1/scans").mock(
        return_value=httpx.Response(200, json=[])
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        await client.authenticate()
        assert client._jwt == token
        assert client._http.headers.get("Authorization") == f"Bearer {token}"


# ---------------------------------------------------------------------------
# 2. test_async_authenticate_failure
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_authenticate_failure() -> None:
    """POST /auth/token → 401: AuthenticationError is raised."""
    respx.post(AUTH_URL).mock(return_value=httpx.Response(401, json={"error": "unauthorized"}))

    client = AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
    try:
        with pytest.raises(AuthenticationError):
            await client.authenticate()
    finally:
        await client._http.aclose()


# ---------------------------------------------------------------------------
# 3. test_async_get_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_scan() -> None:
    """GET /api/v1/scans/{id} → 200: returns the scan dict."""
    token = _fresh_jwt()
    scan_id = "scan-abc-123"
    scan_data = {"id": scan_id, "status": "completed", "target": "https://api.example.com"}

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.get(f"{BASE_URL}/api/v1/scans/{scan_id}").mock(
        return_value=httpx.Response(200, json=scan_data)
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.get_scan(scan_id)

    assert result["id"] == scan_id
    assert result["status"] == "completed"


# ---------------------------------------------------------------------------
# 4. test_async_create_scan
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_create_scan() -> None:
    """POST /api/v1/scans → 201: returns the new scan dict."""
    token = _fresh_jwt()
    new_scan = {"id": "scan-new-001", "status": "pending"}

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.post(f"{BASE_URL}/api/v1/scans").mock(
        return_value=httpx.Response(201, json=new_scan)
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.create_scan(spec_url="https://api.example.com/openapi.json")

    assert result["id"] == "scan-new-001"
    assert result["status"] == "pending"


# ---------------------------------------------------------------------------
# 5. test_async_list_scans
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_list_scans() -> None:
    """GET /api/v1/scans → 200: returns the items list."""
    token = _fresh_jwt()
    scans_payload = {
        "items": [
            {"id": "scan-1", "status": "completed"},
            {"id": "scan-2", "status": "running"},
        ],
        "total": 2,
        "page": 1,
        "per_page": 20,
    }

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.get(f"{BASE_URL}/api/v1/scans").mock(
        return_value=httpx.Response(200, json=scans_payload)
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.list_scans()

    assert len(result) == 2
    assert result[0]["id"] == "scan-1"
    assert result[1]["id"] == "scan-2"


# ---------------------------------------------------------------------------
# 6. test_async_get_findings
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_findings() -> None:
    """GET /api/v1/scans/{id}/findings → 200: returns the findings list."""
    token = _fresh_jwt()
    scan_id = "scan-findings-001"
    findings_payload = [
        {"id": "finding-1", "severity": "HIGH", "title": "SQL Injection"},
        {"id": "finding-2", "severity": "MEDIUM", "title": "Missing auth"},
    ]

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.get(f"{BASE_URL}/api/v1/scans/{scan_id}/findings").mock(
        return_value=httpx.Response(200, json=findings_payload)
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.get_findings(scan_id)

    assert len(result) == 2
    assert result[0]["severity"] == "HIGH"
    assert result[1]["title"] == "Missing auth"


# ---------------------------------------------------------------------------
# 7. test_async_rate_limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_rate_limit() -> None:
    """GET with 429 and Retry-After: 30 raises RateLimitError with retry_after=30."""
    token = _fresh_jwt()

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    # Retry-After > 60 is NOT auto-retried by the SDK, so it raises immediately.
    respx.get(f"{BASE_URL}/api/v1/scans").mock(
        return_value=httpx.Response(
            429,
            json={"error": "rate limited"},
            headers={"Retry-After": "30"},
        )
    )
    # Second call after potential sleep would succeed, but the SDK does NOT
    # auto-sleep for > 60 s; Retry-After=30 is <= 60, so it will sleep and
    # retry once.  Provide the retry response so the mock is satisfied.
    respx.get(f"{BASE_URL}/api/v1/scans").mock(
        return_value=httpx.Response(429, json={"error": "rate limited"}, headers={"Retry-After": "30"})
    )

    client = AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET)
    try:
        with pytest.raises(RateLimitError) as exc_info:
            # The SDK sleeps and retries once on <=60 s; to avoid actually
            # sleeping in CI patch asyncio.sleep out.
            import asyncio
            from unittest.mock import patch, AsyncMock

            with patch("asyncio.sleep", new_callable=AsyncMock):
                await client.list_scans()

        assert exc_info.value.retry_after == 30
    finally:
        await client._http.aclose()


# ---------------------------------------------------------------------------
# 8. test_async_nis2_create_organisation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_nis2_create_organisation() -> None:
    """POST /api/v1/organisations → 201: returns the created organisation dict."""
    token = _fresh_jwt()
    org_data = {
        "id": "org-uuid-001",
        "name": "TestCorp",
        "industry": "finance",
        "country": "DE",
        "size": "large",
        "entity_type": "essential",
    }

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"token": token}))
    respx.post(f"{BASE_URL}/api/v1/organisations").mock(
        return_value=httpx.Response(201, json=org_data)
    )

    async with AsyncNIS2CompassClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.create_organisation(
            name="TestCorp", industry="finance", country="DE", size="large"
        )

    assert result["id"] == "org-uuid-001"
    assert result["name"] == "TestCorp"
    assert result["country"] == "DE"


# ---------------------------------------------------------------------------
# 9. test_async_nis2_get_assessment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_nis2_get_assessment() -> None:
    """GET /api/v1/assessments/{id} → 200: returns the assessment dict."""
    token = _fresh_jwt()
    assessment_id = "assessment-001"
    assessment_data = {
        "id": assessment_id,
        "title": "Q1 2026 NIS2 Assessment",
        "status": "in_progress",
        "framework_version": "NIS2-2022/0383",
        "controls": [],
    }

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"token": token}))
    respx.get(f"{BASE_URL}/api/v1/assessments/{assessment_id}").mock(
        return_value=httpx.Response(200, json=assessment_data)
    )

    async with AsyncNIS2CompassClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        result = await client.get_assessment(assessment_id)

    assert result["id"] == assessment_id
    assert result["title"] == "Q1 2026 NIS2 Assessment"
    assert result["framework_version"] == "NIS2-2022/0383"


# ---------------------------------------------------------------------------
# 10. test_async_context_manager
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_context_manager() -> None:
    """__aenter__/__aexit__ work correctly: client usable inside block, closed after."""
    token = _fresh_jwt()
    scan_id = "scan-ctx-001"

    respx.post(AUTH_URL).mock(return_value=httpx.Response(200, json={"access_token": token}))
    respx.get(f"{BASE_URL}/api/v1/scans/{scan_id}").mock(
        return_value=httpx.Response(200, json={"id": scan_id, "status": "completed"})
    )

    async with AsyncAPIGuardClient(BASE_URL, CLIENT_ID, CLIENT_SECRET) as client:
        # __aenter__ returns the client itself
        assert client is not None
        result = await client.get_scan(scan_id)
        assert result["id"] == scan_id

    # After __aexit__ the underlying httpx.AsyncClient should be closed;
    # further requests would raise httpx.RuntimeError.
    with pytest.raises(Exception):
        await client.get_scan(scan_id)
