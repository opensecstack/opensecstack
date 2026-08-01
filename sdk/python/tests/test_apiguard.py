"""
pytest test suite for APIGuardClient.

Uses the ``responses`` library to intercept HTTP calls made by the underlying
``requests.Session`` so that no real network traffic is generated.
"""

from __future__ import annotations

import base64
import json
import time
from io import BytesIO
from typing import Optional
from unittest.mock import patch

import pytest
import responses as rsps_lib

from opensecstack.apiguard import APIGuardClient
from opensecstack.exceptions import AuthenticationError, RateLimitError

BASE_URL = "http://localhost"
API_KEY = "test-api-key"
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


def _expiring_soon_jwt() -> str:
    """Return a JWT that expires in 30 s (inside the 60 s proactive window)."""
    return _make_jwt(exp=int(time.time()) + 30)


@pytest.fixture()
def client() -> APIGuardClient:
    return APIGuardClient(BASE_URL, API_KEY)


# ---------------------------------------------------------------------------
# 1. Authentication and token caching
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_authenticate_success(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", json={"data": [], "total": 0, "page": 1, "per_page": 20}, status=200)

    client.list_scans()

    assert client._session.headers.get("Authorization") == f"Bearer {token}"
    assert client._jwt == token
    assert len([c for c in rsps_lib.calls if c.request.method == "POST"]) == 1


@rsps_lib.activate
def test_token_cached_no_reauth(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", json={"data": [], "total": 0, "page": 1, "per_page": 20}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", json={"data": [], "total": 0, "page": 1, "per_page": 20}, status=200)

    client.list_scans()
    client.list_scans()

    auth_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(auth_calls) == 1


# ---------------------------------------------------------------------------
# 2. 401 retry logic
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_401_triggers_reauth_and_retry(client: APIGuardClient) -> None:
    token_v1 = _fresh_jwt()
    token_v2 = _make_jwt(exp=int(time.time()) + 7200)

    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token_v1}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", status=401)
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token_v2}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", json={"data": [], "total": 0, "page": 1, "per_page": 20}, status=200)

    result = client.list_scans()
    assert result == []
    assert client._jwt == token_v2


@rsps_lib.activate
def test_401_does_not_retry_infinitely(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    token_v2 = _make_jwt(exp=int(time.time()) + 7200)

    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", status=401)
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token_v2}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", status=401)

    with pytest.raises(AuthenticationError):
        client.list_scans()

    get_calls = [c for c in rsps_lib.calls if c.request.method == "GET"]
    assert len(get_calls) == 2


# ---------------------------------------------------------------------------
# 3. Rate limit handling (429)
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_rate_limit_retry_after_le_60_sleeps_and_retries(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/scans",
        status=429,
        headers={"Retry-After": "5"},
        json={"error": "rate limited"},
    )
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/scans",
        json={"data": [], "total": 0, "page": 1, "per_page": 20},
        status=200,
    )

    with patch("time.sleep") as mock_sleep:
        result = client.list_scans()

    mock_sleep.assert_any_call(5)
    assert result == []


@rsps_lib.activate
def test_rate_limit_retry_after_gt_60_raises_immediately(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/scans",
        status=429,
        headers={"Retry-After": "300"},
        json={"error": "rate limited"},
    )

    with patch("time.sleep") as mock_sleep:
        with pytest.raises(RateLimitError) as exc_info:
            client.list_scans()

    mock_sleep.assert_not_called()
    assert exc_info.value.retry_after == 300


# ---------------------------------------------------------------------------
# 4. list_scans pagination
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_list_scans_pagination(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    page2_response = {"data": [{"id": "scan-1"}], "total": 1, "page": 2, "per_page": 10}
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans", json=page2_response, status=200)

    result = client.list_scans(page=2, per_page=10)

    assert result == [{"id": "scan-1"}]
    scans_call = next(c for c in rsps_lib.calls if "/scans" in c.request.url)
    assert "page=2" in scans_call.request.url
    assert "per_page=10" in scans_call.request.url


# ---------------------------------------------------------------------------
# 5. get_audit_log with page parameter
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_get_audit_log_page_parameter(client: APIGuardClient) -> None:
    token = _fresh_jwt()
    entries = [{"id": "log-1", "action": "scan.created"}]
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/audit", json=entries, status=200)

    result = client.get_audit_log(limit=25, page=2)

    assert result == entries
    audit_call = next(c for c in rsps_lib.calls if "/audit" in c.request.url)
    assert "page=2" in audit_call.request.url
    assert "per_page=25" in audit_call.request.url


# ---------------------------------------------------------------------------
# 6. upload_spec — multipart upload
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_upload_spec_multipart(client: APIGuardClient, tmp_path) -> None:  # type: ignore[no-untyped-def]
    token = _fresh_jwt()
    spec_file = tmp_path / "openapi.yaml"
    spec_file.write_text("openapi: 3.0.0\ninfo:\n  title: Test\n  version: '1.0'\npaths: {}\n")

    upload_response = {
        "spec_path": "/data/specs/abc123.yaml",
        "spec_hash": "sha256:abc123",
        "size": 60,
    }
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v1/specs/upload", json=upload_response, status=200)

    result = client.upload_spec(str(spec_file))

    assert result["spec_path"] == "/data/specs/abc123.yaml"
    upload_call = next(c for c in rsps_lib.calls if "/specs/upload" in c.request.url)
    # The request body should be multipart (Content-Type contains "multipart/form-data").
    content_type = upload_call.request.headers.get("Content-Type", "")
    assert "multipart/form-data" in content_type


# ---------------------------------------------------------------------------
# 7. Proactive token expiry triggers re-auth before request
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_proactive_token_refresh(client: APIGuardClient) -> None:
    expiring_token = _expiring_soon_jwt()
    fresh_token = _make_jwt(exp=int(time.time()) + 3600)

    # Prime the client with a near-expiry token.
    client._jwt = expiring_token
    client._token_expiry = float(int(time.time()) + 30)
    client._session.headers["Authorization"] = f"Bearer {expiring_token}"

    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": fresh_token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/scans",
        json={"data": [], "total": 0, "page": 1, "per_page": 20},
        status=200,
    )

    client.list_scans()

    assert client._jwt == fresh_token
    assert client._session.headers.get("Authorization") == f"Bearer {fresh_token}"
    auth_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(auth_calls) == 1


# ---------------------------------------------------------------------------
# 8. 5xx retry logic
# ---------------------------------------------------------------------------

_VALID_SCAN = {
    "id": "00000000-0000-0000-0000-000000000001",
    "target_url": "https://api.example.com",
    "status": "completed",
    "modules": [],
    "total_findings": 0,
    "critical_count": 0,
    "high_count": 0,
    "medium_count": 0,
    "low_count": 0,
    "info_count": 0,
    "created_at": "2025-01-01T00:00:00Z",
    "updated_at": "2025-01-01T00:00:00Z",
}


@rsps_lib.activate
def test_retry_on_5xx(client: APIGuardClient) -> None:
    """Client retries on 500 and succeeds on the third attempt."""
    token = _fresh_jwt()
    # Auth call
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    # First two scan calls return 500
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans/abc", json={"error": "server error"}, status=500)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans/abc", json={"error": "server error"}, status=500)
    # Third scan call succeeds
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/scans/abc", json=_VALID_SCAN, status=200)

    # Use a client configured for 3 retries so the two 500s are within budget.
    from opensecstack.apiguard import APIGuardClient as _AG
    retrying_client = _AG(BASE_URL, API_KEY, max_retries=3, retry_wait_base=0.0)

    with patch("time.sleep"):
        result = retrying_client.get_scan("abc")

    assert result is not None
    assert result["id"] == _VALID_SCAN["id"]
    scan_calls = [c for c in rsps_lib.calls if "/scans/abc" in c.request.url]
    assert len(scan_calls) == 3


@rsps_lib.activate
def test_no_retry_on_4xx(client: APIGuardClient) -> None:
    """Client does NOT retry on 404 — exactly one scan request is made."""
    from opensecstack.exceptions import NotFoundError

    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"access_token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/scans/abc",
        json={"code": "NOT_FOUND", "message": "not found"},
        status=404,
    )

    with pytest.raises(NotFoundError):
        client.get_scan("abc")

    scan_calls = [c for c in rsps_lib.calls if "/scans/abc" in c.request.url]
    # auth + exactly 1 scan call (no retry on 4xx)
    assert len(scan_calls) == 1
