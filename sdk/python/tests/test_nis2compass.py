"""
pytest test suite for NIS2CompassClient.

Uses the ``responses`` library to intercept HTTP calls made by the underlying
``requests.Session`` so that no real network traffic is generated.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional
from unittest.mock import patch

import pytest
import responses as rsps_lib

from opensecstack.exceptions import AuthenticationError, RateLimitError
from opensecstack.nis2compass import NIS2CompassClient

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
    """Return a JWT that expires 3600 s from now."""
    return _make_jwt(exp=int(time.time()) + 3600)


def _expired_jwt() -> str:
    """Return a JWT that expired 120 s ago (within the 60 s proactive window)."""
    return _make_jwt(exp=int(time.time()) - 120)


def _expiring_soon_jwt() -> str:
    """Return a JWT that expires in 30 s (inside the 60 s proactive window)."""
    return _make_jwt(exp=int(time.time()) + 30)


@pytest.fixture()
def client() -> NIS2CompassClient:
    return NIS2CompassClient(BASE_URL, API_KEY)


# ---------------------------------------------------------------------------
# 1. Successful authentication — JWT is acquired and stored
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_authenticate_success(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)

    client.get_organisations()

    assert client._session.headers.get("Authorization") == f"Bearer {token}"
    # Both the auth call and the GET should have been made.
    assert len(rsps_lib.calls) == 2


# ---------------------------------------------------------------------------
# 2. Token is cached — second request does NOT re-authenticate
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_token_cached(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)

    client.get_organisations()
    client.get_organisations()

    # Only one POST /auth/token should have been issued.
    auth_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(auth_calls) == 1


# ---------------------------------------------------------------------------
# 3. 401 response triggers re-authentication and a single retry
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_401_triggers_reauth_and_retry(client: NIS2CompassClient) -> None:
    token_v1 = _fresh_jwt()
    token_v2 = _make_jwt(exp=int(time.time()) + 7200)

    # Initial auth
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token_v1}, status=200)
    # First GET returns 401
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", status=401)
    # Re-auth returns a new token
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token_v2}, status=200)
    # Retry GET succeeds
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)

    result = client.get_organisations()
    assert result == []
    assert client._session.headers.get("Authorization") == f"Bearer {token_v2}"


# ---------------------------------------------------------------------------
# 4. 401 retry happens only once — does not loop infinitely
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_401_no_infinite_retry(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    token_v2 = _make_jwt(exp=int(time.time()) + 7200)

    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", status=401)
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token_v2}, status=200)
    # Second attempt also 401 — should raise, not loop.
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", status=401)

    with pytest.raises(AuthenticationError):
        client.get_organisations()

    get_calls = [c for c in rsps_lib.calls if c.request.method == "GET"]
    # Exactly two GET calls: the original and the single retry.
    assert len(get_calls) == 2


# ---------------------------------------------------------------------------
# 5. 429 with Retry-After <= 60 causes sleep and retry
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_rate_limit_with_retry_after_sleeps_and_retries(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/organisations",
        status=429,
        headers={"Retry-After": "2"},
        json={"error": "rate limited"},
    )
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)

    with patch("time.sleep") as mock_sleep:
        result = client.get_organisations()

    mock_sleep.assert_any_call(2)
    assert result == []


# ---------------------------------------------------------------------------
# 6. 429 with Retry-After > 60 raises RateLimitError immediately
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_rate_limit_large_retry_after_raises(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/organisations",
        status=429,
        headers={"Retry-After": "120"},
        json={"error": "rate limited"},
    )

    with patch("time.sleep") as mock_sleep:
        with pytest.raises(RateLimitError) as exc_info:
            client.get_organisations()

    mock_sleep.assert_not_called()
    assert exc_info.value.retry_after == 120


# ---------------------------------------------------------------------------
# 7. Proactive token expiry: near-expiry token triggers re-auth before request
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_proactive_token_refresh(client: NIS2CompassClient) -> None:
    expiring_token = _expiring_soon_jwt()
    fresh_token = _make_jwt(exp=int(time.time()) + 3600)

    # Prime the client with an expiring token (bypass the lock directly).
    client._session.headers["Authorization"] = f"Bearer {expiring_token}"
    client._token_expiry = float(int(time.time()) + 30)  # expires in 30 s < 60 s window

    # Re-auth returns a fresh token.
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": fresh_token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=[], status=200)

    client.get_organisations()

    assert client._session.headers.get("Authorization") == f"Bearer {fresh_token}"
    auth_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(auth_calls) == 1


# ---------------------------------------------------------------------------
# 8. Redirect (3xx) raises an error — redirects are NOT followed
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_redirect_is_not_followed(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(
        rsps_lib.GET,
        f"{BASE_URL}/api/v1/organisations",
        status=302,
        headers={"Location": "http://evil.example.com/steal"},
    )

    # With allow_redirects=False and max_redirects=0 the 3xx is returned as-is;
    # it is >= 400 after status check only for 4xx/5xx, but a 302 is not an
    # error HTTP status from _raise_for_status. The important assertion is that
    # the client does NOT make a second request to the Location URL.
    try:
        client.get_organisations()
    except Exception:
        pass  # Any error (TooManyRedirects, APIError, etc.) is acceptable here.

    # Verify no request was ever made to the evil host.
    for call in rsps_lib.calls:
        assert "evil.example.com" not in call.request.url


# ---------------------------------------------------------------------------
# 9. get_organisations returns a list
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_get_organisations(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    orgs = [{"id": "abc", "name": "Acme"}]
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/organisations", json=orgs, status=200)

    result = client.get_organisations()

    assert result == orgs


# ---------------------------------------------------------------------------
# 10. create_organisation returns the created org
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_create_organisation(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    org = {"id": "new-org-uuid", "name": "TestCorp", "industry": "tech", "country": "DE"}
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.POST, f"{BASE_URL}/api/v1/organisations", json=org, status=201)

    result = client.create_organisation(name="TestCorp", industry="tech", country="DE")

    assert result["id"] == "new-org-uuid"
    assert result["name"] == "TestCorp"


# ---------------------------------------------------------------------------
# 11. get_audit_log forwards the page parameter to the query string
# ---------------------------------------------------------------------------

@rsps_lib.activate
def test_get_audit_log_page_parameter(client: NIS2CompassClient) -> None:
    token = _fresh_jwt()
    entries = [{"id": "entry-1", "action": "login"}]
    rsps_lib.add(rsps_lib.POST, AUTH_URL, json={"token": token}, status=200)
    rsps_lib.add(rsps_lib.GET, f"{BASE_URL}/api/v1/audit", json=entries, status=200)

    result = client.get_audit_log(limit=10, page=3)

    assert result == entries
    # Verify the query string included page=3.
    audit_call = next(c for c in rsps_lib.calls if "/audit" in c.request.url)
    assert "page=3" in audit_call.request.url
    assert "per_page=10" in audit_call.request.url
