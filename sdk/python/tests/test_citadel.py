"""
pytest test suite for CITADELClient and AsyncCITADELClient.

Uses the ``responses`` library to intercept HTTP calls made by the underlying
``requests.Session`` (sync client) and ``respx`` to intercept ``httpx`` calls
(async client) so that no real network traffic is generated.

CITADEL authentication is HMAC-SHA256 signing on every POST — there is no
JWT auth endpoint.  Each test therefore configures only the specific
endpoint under test.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from datetime import datetime, timezone
from typing import Optional
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
import responses as rsps_lib

from opensecstack.citadel import (
    Advisory,
    AdvisoryAffects,
    AsyncCITADELClient,
    CITADELClient,
    CreateAdvisoryRequest,
    GetEventsOptions,
    ListAdvisoriesOptions,
    PatchAdvisoryRequest,
    SecurityEvent,
)

BASE_URL = "http://localhost"
SHARED_SECRET = "test-shared-secret"
EVENTS_URL = f"{BASE_URL}/api/v1/events"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    id: str = "evt-001",
    event_type: str = "apiguard.scan.completed",
    source: str = "apiguard",
    chain_hash: str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
    severity: str = "info",
    payload: Optional[dict] = None,
) -> SecurityEvent:
    """Build a minimal SecurityEvent for use in tests."""
    return SecurityEvent(
        id=id,
        event_type=event_type,
        source=source,
        actor_id="actor-123",
        actor_type="api_key",
        resource_type="scan",
        resource_id="res-001",
        severity=severity,
        payload=payload or {"score": 42},
        chain_hash=chain_hash,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
    )


def _make_event_dict(
    id: str = "evt-001",
    event_type: str = "apiguard.scan.completed",
    source: str = "apiguard",
    chain_hash: str = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899",
) -> dict:
    """Build a dict that can be JSON-serialised and returned by the mock server."""
    return {
        "id": id,
        "event_type": event_type,
        "source": source,
        "actor_id": "actor-123",
        "actor_type": "api_key",
        "resource_type": "scan",
        "resource_id": "res-001",
        "severity": "info",
        "payload": {"score": 42},
        "chain_hash": chain_hash,
        "timestamp": "2026-01-01T12:00:00+00:00",
    }


def _compute_expected_signature(secret: str, body: bytes) -> str:
    """Return 'sha256=<hex>' HMAC-SHA256 of body under secret."""
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return "sha256=" + digest


@pytest.fixture()
def client() -> CITADELClient:
    return CITADELClient(BASE_URL, SHARED_SECRET, max_retries=0)


# ---------------------------------------------------------------------------
# 1. send_event — basic success
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_send_event_success(client: CITADELClient) -> None:
    """POST /api/v1/events → 201: no exception is raised."""
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={}, status=201)

    event = _make_event()
    client.send_event(event)  # should not raise

    assert len([c for c in rsps_lib.calls if c.request.method == "POST"]) == 1


# ---------------------------------------------------------------------------
# 2. send_event — HMAC signature header is present and correct
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_send_event_hmac_signature_header(client: CITADELClient) -> None:
    """The X-Citadel-Signature header contains the correct HMAC-SHA256."""
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={}, status=200)

    event = _make_event()
    client.send_event(event)

    post_call = next(c for c in rsps_lib.calls if c.request.method == "POST")
    sig_header = post_call.request.headers.get("X-Citadel-Signature", "")
    assert sig_header.startswith("sha256="), f"expected 'sha256=…', got: {sig_header!r}"

    # Re-derive the expected signature from the actual body sent.
    body_sent = post_call.request.body
    if isinstance(body_sent, str):
        body_sent = body_sent.encode()
    expected_sig = _compute_expected_signature(SHARED_SECRET, body_sent)
    assert sig_header == expected_sig, (
        f"HMAC mismatch: header={sig_header!r} expected={expected_sig!r}"
    )


# ---------------------------------------------------------------------------
# 3. send_event — 4xx is not retried
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_send_event_4xx_not_retried() -> None:
    """A 4xx response from CITADEL raises IOError without retrying."""
    client = CITADELClient(BASE_URL, SHARED_SECRET, max_retries=3, retry_wait_base=0.0)
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={"error": "bad request"}, status=400)

    with pytest.raises(IOError):
        client.send_event(_make_event())

    post_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(post_calls) == 1, "4xx should not be retried"


# ---------------------------------------------------------------------------
# 4. send_event — 5xx triggers retries, succeeds on 3rd attempt
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_send_event_5xx_retried_and_succeeds() -> None:
    """Client retries on 500 and succeeds when the server recovers."""
    client = CITADELClient(BASE_URL, SHARED_SECRET, max_retries=3, retry_wait_base=0.0)
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={"error": "server error"}, status=500)
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={"error": "server error"}, status=500)
    rsps_lib.add(rsps_lib.POST, EVENTS_URL, json={}, status=201)

    with patch("time.sleep"):
        client.send_event(_make_event())

    post_calls = [c for c in rsps_lib.calls if c.request.method == "POST"]
    assert len(post_calls) == 3, f"expected 3 attempts, got {len(post_calls)}"


# ---------------------------------------------------------------------------
# 5. send_event — disabled mode (empty base_url) is a no-op
# ---------------------------------------------------------------------------


def test_send_event_disabled_is_noop() -> None:
    """CITADELClient with empty base_url returns immediately without I/O."""
    client = CITADELClient("", SHARED_SECRET)
    # No mock server — any real HTTP call would fail.
    event = _make_event()
    client.send_event(event)  # should not raise or make any network call


# ---------------------------------------------------------------------------
# 6. get_events — plain list response
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_events_plain_list(client: CITADELClient) -> None:
    """GET /api/v1/events → 200 with JSON array: returns parsed SecurityEvent list."""
    events_data = [
        _make_event_dict(id="e-1", event_type="apiguard.scan.completed"),
        _make_event_dict(id="e-2", event_type="nis2compass.control.updated", source="nis2compass"),
    ]
    rsps_lib.add(rsps_lib.GET, EVENTS_URL, json=events_data, status=200)

    result = client.get_events()

    assert len(result) == 2
    assert result[0].id == "e-1"
    assert result[0].event_type == "apiguard.scan.completed"
    assert result[1].id == "e-2"
    assert result[1].source == "nis2compass"


# ---------------------------------------------------------------------------
# 7. get_events — paginated envelope {"items": [...]}
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_events_envelope(client: CITADELClient) -> None:
    """GET /api/v1/events → 200 with envelope: items are unwrapped correctly."""
    envelope = {
        "items": [_make_event_dict(id="env-1")],
        "total": 1,
        "page": 1,
    }
    rsps_lib.add(rsps_lib.GET, EVENTS_URL, json=envelope, status=200)

    result = client.get_events()

    assert len(result) == 1
    assert result[0].id == "env-1"


# ---------------------------------------------------------------------------
# 8. get_events — filters are forwarded as query parameters
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_events_filters_forwarded(client: CITADELClient) -> None:
    """source and event_type filters appear in the query string."""
    rsps_lib.add(rsps_lib.GET, EVENTS_URL, json=[], status=200)

    opts = GetEventsOptions(source="apiguard", event_type="apiguard.scan.completed", limit=5, page=2)
    client.get_events(opts)

    get_call = next(c for c in rsps_lib.calls if c.request.method == "GET")
    assert "source=apiguard" in get_call.request.url
    assert "event_type=apiguard.scan.completed" in get_call.request.url
    assert "limit=5" in get_call.request.url
    assert "page=2" in get_call.request.url


# ---------------------------------------------------------------------------
# 9. get_events — disabled mode returns empty list
# ---------------------------------------------------------------------------


def test_get_events_disabled_returns_empty() -> None:
    """CITADELClient with empty base_url returns [] for get_events."""
    client = CITADELClient("", SHARED_SECRET)
    result = client.get_events()
    assert result == []


# ---------------------------------------------------------------------------
# 10. get_event — success by ID
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_event_by_id(client: CITADELClient) -> None:
    """GET /api/v1/events/{id} → 200: returns a single SecurityEvent."""
    event_id = "evt-specific-123"
    event_data = _make_event_dict(id=event_id, event_type="citadel.hard_stop", source="apiguard")
    rsps_lib.add(rsps_lib.GET, f"{EVENTS_URL}/{event_id}", json=event_data, status=200)

    result = client.get_event(event_id)

    assert result.id == event_id
    assert result.event_type == "citadel.hard_stop"


# ---------------------------------------------------------------------------
# 11. get_event — 404 raises HTTPError
# ---------------------------------------------------------------------------


@rsps_lib.activate
def test_get_event_not_found(client: CITADELClient) -> None:
    """GET /api/v1/events/{id} → 404: raises requests.HTTPError."""
    import requests

    rsps_lib.add(rsps_lib.GET, f"{EVENTS_URL}/no-such-event", json={"error": "not found"}, status=404)

    with pytest.raises(requests.HTTPError):
        client.get_event("no-such-event")


# ---------------------------------------------------------------------------
# 12. get_event — disabled mode raises ValueError
# ---------------------------------------------------------------------------


def test_get_event_disabled_raises() -> None:
    """CITADELClient with empty base_url raises ValueError for get_event."""
    client = CITADELClient("", SHARED_SECRET)
    with pytest.raises(ValueError, match="disabled"):
        client.get_event("any-id")


# ---------------------------------------------------------------------------
# 13. verify_chain — valid two-event chain
# ---------------------------------------------------------------------------


def test_verify_chain_valid(client: CITADELClient) -> None:
    """verify_chain does not raise for a correctly linked chain."""
    payload1 = {"step": 1}
    payload1_bytes = json.dumps(payload1, separators=(",", ":"), sort_keys=True).encode()
    prev_hash = "genesis0000000000000000000000000000000000000000000000000000000000"
    raw = prev_hash.encode() + payload1_bytes
    chain_hash1 = hashlib.sha256(raw).hexdigest()

    ev0 = _make_event(
        id="e0",
        chain_hash=prev_hash,
        payload={"step": 0},
    )
    ev1 = _make_event(
        id="e1",
        chain_hash=chain_hash1,
        payload=payload1,
    )

    client.verify_chain([ev0, ev1])  # must not raise


# ---------------------------------------------------------------------------
# 14. verify_chain — broken link raises ValueError
# ---------------------------------------------------------------------------


def test_verify_chain_broken_raises(client: CITADELClient) -> None:
    """verify_chain raises ValueError when the chain hash is wrong."""
    ev0 = _make_event(id="e0", chain_hash="aaaaaaaaa")
    ev1 = _make_event(id="e1", chain_hash="this-is-wrong")

    with pytest.raises(ValueError, match="chain broken"):
        client.verify_chain([ev0, ev1])


# ---------------------------------------------------------------------------
# 15. verify_chain — single event and empty list are valid
# ---------------------------------------------------------------------------


def test_verify_chain_single_and_empty(client: CITADELClient) -> None:
    """verify_chain accepts zero and one-element lists without error."""
    client.verify_chain([])
    client.verify_chain([_make_event(id="only")])


# ---------------------------------------------------------------------------
# AUGUR advisory tests
# ---------------------------------------------------------------------------

ADVISORIES_URL = f"{BASE_URL}/api/v1/augur/advisories"


def _make_advisory_dict(
    id: str = "adv-001",
    title: str = "Test Advisory",
    severity: str = "high",
    status: str = "draft",
) -> dict:
    return {
        "id": id,
        "title": title,
        "description": "A test advisory",
        "severity": severity,
        "status": status,
        "affects": [{"component": "apiguard", "version_min": "0.1.0", "version_max": "0.1.5"}],
        "cve": "CVE-2026-0001",
        "references": ["https://example.com/vuln"],
        "created_at": "2026-03-15T10:00:00+00:00",
        "updated_at": "2026-03-15T10:00:00+00:00",
    }


# 16. create_advisory — POST with HMAC signature

@rsps_lib.activate
def test_create_advisory(client: CITADELClient) -> None:
    """POST /api/v1/augur/advisories → 201: returns Advisory."""
    adv_data = _make_advisory_dict()
    rsps_lib.add(rsps_lib.POST, ADVISORIES_URL, json=adv_data, status=201)

    req = CreateAdvisoryRequest(
        title="Test Advisory",
        description="A test advisory",
        severity="high",
        affects=[AdvisoryAffects(component="apiguard", version_min="0.1.0", version_max="0.1.5")],
        cve="CVE-2026-0001",
    )
    result = client.create_advisory(req)

    assert result.id == "adv-001"
    assert result.severity == "high"
    assert result.status == "draft"
    assert len(result.affects) == 1
    assert result.affects[0].component == "apiguard"

    post_call = next(c for c in rsps_lib.calls if c.request.method == "POST")
    assert "X-Citadel-Signature" in post_call.request.headers


# 17. list_advisories — GET with filter params

@rsps_lib.activate
def test_list_advisories(client: CITADELClient) -> None:
    """GET /api/v1/augur/advisories → 200: returns list."""
    rsps_lib.add(rsps_lib.GET, ADVISORIES_URL, json=[_make_advisory_dict()], status=200)

    result = client.list_advisories(ListAdvisoriesOptions(status="draft", severity="high"))

    assert len(result) == 1
    assert result[0].title == "Test Advisory"


# 18. get_advisory — GET by ID

@rsps_lib.activate
def test_get_advisory(client: CITADELClient) -> None:
    """GET /api/v1/augur/advisories/{id} → 200."""
    adv_data = _make_advisory_dict(id="adv-specific")
    rsps_lib.add(rsps_lib.GET, f"{ADVISORIES_URL}/adv-specific", json=adv_data, status=200)

    result = client.get_advisory("adv-specific")
    assert result.id == "adv-specific"


# 19. patch_advisory — PATCH updates status

@rsps_lib.activate
def test_patch_advisory(client: CITADELClient) -> None:
    """PATCH /api/v1/augur/advisories/{id} → 200."""
    updated = _make_advisory_dict(id="adv-001", status="published")
    rsps_lib.add(rsps_lib.PATCH, f"{ADVISORIES_URL}/adv-001", json=updated, status=200)

    req = PatchAdvisoryRequest(status="published")
    result = client.patch_advisory("adv-001", req)

    assert result.status == "published"


# 20. delete_advisory — DELETE

@rsps_lib.activate
def test_delete_advisory(client: CITADELClient) -> None:
    """DELETE /api/v1/augur/advisories/{id} → 204."""
    rsps_lib.add(rsps_lib.DELETE, f"{ADVISORIES_URL}/adv-001", status=204)

    client.delete_advisory("adv-001")  # should not raise


# 21. get_active_advisories — convenience wrapper

@rsps_lib.activate
def test_get_active_advisories(client: CITADELClient) -> None:
    """get_active_advisories passes status=published to list_advisories."""
    published = _make_advisory_dict(status="published")
    rsps_lib.add(rsps_lib.GET, ADVISORIES_URL, json=[published], status=200)

    result = client.get_active_advisories()

    assert len(result) == 1
    assert result[0].status == "published"
    # Verify the query param was sent
    call = next(c for c in rsps_lib.calls if c.request.method == "GET")
    assert "status=published" in call.request.url


# 22. disabled mode — list returns empty, create raises

def test_advisory_disabled_mode() -> None:
    """Advisory methods respect disabled mode (empty base_url)."""
    disabled = CITADELClient("", SHARED_SECRET)

    assert disabled.list_advisories() == []
    disabled.delete_advisory("any")  # no-op, no raise

    with pytest.raises(ValueError, match="disabled"):
        disabled.create_advisory(CreateAdvisoryRequest(title="x", description="x", severity="low"))
    with pytest.raises(ValueError, match="disabled"):
        disabled.get_advisory("any")
    with pytest.raises(ValueError, match="disabled"):
        disabled.patch_advisory("any", PatchAdvisoryRequest(title="x"))


# ---------------------------------------------------------------------------
# Async tests (using respx + pytest-asyncio)
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 16. async send_event — basic success
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_send_event_success() -> None:
    """AsyncCITADELClient.send_event: POST /api/v1/events → 201 succeeds."""
    respx.post(EVENTS_URL).mock(return_value=httpx.Response(201, json={}))

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        event = _make_event()
        await client.send_event(event)


# ---------------------------------------------------------------------------
# 17. async send_event — HMAC signature header forwarded
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_send_event_signature_header() -> None:
    """AsyncCITADELClient.send_event: X-Citadel-Signature is present and has sha256= prefix."""
    route = respx.post(EVENTS_URL).mock(return_value=httpx.Response(200, json={}))

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        await client.send_event(_make_event())

    assert route.called
    request = route.calls.last.request
    sig = request.headers.get("x-citadel-signature", "")
    assert sig.startswith("sha256="), f"signature prefix wrong: {sig!r}"


# ---------------------------------------------------------------------------
# 18. async send_event — disabled mode is a no-op
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_send_event_disabled_noop() -> None:
    """AsyncCITADELClient with empty base_url returns without I/O."""
    async with AsyncCITADELClient("", SHARED_SECRET) as client:
        await client.send_event(_make_event())  # must not raise


# ---------------------------------------------------------------------------
# 19. async get_events — plain list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_events_plain_list() -> None:
    """AsyncCITADELClient.get_events: returns parsed SecurityEvent list."""
    events_data = [
        _make_event_dict(id="ae-1"),
        _make_event_dict(id="ae-2"),
    ]
    respx.get(EVENTS_URL).mock(return_value=httpx.Response(200, json=events_data))

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        result = await client.get_events()

    assert len(result) == 2
    assert result[0].id == "ae-1"
    assert result[1].id == "ae-2"


# ---------------------------------------------------------------------------
# 20. async get_events — paginated envelope
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_events_envelope() -> None:
    """AsyncCITADELClient.get_events: {"items": [...]} envelope is unwrapped."""
    envelope = {
        "items": [_make_event_dict(id="ae-env-1")],
        "total": 1,
    }
    respx.get(EVENTS_URL).mock(return_value=httpx.Response(200, json=envelope))

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        result = await client.get_events()

    assert len(result) == 1
    assert result[0].id == "ae-env-1"


# ---------------------------------------------------------------------------
# 21. async get_events — disabled mode returns empty list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_get_events_disabled_returns_empty() -> None:
    """AsyncCITADELClient with empty base_url returns [] for get_events."""
    async with AsyncCITADELClient("", SHARED_SECRET) as client:
        result = await client.get_events()
    assert result == []


# ---------------------------------------------------------------------------
# 22. async get_event — success by ID
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_event_by_id() -> None:
    """AsyncCITADELClient.get_event: returns parsed SecurityEvent for given ID."""
    event_id = "async-evt-456"
    event_data = _make_event_dict(id=event_id, event_type="citadel.vigil.amber")
    respx.get(f"{EVENTS_URL}/{event_id}").mock(
        return_value=httpx.Response(200, json=event_data)
    )

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        result = await client.get_event(event_id)

    assert result.id == event_id
    assert result.event_type == "citadel.vigil.amber"


# ---------------------------------------------------------------------------
# 23. async get_event — 404 raises
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@respx.mock
async def test_async_get_event_not_found() -> None:
    """AsyncCITADELClient.get_event: 404 raises httpx.HTTPStatusError."""
    respx.get(f"{EVENTS_URL}/missing").mock(
        return_value=httpx.Response(404, json={"error": "not found"})
    )

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await client.get_event("missing")


# ---------------------------------------------------------------------------
# 24. async verify_chain — valid chain does not raise
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_verify_chain_valid() -> None:
    """AsyncCITADELClient.verify_chain: valid chain completes without error."""
    payload1 = {"k": "v"}
    payload1_bytes = json.dumps(payload1, separators=(",", ":"), sort_keys=True).encode()
    prev_hash = "0" * 64
    chain_hash1 = hashlib.sha256(prev_hash.encode() + payload1_bytes).hexdigest()

    ev0 = _make_event(id="ev0", chain_hash=prev_hash, payload={"k": "genesis"})
    ev1 = _make_event(id="ev1", chain_hash=chain_hash1, payload=payload1)

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        await client.verify_chain([ev0, ev1])  # must not raise


# ---------------------------------------------------------------------------
# 25. async verify_chain — broken link raises ValueError
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_async_verify_chain_broken() -> None:
    """AsyncCITADELClient.verify_chain: broken chain raises ValueError."""
    ev0 = _make_event(id="ev0", chain_hash="prev-hash-abc")
    ev1 = _make_event(id="ev1", chain_hash="wrong-hash-xyz")

    async with AsyncCITADELClient(BASE_URL, SHARED_SECRET) as client:
        with pytest.raises(ValueError, match="chain broken"):
            await client.verify_chain([ev0, ev1])
