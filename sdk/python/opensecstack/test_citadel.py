"""
Tests for sdk/python/opensecstack/citadel.py.

Covers:
- SecurityEvent.to_dict / from_dict round-trips
- GetEventsOptions.to_params
- _sign_body helper
- _verify_chain_integrity: valid chain, single event, empty slice, broken link
- _parse_events: plain list and paginated envelope
- CITADELClient disabled mode (empty base_url)
- CITADELClient.send_event — HMAC signature header verified
- CITADELClient.get_events — plain list and envelope responses, filter params
- CITADELClient.get_event — success and 404
- CITADELClient.verify_chain — delegates to _verify_chain_integrity
- CITADELClient retry on 5xx (with tiny backoff)
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
import responses as responses_lib

from opensecstack.citadel import (
    CITADELClient,
    GetEventsOptions,
    SecurityEvent,
    _parse_events,
    _sign_body,
    _verify_chain_integrity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(
    event_id: str = "evt-1",
    *,
    chain_hash: str = "aabbcc",
    payload: dict | None = None,
    prev_hash: str | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        id=event_id,
        event_type="apiguard.scan.completed",
        source="apiguard",
        actor_id="api-key-123",
        actor_type="api_key",
        resource_type="scan",
        resource_id="scan-abc",
        severity="info",
        payload=payload or {"score": 42},
        chain_hash=chain_hash,
        timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc),
        prev_hash=prev_hash,
    )


def _compute_hash(prev_hash: str, payload: dict) -> str:
    """Mirror of _verify_chain_integrity's hash formula."""
    payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    raw = prev_hash.encode() + payload_bytes
    return hashlib.sha256(raw).hexdigest()


def _event_dict(event_id: str = "evt-1", chain_hash: str = "aabbcc") -> dict:
    return {
        "id": event_id,
        "event_type": "apiguard.scan.completed",
        "source": "apiguard",
        "actor_id": "api-key-123",
        "actor_type": "api_key",
        "resource_type": "scan",
        "resource_id": "scan-abc",
        "severity": "info",
        "payload": {"score": 42},
        "chain_hash": chain_hash,
        "timestamp": "2026-01-01T12:00:00+00:00",
        "prev_hash": None,
    }


# ---------------------------------------------------------------------------
# SecurityEvent.to_dict / from_dict
# ---------------------------------------------------------------------------


class TestSecurityEvent:
    def test_to_dict_includes_all_required_fields(self):
        ev = _make_event()
        d = ev.to_dict()
        for key in (
            "id", "event_type", "source", "actor_id", "actor_type",
            "resource_type", "resource_id", "severity", "payload",
            "chain_hash", "timestamp",
        ):
            assert key in d

    def test_to_dict_timestamp_is_string(self):
        ev = _make_event()
        d = ev.to_dict()
        assert isinstance(d["timestamp"], str)

    def test_to_dict_omits_prev_hash_when_none(self):
        ev = _make_event(prev_hash=None)
        d = ev.to_dict()
        assert "prev_hash" not in d

    def test_to_dict_includes_prev_hash_when_set(self):
        ev = _make_event(prev_hash="deadbeef")
        d = ev.to_dict()
        assert d["prev_hash"] == "deadbeef"

    def test_from_dict_round_trip(self):
        ev = _make_event(prev_hash="cafebabe")
        d = ev.to_dict()
        restored = SecurityEvent.from_dict(d)
        assert restored.id == ev.id
        assert restored.chain_hash == ev.chain_hash
        assert restored.prev_hash == ev.prev_hash
        assert restored.payload == ev.payload

    def test_from_dict_parses_z_suffix_timestamp(self):
        d = _event_dict()
        d["timestamp"] = "2026-01-01T12:00:00Z"
        ev = SecurityEvent.from_dict(d)
        assert ev.timestamp.tzinfo is not None

    def test_from_dict_missing_prev_hash_defaults_none(self):
        d = _event_dict()
        d.pop("prev_hash", None)
        ev = SecurityEvent.from_dict(d)
        assert ev.prev_hash is None


# ---------------------------------------------------------------------------
# GetEventsOptions.to_params
# ---------------------------------------------------------------------------


class TestGetEventsOptions:
    def test_empty_options_still_has_limit_and_page(self):
        opts = GetEventsOptions()
        params = opts.to_params()
        assert "limit" in params
        assert "page" in params

    def test_source_filter(self):
        opts = GetEventsOptions(source="apiguard")
        assert opts.to_params()["source"] == "apiguard"

    def test_event_type_filter(self):
        opts = GetEventsOptions(event_type="apiguard.scan.completed")
        assert opts.to_params()["event_type"] == "apiguard.scan.completed"

    def test_since_serialised_as_iso_string(self):
        dt = datetime(2026, 1, 1, tzinfo=timezone.utc)
        opts = GetEventsOptions(since=dt)
        params = opts.to_params()
        assert "since" in params
        assert "2026" in params["since"]

    def test_unset_filters_not_in_params(self):
        opts = GetEventsOptions()
        params = opts.to_params()
        assert "source" not in params
        assert "event_type" not in params
        assert "since" not in params
        assert "until" not in params


# ---------------------------------------------------------------------------
# _sign_body
# ---------------------------------------------------------------------------


class TestSignBody:
    def test_starts_with_sha256_prefix(self):
        sig = _sign_body(b"secret", b"hello")
        assert sig.startswith("sha256=")

    def test_hmac_value_matches_manual_computation(self):
        secret = b"my-secret"
        body = b'{"id":"1"}'
        expected_hex = hmac.new(secret, body, hashlib.sha256).hexdigest()
        sig = _sign_body(secret, body)
        assert sig == f"sha256={expected_hex}"

    def test_different_bodies_produce_different_signatures(self):
        secret = b"key"
        sig1 = _sign_body(secret, b"body1")
        sig2 = _sign_body(secret, b"body2")
        assert sig1 != sig2


# ---------------------------------------------------------------------------
# _verify_chain_integrity
# ---------------------------------------------------------------------------


class TestVerifyChainIntegrity:
    def test_empty_slice_ok(self):
        _verify_chain_integrity([])  # should not raise

    def test_single_event_ok(self):
        _verify_chain_integrity([_make_event()])  # should not raise

    def test_valid_two_event_chain(self):
        ev0 = _make_event("e0", chain_hash="genesis")
        payload1 = {"step": 1}
        hash1 = _compute_hash("genesis", payload1)
        ev1 = _make_event("e1", chain_hash=hash1, payload=payload1)
        _verify_chain_integrity([ev0, ev1])  # should not raise

    def test_valid_three_event_chain(self):
        ev0 = _make_event("e0", chain_hash="genesis")
        p1 = {"n": 1}
        h1 = _compute_hash("genesis", p1)
        ev1 = _make_event("e1", chain_hash=h1, payload=p1)
        p2 = {"n": 2}
        h2 = _compute_hash(h1, p2)
        ev2 = _make_event("e2", chain_hash=h2, payload=p2)
        _verify_chain_integrity([ev0, ev1, ev2])  # should not raise

    def test_broken_link_raises_value_error(self):
        ev0 = _make_event("e0", chain_hash="genesis")
        ev1 = _make_event("e1", chain_hash="wrong-hash")
        with pytest.raises(ValueError, match="broken"):
            _verify_chain_integrity([ev0, ev1])

    def test_error_message_contains_event_ids(self):
        ev0 = _make_event("event-zero", chain_hash="genesis")
        ev1 = _make_event("event-one", chain_hash="bad")
        with pytest.raises(ValueError, match="event-zero"):
            _verify_chain_integrity([ev0, ev1])


# ---------------------------------------------------------------------------
# _parse_events
# ---------------------------------------------------------------------------


class TestParseEvents:
    def test_plain_list(self):
        data = [_event_dict("e1"), _event_dict("e2")]
        events = _parse_events(data)
        assert len(events) == 2
        assert events[0].id == "e1"

    def test_items_envelope(self):
        data = {"items": [_event_dict("e1")], "total": 1}
        events = _parse_events(data)
        assert len(events) == 1

    def test_data_envelope(self):
        data = {"data": [_event_dict("e1"), _event_dict("e2")]}
        events = _parse_events(data)
        assert len(events) == 2

    def test_empty_list(self):
        assert _parse_events([]) == []

    def test_empty_envelope(self):
        assert _parse_events({"items": []}) == []


# ---------------------------------------------------------------------------
# CITADELClient — disabled mode
# ---------------------------------------------------------------------------


class TestCITADELClientDisabled:
    """When base_url is empty, all methods are no-ops."""

    def setup_method(self):
        self.client = CITADELClient("", "secret")

    def test_send_event_returns_none(self):
        result = self.client.send_event(_make_event())
        assert result is None

    def test_get_events_returns_empty_list(self):
        result = self.client.get_events()
        assert result == []

    def test_get_event_raises_value_error(self):
        with pytest.raises((ValueError, IOError)):
            self.client.get_event("some-id")

    def test_verify_chain_empty_ok(self):
        self.client.verify_chain([])  # should not raise


# ---------------------------------------------------------------------------
# CITADELClient — HTTP interactions (responses library)
# ---------------------------------------------------------------------------


BASE = "http://citadel.test"
SECRET = "test-secret"
EVENTS_URL = f"{BASE}/api/v1/events"


@responses_lib.activate
class TestCITADELClientHTTP:
    def _client(self, **kwargs) -> CITADELClient:
        return CITADELClient(BASE, SECRET, retry_wait_base=0.0, **kwargs)

    # ---- send_event -------------------------------------------------------

    def test_send_event_posts_to_events_endpoint(self):
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=201)
        self._client().send_event(_make_event())
        assert len(responses_lib.calls) == 1
        assert "/events" in responses_lib.calls[0].request.url

    def test_send_event_includes_signature_header(self):
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=201)
        self._client().send_event(_make_event())
        req = responses_lib.calls[0].request
        sig_header = req.headers.get("X-Citadel-Signature", "")
        assert sig_header.startswith("sha256=")

    def test_send_event_signature_is_correct(self):
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=201)
        self._client().send_event(_make_event())
        req = responses_lib.calls[0].request
        body_bytes = req.body if isinstance(req.body, bytes) else req.body.encode()
        expected = _sign_body(SECRET.encode(), body_bytes)
        actual = req.headers.get("X-Citadel-Signature", "")
        assert actual == expected

    def test_send_event_raises_on_4xx(self):
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={"error": "bad"}, status=400)
        with pytest.raises((IOError, Exception)):
            self._client().send_event(_make_event())

    # ---- get_events -------------------------------------------------------

    def test_get_events_returns_list(self):
        body = [_event_dict("e1"), _event_dict("e2")]
        responses_lib.add(responses_lib.GET, EVENTS_URL, json=body, status=200)
        events = self._client().get_events()
        assert len(events) == 2
        assert events[0].id == "e1"

    def test_get_events_envelope_response(self):
        body = {"items": [_event_dict("env-1")], "total": 1}
        responses_lib.add(responses_lib.GET, EVENTS_URL, json=body, status=200)
        events = self._client().get_events()
        assert len(events) == 1
        assert events[0].id == "env-1"

    def test_get_events_passes_source_filter(self):
        responses_lib.add(responses_lib.GET, EVENTS_URL, json=[], status=200)
        opts = GetEventsOptions(source="apiguard")
        self._client().get_events(opts)
        req_url = responses_lib.calls[0].request.url
        assert "source=apiguard" in req_url

    def test_get_events_passes_event_type_filter(self):
        responses_lib.add(responses_lib.GET, EVENTS_URL, json=[], status=200)
        opts = GetEventsOptions(event_type="apiguard.scan.completed")
        self._client().get_events(opts)
        req_url = responses_lib.calls[0].request.url
        assert "event_type=apiguard.scan.completed" in req_url

    # ---- get_event --------------------------------------------------------

    def test_get_event_returns_security_event(self):
        responses_lib.add(
            responses_lib.GET,
            f"{BASE}/api/v1/events/evt-42",
            json=_event_dict("evt-42"),
            status=200,
        )
        ev = self._client().get_event("evt-42")
        assert ev.id == "evt-42"
        assert ev.source == "apiguard"

    def test_get_event_404_raises_http_error(self):
        responses_lib.add(
            responses_lib.GET,
            f"{BASE}/api/v1/events/missing",
            json={"error": "not found"},
            status=404,
        )
        import requests
        with pytest.raises(requests.HTTPError):
            self._client().get_event("missing")

    # ---- verify_chain -------------------------------------------------------

    def test_verify_chain_valid_delegates_no_raise(self):
        ev0 = _make_event("e0", chain_hash="genesis")
        p1 = {"x": 1}
        h1 = _compute_hash("genesis", p1)
        ev1 = _make_event("e1", chain_hash=h1, payload=p1)
        self._client().verify_chain([ev0, ev1])  # should not raise

    def test_verify_chain_broken_raises(self):
        ev0 = _make_event("e0", chain_hash="genesis")
        ev1 = _make_event("e1", chain_hash="bad-hash")
        with pytest.raises(ValueError):
            self._client().verify_chain([ev0, ev1])

    # ---- retry on 5xx -------------------------------------------------------

    def test_retry_on_5xx_eventually_succeeds(self):
        # Two 500s then a 201.
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=500)
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=500)
        responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=201)
        # max_retries=3 means up to 4 total attempts — should succeed.
        self._client(max_retries=3).send_event(_make_event())
        assert len(responses_lib.calls) == 3

    def test_retry_exhausted_raises(self):
        # Always 500.
        for _ in range(5):
            responses_lib.add(responses_lib.POST, EVENTS_URL, json={}, status=500)
        with pytest.raises((IOError, Exception)):
            self._client(max_retries=2).send_event(_make_event())
