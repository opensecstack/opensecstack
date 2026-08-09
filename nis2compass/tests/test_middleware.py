"""
Unit tests for app/middleware.py — rate limiting, client IP resolution,
and security headers. No live database or Redis is required: the Redis
client is monkeypatched with an in-memory fake.
"""
import base64
import json
import time

import jwt as pyjwt
import pytest
from flask import Flask

from app import extensions, middleware
from app.middleware import _check_rate_limit, _get_client_ip, apply_middleware


# --------------------------------------------------------------------- #
# _get_client_ip()
# --------------------------------------------------------------------- #


@pytest.fixture()
def ip_app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    return flask_app


class TestGetClientIp:
    def test_returns_remote_addr_when_no_trusted_proxies(self, ip_app):
        with ip_app.test_request_context("/", environ_base={"REMOTE_ADDR": "203.0.113.5"}):
            assert _get_client_ip(set()) == "203.0.113.5"

    def test_ignores_xff_when_remote_not_trusted(self, ip_app):
        with ip_app.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "203.0.113.5"},
            headers={"X-Forwarded-For": "1.2.3.4"},
        ):
            assert _get_client_ip({"10.0.0.1"}) == "203.0.113.5"

    def test_uses_xff_when_remote_is_trusted_proxy(self, ip_app):
        with ip_app.test_request_context(
            "/",
            environ_base={"REMOTE_ADDR": "10.0.0.1"},
            headers={"X-Forwarded-For": "1.2.3.4, 5.6.7.8"},
        ):
            assert _get_client_ip({"10.0.0.1"}) == "1.2.3.4"

    def test_trusted_proxy_without_xff_header_falls_back_to_remote(self, ip_app):
        with ip_app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
            assert _get_client_ip({"10.0.0.1"}) == "10.0.0.1"


# --------------------------------------------------------------------- #
# _check_rate_limit()
# --------------------------------------------------------------------- #


class _FakeScript:
    """Stand-in for redis.Redis.register_script()'s callable return value."""

    def __init__(self, store):
        self._store = store

    def __call__(self, keys, args):
        key = keys[0]
        now_ms, window_ms, limit, req_id = args
        entries = [t for t in self._store.get(key, []) if t >= now_ms - window_ms]
        if len(entries) >= limit:
            self._store[key] = entries
            return [0, len(entries)]
        entries.append(now_ms)
        self._store[key] = entries
        return [1, len(entries)]


class _FakeRedisRateLimit:
    def __init__(self):
        self._store = {}

    def register_script(self, script_body):
        return _FakeScript(self._store)

    def zrange(self, key, start, end, withscores=False):
        entries = sorted(self._store.get(key, []))
        if not entries:
            return []
        return [(str(entries[0]), entries[0])]


class TestCheckRateLimit:
    def test_allows_when_redis_unavailable(self, monkeypatch):
        monkeypatch.setattr(extensions, "redis_client", None)
        allowed, retry_after = _check_rate_limit("1.2.3.4", limit=1)
        assert allowed is True
        assert retry_after == 0

    def test_allows_first_request_within_limit(self, monkeypatch):
        monkeypatch.setattr(middleware, "_rate_limit_script", None)
        monkeypatch.setattr(extensions, "redis_client", _FakeRedisRateLimit())
        allowed, retry_after = _check_rate_limit("1.2.3.4", limit=5)
        assert allowed is True
        assert retry_after == 0

    def test_denies_when_over_limit(self, monkeypatch):
        monkeypatch.setattr(middleware, "_rate_limit_script", None)
        fake = _FakeRedisRateLimit()
        monkeypatch.setattr(extensions, "redis_client", fake)
        for _ in range(3):
            allowed, _ = _check_rate_limit("1.2.3.4", limit=3)
            assert allowed is True
        allowed, retry_after = _check_rate_limit("1.2.3.4", limit=3)
        assert allowed is False
        assert retry_after >= 1

    def test_fails_open_on_redis_script_error(self, monkeypatch):
        class BoomRedis:
            def register_script(self, script_body):
                def boom(keys, args):
                    raise ConnectionError("redis down")

                return boom

        monkeypatch.setattr(middleware, "_rate_limit_script", None)
        monkeypatch.setattr(extensions, "redis_client", BoomRedis())
        allowed, retry_after = _check_rate_limit("1.2.3.4", limit=1)
        assert allowed is True
        assert retry_after == 0

    def test_different_ips_tracked_independently(self, monkeypatch):
        monkeypatch.setattr(middleware, "_rate_limit_script", None)
        fake = _FakeRedisRateLimit()
        monkeypatch.setattr(extensions, "redis_client", fake)
        allowed_a, _ = _check_rate_limit("1.1.1.1", limit=1)
        allowed_b, _ = _check_rate_limit("2.2.2.2", limit=1)
        assert allowed_a is True
        assert allowed_b is True


# --------------------------------------------------------------------- #
# apply_middleware() — end-to-end via a minimal Flask app
# --------------------------------------------------------------------- #


@pytest.fixture()
def mw_app(monkeypatch):
    monkeypatch.setattr(middleware, "_rate_limit_script", None)
    monkeypatch.setattr(extensions, "redis_client", _FakeRedisRateLimit())

    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True
    flask_app.config["RATE_LIMIT"] = 2
    flask_app.config["CORS_ORIGINS"] = ["https://example.com"]
    flask_app.config["TRUSTED_PROXIES"] = ""
    flask_app.debug = False
    apply_middleware(flask_app)

    @flask_app.route("/api/thing")
    def _thing():
        return {"ok": True}

    @flask_app.route("/health")
    def _health():
        return {"ok": True}

    return flask_app


class TestApplyMiddlewareSecurityHeaders:
    def test_security_headers_present_on_response(self, mw_app):
        client = mw_app.test_client()
        resp = client.get("/api/thing")
        assert resp.headers["X-Content-Type-Options"] == "nosniff"
        assert resp.headers["X-Frame-Options"] == "DENY"
        assert resp.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert resp.headers["Content-Security-Policy"] == "default-src 'none'"

    def test_hsts_header_present_when_not_debug(self, mw_app):
        client = mw_app.test_client()
        resp = client.get("/api/thing")
        assert "Strict-Transport-Security" in resp.headers

    def test_hsts_header_absent_in_debug_mode(self, mw_app):
        mw_app.debug = True
        client = mw_app.test_client()
        resp = client.get("/api/thing")
        assert "Strict-Transport-Security" not in resp.headers


class TestApplyMiddlewareRateLimit:
    def test_health_endpoint_bypasses_rate_limit(self, mw_app):
        client = mw_app.test_client()
        for _ in range(5):
            resp = client.get("/health")
            assert resp.status_code == 200

    def test_requests_over_limit_return_429(self, mw_app):
        client = mw_app.test_client()
        r1 = client.get("/api/thing")
        r2 = client.get("/api/thing")
        r3 = client.get("/api/thing")
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
        body = r3.get_json()
        assert body["code"] == "RATE_LIMITED"
        assert "Retry-After" in r3.headers

    def test_admin_jwt_bypasses_rate_limit(self, mw_app):
        # Unverified peek at claims — payload only needs a valid base64url
        # JSON segment; middleware does not check the signature here.
        token = pyjwt.encode({"role": "admin"}, "any-secret", algorithm="HS256")
        headers = {"Authorization": f"Bearer {token}"}
        client = mw_app.test_client()
        for _ in range(5):
            resp = client.get("/api/thing", headers=headers)
            assert resp.status_code == 200

    def test_malformed_bearer_token_falls_through_to_rate_limiting(self, mw_app):
        headers = {"Authorization": "Bearer not-a-real-jwt"}
        client = mw_app.test_client()
        r1 = client.get("/api/thing", headers=headers)
        r2 = client.get("/api/thing", headers=headers)
        r3 = client.get("/api/thing", headers=headers)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert r3.status_code == 429
