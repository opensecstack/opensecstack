"""
Unit tests for the parts of app/auth.py not already covered by
tests/test_auth.py: access/refresh token pairs, verify_token() revocation
checks (Redis + DB fallback), revoke_token(), and the require_scope /
require_role decorators. No live database is required — Redis and the DB
session are monkeypatched.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import jwt as pyjwt
import pytest
from flask import Flask, g, jsonify

from app import auth as auth_module
from app.auth import (
    create_access_token,
    create_refresh_token,
    require_role,
    require_scope,
    revoke_token,
    verify_token,
)


# --------------------------------------------------------------------- #
# create_access_token() / create_refresh_token()
# --------------------------------------------------------------------- #


class TestCreateAccessToken:
    def test_returns_token_with_access_type_claim(self, app):
        with app.app_context():
            token, expires_at = create_access_token("user-1", "admin")
        payload = pyjwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
        assert payload["type"] == "access"
        assert payload["sub"] == "user-1"
        assert payload["role"] == "admin"
        assert "jti" in payload
        assert isinstance(expires_at, datetime)

    def test_expiry_respects_configured_ttl_minutes(self, app):
        with app.app_context():
            app.config["JWT_ACCESS_TTL_MINUTES"] = 5
            _, expires_at = create_access_token("user-1", "admin")
        now = datetime.now(timezone.utc)
        assert timedelta(minutes=4) < (expires_at - now) <= timedelta(minutes=5)

    def test_two_tokens_have_different_jti(self, app):
        with app.app_context():
            t1, _ = create_access_token("user-1", "admin")
            t2, _ = create_access_token("user-1", "admin")
        p1 = pyjwt.decode(t1, app.config["JWT_SECRET"], algorithms=["HS256"])
        p2 = pyjwt.decode(t2, app.config["JWT_SECRET"], algorithms=["HS256"])
        assert p1["jti"] != p2["jti"]


class TestCreateRefreshToken:
    def test_returns_token_with_refresh_type_claim(self, app):
        with app.app_context():
            token, expires_at = create_refresh_token("user-1", "viewer")
        payload = pyjwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])
        assert payload["type"] == "refresh"
        assert payload["role"] == "viewer"

    def test_expiry_respects_configured_ttl_days(self, app):
        with app.app_context():
            app.config["JWT_REFRESH_TTL_DAYS"] = 1
            _, expires_at = create_refresh_token("user-1", "viewer")
        now = datetime.now(timezone.utc)
        assert timedelta(hours=23) < (expires_at - now) <= timedelta(days=1)


# --------------------------------------------------------------------- #
# verify_token()
# --------------------------------------------------------------------- #


class _FakeRedis:
    def __init__(self, revoked_jtis=()):
        self._revoked = set(revoked_jtis)
        self.setex_calls = []

    def exists(self, key):
        jti = key.split(":", 1)[1]
        return 1 if jti in self._revoked else 0

    def setex(self, key, ttl, value):
        self.setex_calls.append((key, ttl, value))


class TestVerifyToken:
    def test_valid_access_token_returns_payload(self, app, monkeypatch):
        monkeypatch.setattr("app.extensions.redis_client", _FakeRedis())
        with app.app_context():
            token, _ = create_access_token("user-1", "admin")
            payload = verify_token(token, "access")
        assert payload["sub"] == "user-1"

    def test_wrong_expected_type_raises(self, app, monkeypatch):
        monkeypatch.setattr("app.extensions.redis_client", _FakeRedis())
        with app.app_context():
            token, _ = create_access_token("user-1", "admin")
            with pytest.raises(pyjwt.InvalidTokenError):
                verify_token(token, "refresh")

    def test_expired_token_raises_expired_signature_error(self, app, monkeypatch):
        monkeypatch.setattr("app.extensions.redis_client", _FakeRedis())
        with app.app_context():
            secret = app.config["JWT_SECRET"]
            payload = {
                "sub": "user-1",
                "role": "admin",
                "type": "access",
                "jti": "expired-jti",
                "iat": datetime.now(timezone.utc) - timedelta(hours=2),
                "exp": datetime.now(timezone.utc) - timedelta(hours=1),
            }
            token = pyjwt.encode(payload, secret, algorithm="HS256")
            with pytest.raises(pyjwt.ExpiredSignatureError):
                verify_token(token, "access")

    def test_revoked_jti_in_redis_raises(self, app, monkeypatch):
        with app.app_context():
            token, _ = create_access_token("user-1", "admin")
            jti = pyjwt.decode(token, app.config["JWT_SECRET"], algorithms=["HS256"])["jti"]
            monkeypatch.setattr("app.extensions.redis_client", _FakeRedis(revoked_jtis={jti}))
            with pytest.raises(pyjwt.InvalidTokenError, match="revoked"):
                verify_token(token, "access")

    def test_redis_unavailable_falls_back_to_db(self, app, monkeypatch):
        class BoomRedis:
            def exists(self, key):
                raise ConnectionError("redis down")

        db_checked = {"called": False}

        def fake_db_is_revoked(jti):
            db_checked["called"] = True
            return False

        monkeypatch.setattr("app.extensions.redis_client", BoomRedis())
        monkeypatch.setattr(auth_module, "_db_is_revoked", fake_db_is_revoked)
        with app.app_context():
            token, _ = create_access_token("user-1", "admin")
            payload = verify_token(token, "access")
        assert payload["sub"] == "user-1"
        assert db_checked["called"] is True

    def test_no_redis_client_uses_db_fallback(self, app, monkeypatch):
        db_checked = {"called": False}

        def fake_db_is_revoked(jti):
            db_checked["called"] = True
            return True

        monkeypatch.setattr("app.extensions.redis_client", None)
        monkeypatch.setattr(auth_module, "_db_is_revoked", fake_db_is_revoked)
        with app.app_context():
            token, _ = create_access_token("user-1", "admin")
            with pytest.raises(pyjwt.InvalidTokenError, match="revoked"):
                verify_token(token, "access")
        assert db_checked["called"] is True


# --------------------------------------------------------------------- #
# revoke_token()
# --------------------------------------------------------------------- #


class TestRevokeToken:
    def test_stores_jti_in_redis_with_correct_ttl(self, app, monkeypatch):
        fake_redis = _FakeRedis()
        monkeypatch.setattr("app.extensions.redis_client", fake_redis)
        with app.app_context():
            exp = datetime.now(timezone.utc) + timedelta(seconds=120)
            revoke_token("some-jti", exp)
        assert len(fake_redis.setex_calls) == 1
        key, ttl, value = fake_redis.setex_calls[0]
        assert key == "revoked_jti:some-jti"
        assert 115 <= ttl <= 120
        assert value == "1"

    def test_already_expired_token_is_a_no_op(self, app, monkeypatch):
        fake_redis = _FakeRedis()
        monkeypatch.setattr("app.extensions.redis_client", fake_redis)
        with app.app_context():
            exp = datetime.now(timezone.utc) - timedelta(seconds=10)
            revoke_token("expired-jti", exp)
        assert fake_redis.setex_calls == []

    def test_naive_datetime_is_treated_as_utc(self, app, monkeypatch):
        fake_redis = _FakeRedis()
        monkeypatch.setattr("app.extensions.redis_client", fake_redis)
        with app.app_context():
            exp = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(seconds=60)
            revoke_token("naive-jti", exp)
        assert len(fake_redis.setex_calls) == 1

    def test_redis_failure_does_not_raise(self, app, monkeypatch):
        class BoomRedis:
            def setex(self, *a, **kw):
                raise ConnectionError("redis down")

        monkeypatch.setattr("app.extensions.redis_client", BoomRedis())
        with app.app_context():
            exp = datetime.now(timezone.utc) + timedelta(seconds=60)
            # Must not raise even though both Redis and (unmocked) DB fail.
            revoke_token("some-jti", exp)


# --------------------------------------------------------------------- #
# require_scope() / require_role() decorators
# --------------------------------------------------------------------- #


@pytest.fixture()
def scoped_app():
    flask_app = Flask(__name__)
    flask_app.config["TESTING"] = True

    @flask_app.route("/read-only")
    @require_scope("read")
    def _read_only():
        return jsonify({"ok": True})

    @flask_app.route("/write-only")
    @require_scope("read_write")
    def _write_only():
        return jsonify({"ok": True})

    @flask_app.route("/admin-only")
    @require_role("admin")
    def _admin_only():
        return jsonify({"ok": True})

    @flask_app.route("/admin-or-auditor")
    @require_role("admin", "auditor")
    def _admin_or_auditor():
        return jsonify({"ok": True})

    @flask_app.before_request
    def _set_scope_and_role():
        from flask import request

        g.token_scope = request.headers.get("X-Test-Scope", "read_write")
        g.token_role = request.headers.get("X-Test-Role", "viewer")

    return flask_app


class TestRequireScope:
    def test_sufficient_scope_passes_through(self, scoped_app):
        client = scoped_app.test_client()
        resp = client.get("/write-only", headers={"X-Test-Scope": "read_write"})
        assert resp.status_code == 200

    def test_insufficient_scope_returns_403(self, scoped_app):
        client = scoped_app.test_client()
        resp = client.get("/write-only", headers={"X-Test-Scope": "read"})
        assert resp.status_code == 403
        assert resp.get_json()["code"] == "FORBIDDEN"

    def test_read_scope_allows_read_route(self, scoped_app):
        client = scoped_app.test_client()
        resp = client.get("/read-only", headers={"X-Test-Scope": "read"})
        assert resp.status_code == 200


class TestRequireRole:
    def test_allowed_role_passes_through(self, scoped_app):
        client = scoped_app.test_client()
        resp = client.get("/admin-only", headers={"X-Test-Role": "admin"})
        assert resp.status_code == 200

    def test_disallowed_role_returns_403(self, scoped_app):
        client = scoped_app.test_client()
        resp = client.get("/admin-only", headers={"X-Test-Role": "viewer"})
        assert resp.status_code == 403
        body = resp.get_json()
        assert body["code"] == "FORBIDDEN"
        assert "viewer" in body["error"]

    def test_multiple_allowed_roles(self, scoped_app):
        client = scoped_app.test_client()
        resp_admin = client.get("/admin-or-auditor", headers={"X-Test-Role": "admin"})
        resp_auditor = client.get("/admin-or-auditor", headers={"X-Test-Role": "auditor"})
        resp_viewer = client.get("/admin-or-auditor", headers={"X-Test-Role": "viewer"})
        assert resp_admin.status_code == 200
        assert resp_auditor.status_code == 200
        assert resp_viewer.status_code == 403


# --------------------------------------------------------------------- #
# _db_is_revoked() — DB fallback path (uses monkeypatched db.session.get)
# --------------------------------------------------------------------- #


class TestDbIsRevoked:
    def test_returns_false_when_no_record(self, app, monkeypatch):
        fake_db = SimpleNamespace(session=SimpleNamespace(get=lambda model, jti: None))
        monkeypatch.setattr("app.extensions.db", fake_db)
        with app.app_context():
            assert auth_module._db_is_revoked("no-such-jti") is False

    def test_returns_true_when_record_not_yet_expired(self, app, monkeypatch):
        record = SimpleNamespace(expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
        fake_db = SimpleNamespace(session=SimpleNamespace(get=lambda model, jti: record))
        monkeypatch.setattr("app.extensions.db", fake_db)
        with app.app_context():
            assert auth_module._db_is_revoked("some-jti") is True

    def test_returns_false_when_record_expired(self, app, monkeypatch):
        record = SimpleNamespace(expires_at=datetime.now(timezone.utc) - timedelta(hours=1))
        fake_db = SimpleNamespace(session=SimpleNamespace(get=lambda model, jti: record))
        monkeypatch.setattr("app.extensions.db", fake_db)
        with app.app_context():
            assert auth_module._db_is_revoked("some-jti") is False

    def test_db_error_fails_open_returns_false(self, app, monkeypatch):
        class BoomSession:
            def get(self, model, jti):
                raise ConnectionError("db down")

            def rollback(self):
                pass

        fake_db = SimpleNamespace(session=BoomSession())
        monkeypatch.setattr("app.extensions.db", fake_db)
        with app.app_context():
            assert auth_module._db_is_revoked("some-jti") is False
