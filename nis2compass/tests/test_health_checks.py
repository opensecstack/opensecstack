"""
Unit tests for app/api/health.py's _collect_checks() — exercises the
db-error, redis-ok, redis-error, and redis-unavailable branches directly,
independent of whether a live database/Redis is actually reachable in
this test environment.
"""
from types import SimpleNamespace

import pytest

from app.api import health as health_module
from app.extensions import db


class TestCollectChecksDbBranches:
    def test_db_ok_sets_status_ok(self, app, monkeypatch):
        monkeypatch.setattr(db.session, "execute", lambda stmt: None)
        monkeypatch.setattr(health_module, "redis_client", None)
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["db"] == "ok"

    def test_db_error_marks_degraded(self, app, monkeypatch):
        def boom(stmt):
            raise ConnectionError("db unreachable")

        monkeypatch.setattr(db.session, "execute", boom)
        monkeypatch.setattr(health_module, "redis_client", None)
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["db"] == "error"
        assert checks["status"] == "degraded"


class TestCollectChecksRedisBranches:
    def test_redis_none_reports_unavailable(self, app, monkeypatch):
        monkeypatch.setattr(db.session, "execute", lambda stmt: None)
        monkeypatch.setattr(health_module, "redis_client", None)
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["redis"] == "unavailable"
        # Redis being merely unconfigured (vs erroring) does not degrade status.
        assert checks["status"] == "ok"

    def test_redis_ping_ok(self, app, monkeypatch):
        monkeypatch.setattr(db.session, "execute", lambda stmt: None)
        monkeypatch.setattr(health_module, "redis_client", SimpleNamespace(ping=lambda: True))
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["redis"] == "ok"
        assert checks["status"] == "ok"

    def test_redis_ping_error_marks_degraded(self, app, monkeypatch):
        def boom():
            raise ConnectionError("redis down")

        monkeypatch.setattr(db.session, "execute", lambda stmt: None)
        monkeypatch.setattr(health_module, "redis_client", SimpleNamespace(ping=boom))
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["redis"] == "error"
        assert checks["status"] == "degraded"

    def test_both_db_and_redis_error_still_reports_degraded_not_crash(self, app, monkeypatch):
        def db_boom(stmt):
            raise ConnectionError("db down")

        def redis_boom():
            raise ConnectionError("redis down")

        monkeypatch.setattr(db.session, "execute", db_boom)
        monkeypatch.setattr(health_module, "redis_client", SimpleNamespace(ping=redis_boom))
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["db"] == "error"
        assert checks["redis"] == "error"
        assert checks["status"] == "degraded"

    def test_includes_version(self, app, monkeypatch):
        monkeypatch.setattr(db.session, "execute", lambda stmt: None)
        monkeypatch.setattr(health_module, "redis_client", None)
        with app.app_context():
            checks = health_module._collect_checks()
        assert checks["version"] == health_module.VERSION


class TestHealthDetailAuthEdgeCases:
    def test_missing_authorization_header_returns_401(self, client):
        resp = client.get("/health/detail")
        assert resp.status_code == 401
        assert resp.get_json()["code"] == "UNAUTHORIZED"

    def test_non_bearer_scheme_returns_401(self, client):
        resp = client.get("/health/detail", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert resp.status_code == 401

    def test_invalid_token_returns_401(self, client):
        resp = client.get("/health/detail", headers={"Authorization": "Bearer garbage-token"})
        assert resp.status_code == 401
        assert resp.get_json()["code"] == "UNAUTHORIZED"

    def test_valid_token_with_degraded_checks_returns_503(self, app, client, monkeypatch):
        from app.auth import issue_jwt

        def db_boom(stmt):
            raise ConnectionError("db down")

        monkeypatch.setattr(db.session, "execute", db_boom)
        monkeypatch.setattr(health_module, "redis_client", None)

        with app.app_context():
            token, _ = issue_jwt("test-user")

        resp = client.get("/health/detail", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 503
        data = resp.get_json()
        assert data["status"] == "degraded"
        assert data["db"] == "error"
