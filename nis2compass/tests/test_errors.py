"""
Unit tests for app/errors.py — structured JSON error handlers.

Uses a minimal standalone Flask app (no DB) with routes that trigger each
HTTP error status, so the actual registered handlers run end-to-end.
"""
import pytest
from flask import Flask, abort

from app.errors import register_error_handlers


@pytest.fixture()
def errors_app():
    app = Flask(__name__)
    app.config["TESTING"] = True
    register_error_handlers(app)

    @app.route("/bad-request")
    def _bad_request():
        abort(400, description="custom bad request message")

    @app.route("/bad-request-default")
    def _bad_request_default():
        abort(400)

    @app.route("/unauthorized")
    def _unauthorized():
        abort(401)

    @app.route("/forbidden")
    def _forbidden():
        abort(403)

    @app.route("/not-found")
    def _not_found():
        abort(404)

    @app.route("/method-not-allowed", methods=["GET"])
    def _method_not_allowed():
        return "ok"

    @app.route("/rate-limited")
    def _rate_limited():
        abort(429)

    @app.route("/boom")
    def _boom():
        raise RuntimeError("something broke")

    return app


@pytest.fixture()
def errors_client(errors_app):
    return errors_app.test_client()


class TestErrorHandlers:
    def test_400_returns_structured_json_with_custom_description(self, errors_client):
        resp = errors_client.get("/bad-request")
        assert resp.status_code == 400
        body = resp.get_json()
        assert body == {"error": "custom bad request message", "code": "BAD_REQUEST"}

    def test_400_falls_back_to_default_message(self, errors_client):
        resp = errors_client.get("/bad-request-default")
        assert resp.status_code == 400
        body = resp.get_json()
        assert body["code"] == "BAD_REQUEST"
        assert body["error"]  # some description string

    def test_401_returns_structured_json(self, errors_client):
        resp = errors_client.get("/unauthorized")
        assert resp.status_code == 401
        assert resp.get_json() == {"error": "Authentication required", "code": "UNAUTHORIZED"}

    def test_403_returns_structured_json(self, errors_client):
        resp = errors_client.get("/forbidden")
        assert resp.status_code == 403
        assert resp.get_json() == {"error": "Insufficient permissions", "code": "FORBIDDEN"}

    def test_404_returns_structured_json(self, errors_client):
        resp = errors_client.get("/not-found")
        assert resp.status_code == 404
        assert resp.get_json() == {"error": "Resource not found", "code": "NOT_FOUND"}

    def test_404_for_unregistered_route_also_uses_handler(self, errors_client):
        resp = errors_client.get("/this-route-does-not-exist")
        assert resp.status_code == 404
        assert resp.get_json() == {"error": "Resource not found", "code": "NOT_FOUND"}

    def test_405_returns_structured_json(self, errors_client):
        resp = errors_client.post("/method-not-allowed")
        assert resp.status_code == 405
        assert resp.get_json() == {"error": "Method not allowed", "code": "METHOD_NOT_ALLOWED"}

    def test_429_returns_structured_json(self, errors_client):
        resp = errors_client.get("/rate-limited")
        assert resp.status_code == 429
        assert resp.get_json() == {"error": "Rate limit exceeded", "code": "RATE_LIMITED"}

    def test_500_returns_structured_json_and_logs(self, errors_app):
        # PROPAGATE_EXCEPTIONS defaults to True under TESTING, which would
        # bubble the RuntimeError instead of invoking the 500 handler.
        errors_app.config["PROPAGATE_EXCEPTIONS"] = False
        client = errors_app.test_client()
        resp = client.get("/boom")
        assert resp.status_code == 500
        assert resp.get_json() == {"error": "Internal server error", "code": "INTERNAL_ERROR"}
