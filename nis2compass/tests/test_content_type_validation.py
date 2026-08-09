"""
Unit tests for the require_json_content_type() before_request hooks that
guard POST/PUT/PATCH routes on the assessments, controls, organisations,
api_keys, and artifacts blueprints.

These hooks run before authentication/DB access, so a wrong Content-Type
is rejected with 415 regardless of whether a database is reachable.
"""
import uuid

import pytest


# (path, method) pairs — one per blueprint that registers the hook.
# artifacts uses multipart/form-data (file upload) so it is NOT guarded by
# this JSON-only hook; excluded intentionally.
#
# The assessments blueprint has no bare POST /api/v1/assessments route --
# assessment creation is nested under an organisation
# (POST /api/v1/organisations/<uuid:org_id>/assessments). Flask only runs a
# blueprint's before_request hook once a route from that blueprint has
# actually matched, so hitting the wrong (non-existent) path returns a plain
# 404 without ever reaching require_json_content_type(). Use a syntactically
# valid (but nonexistent) org UUID so the route matches and the hook fires;
# the content-type check runs before auth/DB access either way.
_GUARDED_ENDPOINTS = [
    (f"/api/v1/organisations/{uuid.uuid4()}/assessments", "post"),
    ("/api/v1/organisations", "post"),
    ("/api/v1/api-keys", "post"),
]


class TestRequireJsonContentType:
    @pytest.mark.parametrize("path,method", _GUARDED_ENDPOINTS)
    def test_non_json_content_type_returns_415(self, client, path, method):
        resp = getattr(client, method)(
            path,
            data="name=foo",
            content_type="application/x-www-form-urlencoded",
        )
        assert resp.status_code == 415
        body = resp.get_json()
        assert body["code"] == "UNSUPPORTED_MEDIA_TYPE"
        assert "application/json" in body["error"]

    @pytest.mark.parametrize("path,method", _GUARDED_ENDPOINTS)
    def test_missing_content_type_is_not_rejected_by_the_hook(self, client, path, method):
        """No Content-Type header at all -- the hook only rejects an explicitly
        wrong one, so this must fall through to auth (401), not 415."""
        resp = client.post(path, data="{}")
        assert resp.status_code != 415

    def test_get_requests_are_not_subject_to_the_check(self, client):
        # GET is not in the guarded method set -- wrong header must not 415.
        resp = client.get(
            "/api/v1/organisations",
            content_type="text/plain",
        )
        assert resp.status_code != 415

    def test_json_content_type_passes_the_hook(self, client):
        # Correct Content-Type clears the hook; request proceeds to auth,
        # which then rejects it for lacking a token -- proving the hook let
        # it through rather than short-circuiting with 415.
        resp = client.post(
            "/api/v1/organisations",
            json={"name": "Test"},
        )
        assert resp.status_code != 415
        assert resp.status_code == 401
