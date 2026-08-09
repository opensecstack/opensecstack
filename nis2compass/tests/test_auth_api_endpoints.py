"""
Integration tests for POST /api/v1/auth/token/refresh and
POST /api/v1/auth/token/revoke (app/api/auth.py).

These two endpoints previously had zero test coverage -- test_auth.py and
test_auth_tokens.py only exercise POST /api/v1/auth/token and the
lower-level app.auth helpers directly.
"""
import jwt as pyjwt
import pytest


def _get_token_pair(client):
    resp = client.post('/api/v1/auth/token', json={'api_key': 'test-api-key'})
    assert resp.status_code == 200, resp.get_json()
    return resp.get_json()


class TestTokenRefresh:
    def test_missing_refresh_token_returns_400(self, client):
        resp = client.post('/api/v1/auth/token/refresh', json={})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_garbage_token_returns_401(self, client):
        resp = client.post('/api/v1/auth/token/refresh', json={'refresh_token': 'not-a-jwt'})
        assert resp.status_code == 401
        assert resp.get_json()['code'] == 'UNAUTHORIZED'

    def test_access_token_rejected_as_refresh_token(self, client):
        """An access token presented where a refresh token is expected must be
        rejected -- the 'type' claim distinguishes them."""
        pair = _get_token_pair(client)
        resp = client.post('/api/v1/auth/token/refresh', json={'refresh_token': pair['access_token']})
        assert resp.status_code == 401
        assert resp.get_json()['code'] == 'UNAUTHORIZED'

    def test_valid_refresh_token_returns_new_pair(self, client):
        pair = _get_token_pair(client)
        resp = client.post('/api/v1/auth/token/refresh', json={'refresh_token': pair['refresh_token']})
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'access_token' in data
        assert 'refresh_token' in data
        assert data['token_type'] == 'Bearer'
        assert data['refresh_token'] != pair['refresh_token']

    def test_new_access_token_is_usable(self, client):
        pair = _get_token_pair(client)
        refreshed = client.post('/api/v1/auth/token/refresh', json={'refresh_token': pair['refresh_token']}).get_json()
        resp = client.get(
            '/api/v1/organisations',
            headers={'Authorization': f"Bearer {refreshed['access_token']}"},
        )
        assert resp.status_code != 401

    def test_refresh_token_is_rotated_single_use(self, client):
        """Rotation: a refresh token that has already been exchanged must be rejected
        on a second use (it is revoked as part of the first exchange)."""
        pair = _get_token_pair(client)
        first = client.post('/api/v1/auth/token/refresh', json={'refresh_token': pair['refresh_token']})
        assert first.status_code == 200

        second = client.post('/api/v1/auth/token/refresh', json={'refresh_token': pair['refresh_token']})
        assert second.status_code == 401
        assert second.get_json()['code'] == 'UNAUTHORIZED'


class TestTokenRevoke:
    def test_missing_token_returns_400(self, client):
        resp = client.post('/api/v1/auth/token/revoke', json={})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_undecodable_token_returns_400(self, client):
        resp = client.post('/api/v1/auth/token/revoke', json={'token': 'not-a-jwt-at-all'})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_token_missing_jti_returns_400(self, client):
        # A syntactically valid but unsigned JWT with no jti/exp claims.
        bad = pyjwt.encode({'sub': 'x'}, 'irrelevant', algorithm='HS256')
        resp = client.post('/api/v1/auth/token/revoke', json={'token': bad})
        assert resp.status_code == 400
        assert resp.get_json()['code'] == 'INVALID_INPUT'

    def test_valid_token_is_revoked_and_returns_204(self, client):
        pair = _get_token_pair(client)
        resp = client.post('/api/v1/auth/token/revoke', json={'token': pair['access_token']})
        assert resp.status_code == 204
        assert resp.data == b''

    def test_revoked_access_token_can_no_longer_authenticate(self, client):
        pair = _get_token_pair(client)
        revoke_resp = client.post('/api/v1/auth/token/revoke', json={'token': pair['access_token']})
        assert revoke_resp.status_code == 204

        resp = client.get(
            '/api/v1/organisations',
            headers={'Authorization': f"Bearer {pair['access_token']}"},
        )
        assert resp.status_code == 401

    def test_revoke_does_not_verify_signature(self, client):
        """revoke_token() intentionally decodes without signature verification
        (documented in app/api/auth.py) so a token signed with a different
        secret is still accepted, as long as it carries jti + exp."""
        import time
        forged = pyjwt.encode(
            {'sub': 'attacker', 'jti': 'forged-jti-123', 'exp': int(time.time()) + 3600},
            'a-completely-different-secret',
            algorithm='HS256',
        )
        resp = client.post('/api/v1/auth/token/revoke', json={'token': forged})
        assert resp.status_code == 204
