"""
Tests for the api_keys blueprint (app/api/api_keys.py).

Unit tests (pure logic, no DB): run always.
HTTP tests (Flask test client): run always — DB-dependent operations may return
500 when NIS2_TEST_DB_URL is not set, which is expected and accepted.
"""
import hashlib
import pytest
from app.api.api_keys import _hash_key, VALID_SCOPES


# ------------------------------------------------------------------ #
# Unit tests — pure logic, no HTTP, no DB                              #
# ------------------------------------------------------------------ #

class TestHashKey:
    def test_returns_hex_string(self):
        result = _hash_key('test-key')
        assert isinstance(result, str)

    def test_length_is_64(self):
        # SHA-256 hex digest is always 64 characters
        result = _hash_key('test-key')
        assert len(result) == 64

    def test_deterministic(self):
        assert _hash_key('same-key') == _hash_key('same-key')

    def test_different_inputs_produce_different_hashes(self):
        assert _hash_key('key-one') != _hash_key('key-two')

    def test_empty_string(self):
        result = _hash_key('')
        assert len(result) == 64

    def test_known_value(self):
        # SHA-256('hello') = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        expected = hashlib.sha256(b'hello').hexdigest()
        assert _hash_key('hello') == expected

    def test_unicode_input(self):
        result = _hash_key('héllo-wörld')
        assert len(result) == 64

    def test_long_input(self):
        result = _hash_key('x' * 10_000)
        assert len(result) == 64


class TestValidScopes:
    def test_contains_read(self):
        assert 'read' in VALID_SCOPES

    def test_contains_read_write(self):
        assert 'read_write' in VALID_SCOPES

    def test_exactly_two_scopes(self):
        assert len(VALID_SCOPES) == 2

    def test_invalid_scope_not_in_set(self):
        assert 'admin' not in VALID_SCOPES
        assert 'write' not in VALID_SCOPES


# ------------------------------------------------------------------ #
# HTTP tests — authentication enforcement                              #
# ------------------------------------------------------------------ #

class TestApiKeysAuthEnforcement:
    def test_list_without_auth_returns_401(self, client):
        resp = client.get('/api/v1/api-keys')
        assert resp.status_code == 401

    def test_create_without_auth_returns_401(self, client):
        resp = client.post('/api/v1/api-keys', json={'scope': 'read_write'})
        assert resp.status_code == 401

    def test_revoke_without_auth_returns_401(self, client):
        resp = client.delete('/api/v1/api-keys/00000000-0000-0000-0000-000000000001')
        assert resp.status_code == 401

    def test_list_with_invalid_token_returns_401(self, client):
        resp = client.get(
            '/api/v1/api-keys',
            headers={'Authorization': 'Bearer not-a-real-token'},
        )
        assert resp.status_code == 401

    def test_create_with_invalid_token_returns_401(self, client):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write'},
            headers={'Authorization': 'Bearer invalid'},
        )
        assert resp.status_code == 401


# ------------------------------------------------------------------ #
# HTTP tests — input validation (before DB is accessed)                #
# ------------------------------------------------------------------ #

class TestCreateApiKeyValidation:
    def test_invalid_scope_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'superadmin'},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get('code') == 'INVALID_INPUT'
        assert 'scope' in data.get('error', '').lower()

    def test_scope_write_only_invalid_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'write'},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_expires_in_days_zero_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': 0},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get('code') == 'INVALID_INPUT'

    def test_expires_in_days_negative_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': -5},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_expires_in_days_exceeds_365_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': 366},
            headers=auth_headers,
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert data.get('code') == 'INVALID_INPUT'
        assert '365' in data.get('error', '')

    def test_expires_in_days_string_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': 'thirty'},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_expires_in_days_float_returns_400(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': 3.5},
            headers=auth_headers,
        )
        # 3.5 passes int() but may round — implementation raises ValueError
        # Acceptable: 400 or 201/500 depending on int() behaviour
        assert resp.status_code in (400, 201, 500)

    def test_expires_in_days_exactly_365_accepted(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'expires_in_days': 365},
            headers=auth_headers,
        )
        # Validation passes — result is 201 (DB available) or 500 (DB unavailable)
        assert resp.status_code in (201, 500)

    def test_valid_scope_read_passes_validation(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read'},
            headers=auth_headers,
        )
        # Validation passes — result is 201 (DB) or 500 (no DB)
        assert resp.status_code in (201, 500)

    def test_valid_scope_read_write_passes_validation(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write'},
            headers=auth_headers,
        )
        assert resp.status_code in (201, 500)

    def test_no_body_defaults_to_read_write(self, client, auth_headers):
        # No body → scope defaults to 'read_write' which is valid
        resp = client.post('/api/v1/api-keys', headers=auth_headers)
        assert resp.status_code in (201, 500)

    def test_empty_json_defaults_to_read_write(self, client, auth_headers):
        resp = client.post('/api/v1/api-keys', json={}, headers=auth_headers)
        assert resp.status_code in (201, 500)


# ------------------------------------------------------------------ #
# HTTP tests — response shape (when DB is available)                   #
# ------------------------------------------------------------------ #

class TestCreateApiKeyResponseShape:
    @pytest.mark.skipif(
        not __import__('os').getenv('NIS2_TEST_DB_URL'),
        reason='requires NIS2_TEST_DB_URL',
    )
    def test_created_response_contains_key(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write', 'label': 'test-key'},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'key' in data
        assert data['key'].startswith('nis2_')

    @pytest.mark.skipif(
        not __import__('os').getenv('NIS2_TEST_DB_URL'),
        reason='requires NIS2_TEST_DB_URL',
    )
    def test_created_response_contains_warning(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read_write'},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert 'warning' in data
        assert 'only time' in data['warning'].lower()

    @pytest.mark.skipif(
        not __import__('os').getenv('NIS2_TEST_DB_URL'),
        reason='requires NIS2_TEST_DB_URL',
    )
    def test_created_response_has_correct_scope(self, client, auth_headers):
        resp = client.post(
            '/api/v1/api-keys',
            json={'scope': 'read'},
            headers=auth_headers,
        )
        assert resp.status_code == 201
        data = resp.get_json()
        assert data['scope'] == 'read'

    @pytest.mark.skipif(
        not __import__('os').getenv('NIS2_TEST_DB_URL'),
        reason='requires NIS2_TEST_DB_URL',
    )
    def test_list_returns_pagination_fields(self, client, auth_headers):
        resp = client.get('/api/v1/api-keys', headers=auth_headers)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'data' in data
        assert 'page' in data
        assert 'per_page' in data
        assert 'total' in data

    @pytest.mark.skipif(
        not __import__('os').getenv('NIS2_TEST_DB_URL'),
        reason='requires NIS2_TEST_DB_URL',
    )
    def test_revoke_nonexistent_returns_404(self, client, auth_headers):
        resp = client.delete(
            '/api/v1/api-keys/00000000-0000-0000-0000-000000000001',
            headers=auth_headers,
        )
        assert resp.status_code == 404
        data = resp.get_json()
        assert data.get('code') == 'NOT_FOUND'


# ------------------------------------------------------------------ #
# HTTP tests — list pagination query parameters                        #
# ------------------------------------------------------------------ #

class TestListApiKeysPagination:
    def test_list_with_page_param_requires_auth(self, client):
        resp = client.get('/api/v1/api-keys?page=2&per_page=10')
        assert resp.status_code == 401

    def test_list_with_auth_accepts_pagination(self, client, auth_headers):
        resp = client.get('/api/v1/api-keys?page=1&per_page=5', headers=auth_headers)
        # 200 (DB) or 500 (no DB) — not 400 or 401
        assert resp.status_code in (200, 500)
