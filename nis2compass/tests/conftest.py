"""
Shared pytest fixtures for NIS2 Compass tests.

Unit tests (no database): use the `app` and `client` fixtures.
Integration tests (real PostgreSQL): set NIS2_TEST_DB_URL env var.
"""
import os
import pytest
from app import create_app
from app.config import Config


class TestConfig(Config):
    TESTING = True
    # Use a separate test DB if provided; otherwise skip DB-dependent tests.
    SQLALCHEMY_DATABASE_URI = os.getenv(
        'NIS2_TEST_DB_URL',
        'postgresql+psycopg2://nis2compass:nis2compassdev@localhost:5433/nis2compass_test',
    )
    JWT_SECRET = 'test-jwt-secret-32-chars-minimum-x'
    JWT_TTL = 3600
    API_KEYS = ['test-api-key']
    RATE_LIMIT = 10000  # disable effective rate limiting in tests
    REDIS_URL = os.getenv('NIS2_TEST_REDIS_URL', 'redis://localhost:6380/1')
    NIS2_ENV = 'development'
    DEBUG = True


@pytest.fixture(scope='session')
def app():
    app = create_app(TestConfig)
    return app


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def auth_headers(client):
    """Return Authorization headers with a valid JWT for test-api-key."""
    resp = client.post(
        '/api/v1/auth/token',
        json={'api_key': 'test-api-key'},
    )
    assert resp.status_code == 200, f'Auth failed: {resp.get_json()}'
    token = resp.get_json()['access_token']
    return {'Authorization': f'Bearer {token}'}
