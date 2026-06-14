"""Shared pytest fixtures."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

# Make sure no leftover env from a previous test run influences config().
_KEYS = [
    "OPENCSIRT_PY_PORT",
    "OPENCSIRT_PY_JWT_SECRET",
    "OPENCSIRT_PY_VT_API_KEY",
    "OPENCSIRT_PY_OTX_API_KEY",
    "OPENCSIRT_PY_ABUSEIPDB_API_KEY",
    "OPENCSIRT_PY_MISP_URL",
    "OPENCSIRT_PY_MISP_API_KEY",
    "OPENCSIRT_PY_REDIS_URL",
    "OPENCSIRT_PY_DEV_MODE",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for k in _KEYS:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "1")
    from advisory.config import reset_settings_cache

    reset_settings_cache()
    yield
    reset_settings_cache()


@pytest.fixture
def jwt_secret(monkeypatch: pytest.MonkeyPatch) -> str:
    secret = "test-secret-do-not-use-in-prod"
    monkeypatch.setenv("OPENCSIRT_PY_JWT_SECRET", secret)
    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "0")
    from advisory.config import reset_settings_cache

    reset_settings_cache()
    return secret


@pytest.fixture
def fixtures_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "fixtures")
