"""
Unit tests for app/config.py — database URI construction and the
Config class's startup-time SSRF/secret validation.

Config's validation runs in the class body at *import* time, so each
scenario reloads the module with a patched environment via importlib.reload,
then restores it afterwards so later tests (which rely on the app/client
fixtures built from the original Config) are unaffected.
"""
import importlib

import pytest

import app.config as config_module
from app.config import _build_database_uri


@pytest.fixture(autouse=True)
def _restore_config_module():
    """Reload app.config back to its original state after each test."""
    yield
    importlib.reload(config_module)


# --------------------------------------------------------------------- #
# _build_database_uri()
# --------------------------------------------------------------------- #


class TestBuildDatabaseUri:
    def test_uses_nis2_db_url_verbatim_when_set(self, monkeypatch):
        monkeypatch.setenv("NIS2_DB_URL", "postgresql+psycopg2://custom:pw@dbhost:5555/customdb")
        assert _build_database_uri() == "postgresql+psycopg2://custom:pw@dbhost:5555/customdb"

    def test_raises_when_no_password_and_no_url(self, monkeypatch):
        monkeypatch.delenv("NIS2_DB_URL", raising=False)
        monkeypatch.delenv("NIS2_DB_PASSWORD", raising=False)
        try:
            with pytest.raises(RuntimeError, match="NIS2_DB_PASSWORD"):
                _build_database_uri()
        finally:
            # Restore before the autouse config-reload fixture runs, since
            # that reload needs NIS2_DB_PASSWORD (or NIS2_DB_URL) set.
            monkeypatch.undo()

    def test_builds_uri_from_parts_with_defaults(self, monkeypatch):
        monkeypatch.delenv("NIS2_DB_URL", raising=False)
        monkeypatch.setenv("NIS2_DB_PASSWORD", "s3cr3t")
        monkeypatch.delenv("NIS2_DB_USER", raising=False)
        monkeypatch.delenv("NIS2_DB_HOST", raising=False)
        monkeypatch.delenv("NIS2_DB_PORT", raising=False)
        monkeypatch.delenv("NIS2_DB_NAME", raising=False)
        uri = _build_database_uri()
        assert uri == "postgresql+psycopg2://nis2compass:s3cr3t@localhost:5432/nis2compass"

    def test_builds_uri_from_custom_parts(self, monkeypatch):
        monkeypatch.delenv("NIS2_DB_URL", raising=False)
        monkeypatch.setenv("NIS2_DB_PASSWORD", "pw")
        monkeypatch.setenv("NIS2_DB_USER", "custom_user")
        monkeypatch.setenv("NIS2_DB_HOST", "db.internal")
        monkeypatch.setenv("NIS2_DB_PORT", "5544")
        monkeypatch.setenv("NIS2_DB_NAME", "custom_db")
        uri = _build_database_uri()
        assert uri == "postgresql+psycopg2://custom_user:pw@db.internal:5544/custom_db"

    def test_url_encodes_special_characters_in_password(self, monkeypatch):
        monkeypatch.delenv("NIS2_DB_URL", raising=False)
        monkeypatch.setenv("NIS2_DB_PASSWORD", "p@ss/w:rd?")
        uri = _build_database_uri()
        # '@', '/', ':' and '?' must be percent-encoded so they cannot be
        # misparsed as URI delimiters (host/path/query separators).
        assert "p%40ss%2Fw%3Ard%3F" in uri
        assert "p@ss/w:rd?" not in uri


# --------------------------------------------------------------------- #
# Config class body — startup-time validation
# --------------------------------------------------------------------- #


class TestConfigWebhookValidation:
    def _reload_with_env(self, monkeypatch, **env):
        monkeypatch.setenv("NIS2_DB_PASSWORD", "testpassword123")
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
        return importlib.reload(config_module)

    def test_no_webhook_url_does_not_raise(self, monkeypatch):
        monkeypatch.delenv("NIS2_WEBHOOK_URL", raising=False)
        monkeypatch.delenv("NIS2_WEBHOOK_SECRET", raising=False)
        mod = self._reload_with_env(monkeypatch)
        assert mod.Config.WEBHOOK_URL == ""

    def test_webhook_url_without_secret_raises(self, monkeypatch):
        try:
            with pytest.raises(ValueError, match="NIS2_WEBHOOK_SECRET"):
                self._reload_with_env(
                    monkeypatch,
                    NIS2_WEBHOOK_URL="https://example.com/hook",
                    NIS2_WEBHOOK_SECRET=None,
                )
        finally:
            monkeypatch.undo()

    def test_webhook_url_with_secret_does_not_raise(self, monkeypatch):
        mod = self._reload_with_env(
            monkeypatch,
            NIS2_WEBHOOK_URL="https://example.com/hook",
            NIS2_WEBHOOK_SECRET="a-real-secret",
        )
        assert mod.Config.WEBHOOK_URL == "https://example.com/hook"

    def test_webhook_url_invalid_scheme_raises(self, monkeypatch):
        try:
            with pytest.raises(ValueError, match="invalid scheme"):
                self._reload_with_env(
                    monkeypatch,
                    NIS2_WEBHOOK_URL="ftp://example.com/hook",
                    NIS2_WEBHOOK_SECRET="secret",
                )
        finally:
            monkeypatch.undo()

    def test_webhook_url_localhost_hostname_raises(self, monkeypatch):
        try:
            with pytest.raises(ValueError, match="loopback"):
                self._reload_with_env(
                    monkeypatch,
                    NIS2_WEBHOOK_URL="http://localhost:8080/hook",
                    NIS2_WEBHOOK_SECRET="secret",
                )
        finally:
            monkeypatch.undo()

    def test_webhook_url_loopback_ip_raises(self, monkeypatch):
        try:
            with pytest.raises(ValueError, match="loopback"):
                self._reload_with_env(
                    monkeypatch,
                    NIS2_WEBHOOK_URL="http://127.0.0.1:8080/hook",
                    NIS2_WEBHOOK_SECRET="secret",
                )
        finally:
            monkeypatch.undo()

    def test_webhook_url_private_ip_raises(self, monkeypatch):
        try:
            with pytest.raises(ValueError, match="private/loopback"):
                self._reload_with_env(
                    monkeypatch,
                    NIS2_WEBHOOK_URL="http://10.0.0.5:8080/hook",
                    NIS2_WEBHOOK_SECRET="secret",
                )
        finally:
            monkeypatch.undo()

    def test_webhook_url_public_dns_name_is_allowed(self, monkeypatch):
        mod = self._reload_with_env(
            monkeypatch,
            NIS2_WEBHOOK_URL="https://hooks.example.com/receive",
            NIS2_WEBHOOK_SECRET="secret",
        )
        assert mod.Config.WEBHOOK_URL == "https://hooks.example.com/receive"

    def test_webhook_url_public_ip_is_allowed(self, monkeypatch):
        mod = self._reload_with_env(
            monkeypatch,
            NIS2_WEBHOOK_URL="http://8.8.8.8:8080/hook",
            NIS2_WEBHOOK_SECRET="secret",
        )
        assert mod.Config.WEBHOOK_URL == "http://8.8.8.8:8080/hook"


class TestConfigCorsOrigins:
    def _reload_with_env(self, monkeypatch, **env):
        monkeypatch.setenv("NIS2_DB_PASSWORD", "testpassword123")
        for k, v in env.items():
            if v is None:
                monkeypatch.delenv(k, raising=False)
            else:
                monkeypatch.setenv(k, v)
        return importlib.reload(config_module)

    def test_explicit_cors_origins_split_on_comma(self, monkeypatch):
        mod = self._reload_with_env(
            monkeypatch,
            NIS2_CORS_ORIGINS="https://a.example.com,https://b.example.com",
        )
        assert mod.Config.CORS_ORIGINS == ["https://a.example.com", "https://b.example.com"]

    def test_development_default_is_wildcard(self, monkeypatch):
        mod = self._reload_with_env(monkeypatch, NIS2_CORS_ORIGINS=None, NIS2_ENV="development")
        assert mod.Config.CORS_ORIGINS == ["*"]

    def test_production_default_is_empty(self, monkeypatch):
        mod = self._reload_with_env(monkeypatch, NIS2_CORS_ORIGINS=None, NIS2_ENV="production")
        assert mod.Config.CORS_ORIGINS == []
