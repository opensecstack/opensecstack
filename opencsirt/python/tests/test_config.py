from __future__ import annotations

import pytest

from advisory.config import Settings, get_settings, reset_settings_cache


def test_defaults() -> None:
    reset_settings_cache()
    s = Settings(_env_file=None)  # type: ignore[call-arg]
    assert s.port == 8089
    assert s.default_tlp == "AMBER"
    assert s.publisher_category == "coordinator"
    assert s.enricher_timeout_seconds == 8.0


def test_get_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    reset_settings_cache()
    monkeypatch.setenv("OPENCSIRT_PY_PORT", "9000")
    a = get_settings()
    monkeypatch.setenv("OPENCSIRT_PY_PORT", "9001")
    b = get_settings()
    assert a is b
    assert a.port == 9000
    reset_settings_cache()
    assert get_settings().port == 9001
