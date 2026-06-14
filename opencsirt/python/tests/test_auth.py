from __future__ import annotations

import time

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient

from advisory.auth import Claims, _decode, require_auth, require_role
from advisory.config import Settings, get_settings, reset_settings_cache


def _mint(secret: str, **claims: object) -> str:
    payload = {"exp": int(time.time()) + 60, "iss": "opencsirt", **claims}
    return pyjwt.encode(payload, secret, algorithm="HS256")


def test_decode_returns_claims() -> None:
    tok = _mint("s", sub="alice", role="operator")
    c = _decode(tok, "s", "opencsirt")
    assert c == Claims(sub="alice", role="operator", issuer="opencsirt")


def test_decode_rejects_wrong_secret() -> None:
    tok = _mint("right", sub="x", role="x")
    with pytest.raises(Exception):
        _decode(tok, "wrong", "opencsirt")


def test_decode_rejects_expired() -> None:
    tok = pyjwt.encode(
        {"sub": "a", "role": "b", "iss": "opencsirt", "exp": int(time.time()) - 60},
        "s",
        algorithm="HS256",
    )
    with pytest.raises(Exception):
        _decode(tok, "s", "opencsirt")


def test_require_role_admits_match(monkeypatch: pytest.MonkeyPatch) -> None:
    from fastapi import Depends

    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "1")
    reset_settings_cache()
    app = FastAPI()

    admin_dep = require_role("admin")

    @app.get("/admin")
    def admin_only(c: Claims = Depends(admin_dep)) -> dict[str, str]:
        return {"sub": c.sub}

    # Dev mode injects role=admin so this works.
    with TestClient(app) as client:
        r = client.get("/admin")
        assert r.status_code == 200


def test_require_auth_dev_mode_synthetic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "1")
    monkeypatch.delenv("OPENCSIRT_PY_JWT_SECRET", raising=False)
    reset_settings_cache()

    # Simulate FastAPI's dependency call: pass a request stub + None creds.
    class _Req:
        class _State:
            pass

        state = _State()

    settings = get_settings()
    c = require_auth(_Req(), credentials=None, settings=settings)  # type: ignore[arg-type]
    assert c.sub == "dev-anonymous" and c.role == "admin"


def test_require_auth_fails_closed_without_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("OPENCSIRT_PY_JWT_SECRET", raising=False)
    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "0")
    reset_settings_cache()
    settings = Settings(_env_file=None, jwt_secret="", dev_mode=False)  # type: ignore[call-arg]

    class _Req:
        class _State:
            pass

        state = _State()

    with pytest.raises(Exception):
        require_auth(_Req(), credentials=None, settings=settings)  # type: ignore[arg-type]


def test_require_auth_rejects_wrong_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENCSIRT_PY_JWT_SECRET", "s")
    monkeypatch.setenv("OPENCSIRT_PY_DEV_MODE", "0")
    reset_settings_cache()
    settings = get_settings()

    class _Req:
        class _State:
            pass

        state = _State()

    creds = HTTPAuthorizationCredentials(scheme="Basic", credentials="x")
    with pytest.raises(Exception):
        require_auth(_Req(), credentials=creds, settings=settings)  # type: ignore[arg-type]
