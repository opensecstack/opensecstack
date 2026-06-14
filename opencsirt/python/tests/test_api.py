from __future__ import annotations

import base64
import time
from collections.abc import Iterator

import jwt
import pytest
from fastapi.testclient import TestClient

from advisory.config import reset_settings_cache
from advisory.main import create_app


def _mint(sub: str, role: str, secret: str, issuer: str = "opencsirt") -> str:
    return jwt.encode(
        {
            "sub": sub,
            "role": role,
            "iss": issuer,
            "exp": int(time.time()) + 300,
        },
        secret,
        algorithm="HS256",
    )


@pytest.fixture
def client() -> Iterator[TestClient]:
    """Dev-mode client — no JWT required, claims auto-injected."""
    reset_settings_cache()
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def auth_client(jwt_secret: str) -> Iterator[tuple[TestClient, str]]:
    """Real-auth client — caller must mint a JWT against ``jwt_secret``."""
    reset_settings_cache()
    with TestClient(create_app()) as c:
        yield c, jwt_secret


def test_health_unauth(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert isinstance(body["enrichers"], list)


def test_generate_csaf_dev_mode(client: TestClient) -> None:
    r = client.post(
        "/generate",
        json={
            "title": "Test advisory",
            "summary": "An incident occurred.",
            "cve_ids": ["CVE-2026-9999"],
            "iocs": ["198.51.100.7"],
            "tlp": "GREEN",
        },
    )
    assert r.status_code == 201
    advisory = r.json()["advisory"]
    assert advisory["document"]["csaf_version"] == "2.0"
    assert advisory["vulnerabilities"][0]["cve"] == "CVE-2026-9999"
    assert advisory["document"]["distribution"]["tlp"]["label"] == "GREEN"


def test_generate_requires_auth(auth_client: tuple[TestClient, str]) -> None:
    client, secret = auth_client
    r = client.post("/generate", json={"title": "title", "summary": "summary"})
    assert r.status_code == 401

    tok = _mint("alice", "operator", secret)
    r = client.post(
        "/generate",
        json={"title": "title", "summary": "summary"},
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 201


def test_generate_rejects_bad_tlp(client: TestClient) -> None:
    r = client.post("/generate", json={"title": "title", "summary": "summary", "tlp": "ORANGE"})
    assert r.status_code == 422


def test_enrich_iocs_no_keys_yields_empty_sources(client: TestClient) -> None:
    r = client.post("/enrich/iocs", json={"iocs": ["198.51.100.7", "evil.example.com"]})
    assert r.status_code == 200
    body = r.json()
    assert body["active_sources"] == []
    assert len(body["results"]) == 2
    assert body["results"][0]["score"] == 0.0


def test_enrich_iocs_validates_min_length(client: TestClient) -> None:
    r = client.post("/enrich/iocs", json={"iocs": []})
    assert r.status_code == 422


def test_triage_endpoint_accepts_raw(client: TestClient, fixtures_dir: str) -> None:
    with open(f"{fixtures_dir}/phishing_microsoft.eml", "rb") as fh:
        raw = fh.read()
    r = client.post("/triage/abuse-email", json={"raw_rfc822": raw.decode("utf-8")})
    assert r.status_code == 200
    body = r.json()
    assert "203.0.113.42" in body["originating_ips"]
    assert any("bit.ly" in u for u in body["urls"])


def test_triage_endpoint_accepts_b64(client: TestClient, fixtures_dir: str) -> None:
    with open(f"{fixtures_dir}/scam_419.eml", "rb") as fh:
        raw = fh.read()
    r = client.post(
        "/triage/abuse-email",
        json={"raw_rfc822_b64": base64.b64encode(raw).decode("ascii")},
    )
    assert r.status_code == 200
    assert r.json()["from_address"] == "prince@scammer.example"


def test_triage_rejects_missing_body(client: TestClient) -> None:
    r = client.post("/triage/abuse-email", json={})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "missing_body"


def test_triage_rejects_bad_b64(client: TestClient) -> None:
    r = client.post("/triage/abuse-email", json={"raw_rfc822_b64": "!!!not-base64"})
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "bad_base64"


def test_jwt_with_wrong_secret_rejected(auth_client: tuple[TestClient, str]) -> None:
    client, _ = auth_client
    bad = _mint("alice", "operator", "WRONG")
    r = client.post(
        "/triage/abuse-email",
        json={"raw_rfc822": "From: a@b\r\nSubject: t\r\n\r\nhello"},
        headers={"Authorization": f"Bearer {bad}"},
    )
    assert r.status_code == 401
