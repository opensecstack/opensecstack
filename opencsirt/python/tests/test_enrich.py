from __future__ import annotations

import httpx
import pytest

from advisory.config import Settings
from advisory.enrich import (
    AbuseIPDBEnricher,
    Aggregator,
    BaseEnricher,
    EnrichedIOC,
    EnricherResult,
    OTXEnricher,
    VirusTotalEnricher,
    _MemoryCache,
    classify_ioc,
)

# ── classify_ioc ──────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("198.51.100.7", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("evil.example.com", "domain"),
        ("https://example.com/a?b=1", "url"),
        ("a" * 64, "sha256"),
        ("a" * 32, "md5"),
        ("not an ioc", "unknown"),
        ("", "unknown"),
    ],
)
def test_classify_ioc(value: str, expected: str) -> None:
    assert classify_ioc(value) == expected


# ── Memory cache ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_memory_cache_set_get_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    cache = _MemoryCache()
    val = EnricherResult(source="t", found=True, score=0.5)
    await cache.set("k", val, ttl=60)
    got = await cache.get("k")
    assert got is not None and got.score == 0.5

    # Force expiry by rewinding the stored deadline.
    cache._data["k"] = (0.0, val)  # type: ignore[attr-defined]
    assert await cache.get("k") is None


# ── VirusTotal enricher ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_virustotal_lookup_parses_score() -> None:
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 60,
                    "malicious": 5,
                    "suspicious": 5,
                    "undetected": 30,
                },
                "tags": ["c2", "phishing"],
            }
        }
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v3/ip_addresses/198.51.100.7"
        assert request.headers["x-apikey"] == "key"
        return httpx.Response(200, json=payload)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as http:
        enricher = VirusTotalEnricher(http, "key")
        out = await enricher.lookup("198.51.100.7", "ipv4")
    assert out.found
    assert out.score == round((5 + 0.5 * 5) / 100.0, 3)
    assert "phishing" in out.tags


@pytest.mark.asyncio
async def test_virustotal_404_is_not_found() -> None:
    transport = httpx.MockTransport(lambda r: httpx.Response(404))
    async with httpx.AsyncClient(transport=transport) as http:
        out = await VirusTotalEnricher(http, "k").lookup("a" * 64, "sha256")
    assert not out.found
    assert out.error is None


# ── OTX + AbuseIPDB ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_otx_lookup_pulse_count_drives_score() -> None:
    payload = {"pulse_info": {"count": 7, "pulses": [{"tags": ["apt"]}]}}
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    async with httpx.AsyncClient(transport=transport) as http:
        out = await OTXEnricher(http, "k").lookup("evil.example.com", "domain")
    assert out.found
    assert 0.5 < out.score <= 0.9  # type: ignore[operator]
    assert "apt" in out.tags


@pytest.mark.asyncio
async def test_abuseipdb_lookup_normalises_score() -> None:
    payload = {"data": {"abuseConfidenceScore": 75, "countryCode": "RU", "usageType": "isp"}}
    transport = httpx.MockTransport(lambda r: httpx.Response(200, json=payload))
    async with httpx.AsyncClient(transport=transport) as http:
        out = await AbuseIPDBEnricher(http, "k").lookup("198.51.100.7", "ipv4")
    assert out.found
    assert out.score == 0.75
    assert "isp" in out.tags


# ── Aggregator merge logic ────────────────────────────────────────────────────


class StubEnricher(BaseEnricher):
    def __init__(
        self, name: str, score: float, tags: list[str], supports: bool = True
    ) -> None:
        self.name = name
        self._score = score
        self._tags = tags
        self._supports = supports

    def supports(self, ioc_type: str) -> bool:  # type: ignore[override]
        return self._supports

    async def lookup(self, value: str, ioc_type: str) -> EnricherResult:  # type: ignore[override]
        return EnricherResult(source=self.name, found=True, score=self._score, tags=self._tags)


@pytest.mark.asyncio
async def test_aggregator_merges_scores_and_tags() -> None:
    settings = Settings(jwt_secret="x")
    a = StubEnricher("alpha", 0.4, ["c2", "tor"])
    b = StubEnricher("beta", 0.8, ["TOR", "scanning"])  # case-insensitive dedupe
    agg = Aggregator(settings, http=httpx.AsyncClient(), enrichers=[a, b])
    try:
        results = await agg.enrich(["198.51.100.7"])
    finally:
        await agg.aclose()
    assert len(results) == 1
    e = results[0]
    assert isinstance(e, EnrichedIOC)
    assert e.score == 0.8  # max wins
    assert e.tags == ["c2", "tor", "scanning"]  # case-insensitive, first-seen order
    assert {s.source for s in e.sources} == {"alpha", "beta"}


@pytest.mark.asyncio
async def test_aggregator_empty_enricher_set_yields_zero_score() -> None:
    agg = Aggregator(Settings(jwt_secret="x"), http=httpx.AsyncClient(), enrichers=[])
    try:
        results = await agg.enrich(["198.51.100.7"])
    finally:
        await agg.aclose()
    assert results[0].score == 0.0
    assert results[0].sources == []


@pytest.mark.asyncio
async def test_aggregator_unknown_ioc_skipped() -> None:
    agg = Aggregator(
        Settings(jwt_secret="x"),
        http=httpx.AsyncClient(),
        enrichers=[StubEnricher("alpha", 0.9, ["x"])],
    )
    try:
        results = await agg.enrich(["not-an-ioc"])
    finally:
        await agg.aclose()
    assert results[0].type == "unknown"
    assert results[0].score == 0.0
