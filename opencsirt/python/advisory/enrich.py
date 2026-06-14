"""IOC enrichment plugin framework.

Each enricher is a small async class implementing :class:`BaseEnricher`.
The aggregator walks the active set, queries each in parallel, and
merges the results into a single normalised :class:`EnrichedIOC` per
input. Enrichers self-disable when their API key is missing — a missing
key is a configuration choice, not a runtime error.

Caching: results are cached for ``settings.enrich_cache_ttl_seconds``
keyed by ``(enricher_name, ioc_value)``. Redis is used when
``OPENCSIRT_PY_REDIS_URL`` is set; otherwise the cache falls back to a
process-local LRU. Either way the enrichers themselves are oblivious.
"""

from __future__ import annotations

import abc
import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from advisory.config import Settings

# ── IOC typing ────────────────────────────────────────────────────────────────


IOCType = str  # one of: "ipv4", "ipv6", "domain", "url", "sha256", "md5", "unknown"


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"
)
_SHA256_RE = re.compile(r"^[A-Fa-f0-9]{64}$")
_MD5_RE = re.compile(r"^[A-Fa-f0-9]{32}$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def classify_ioc(value: str) -> IOCType:
    """Best-effort IOC type detection. Order matters — URLs win over
    domains, hashes win over numeric-looking strings."""
    v = value.strip()
    if not v:
        return "unknown"
    if _URL_RE.match(v):
        return "url"
    if _SHA256_RE.match(v):
        return "sha256"
    if _MD5_RE.match(v):
        return "md5"
    try:
        addr = ipaddress.ip_address(v)
        return "ipv4" if isinstance(addr, ipaddress.IPv4Address) else "ipv6"
    except ValueError:
        pass
    if _DOMAIN_RE.match(v):
        return "domain"
    return "unknown"


# ── Result shapes ─────────────────────────────────────────────────────────────


@dataclass
class EnricherResult:
    """One enricher's view of a single IOC."""

    source: str
    found: bool
    score: float | None = None  # 0..1 normalised malice score
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


@dataclass
class EnrichedIOC:
    """Per-IOC merged result returned to the caller."""

    value: str
    type: IOCType
    score: float = 0.0
    tags: list[str] = field(default_factory=list)
    sources: list[EnricherResult] = field(default_factory=list)


# ── Cache ─────────────────────────────────────────────────────────────────────


class _Cache(abc.ABC):
    @abc.abstractmethod
    async def get(self, key: str) -> EnricherResult | None: ...

    @abc.abstractmethod
    async def set(self, key: str, value: EnricherResult, ttl: int) -> None: ...


class _MemoryCache(_Cache):
    """In-process TTL cache used when Redis is not configured."""

    def __init__(self, max_entries: int = 4096) -> None:
        self._data: dict[str, tuple[float, EnricherResult]] = {}
        self._max = max_entries

    async def get(self, key: str) -> EnricherResult | None:
        entry = self._data.get(key)
        if entry is None:
            return None
        expires, value = entry
        if expires < time.time():
            self._data.pop(key, None)
            return None
        return value

    async def set(self, key: str, value: EnricherResult, ttl: int) -> None:
        if len(self._data) >= self._max:
            # Simple eviction: drop the oldest entry by expires-at.
            oldest_key = min(self._data, key=lambda k: self._data[k][0])
            self._data.pop(oldest_key, None)
        self._data[key] = (time.time() + ttl, value)


class _RedisCache(_Cache):
    """Redis-backed cache. Falls back gracefully on connection error."""

    def __init__(self, url: str) -> None:
        import redis.asyncio as redis  # local import — optional dep

        self._client = redis.from_url(url, decode_responses=True)  # type: ignore[no-untyped-call]

    async def get(self, key: str) -> EnricherResult | None:
        try:
            raw = await self._client.get(key)
        except Exception:
            return None
        if raw is None:
            return None
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return EnricherResult(**data)

    async def set(self, key: str, value: EnricherResult, ttl: int) -> None:
        payload = json.dumps(value.__dict__, default=str)
        try:
            await self._client.set(key, payload, ex=ttl)
        except Exception:
            return


def _build_cache(settings: Settings) -> _Cache:
    if settings.redis_url:
        try:
            return _RedisCache(settings.redis_url)
        except Exception:
            return _MemoryCache()
    return _MemoryCache()


# ── Enricher base + plugins ───────────────────────────────────────────────────


class BaseEnricher(abc.ABC):
    """Plugin contract. Concrete enrichers wire one external API."""

    name: str = "base"

    def __init__(self, http: httpx.AsyncClient) -> None:
        self.http = http

    @abc.abstractmethod
    def supports(self, ioc_type: IOCType) -> bool:
        """Return True when the enricher can answer for this IOC type."""

    @abc.abstractmethod
    async def lookup(self, value: str, ioc_type: IOCType) -> EnricherResult:
        """Query the upstream and return a normalised result."""


class VirusTotalEnricher(BaseEnricher):
    """VirusTotal v3 file/domain/ip lookup."""

    name = "virustotal"
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, http: httpx.AsyncClient, api_key: str) -> None:
        super().__init__(http)
        self._api_key = api_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in ("ipv4", "ipv6", "domain", "sha256", "md5")

    async def lookup(self, value: str, ioc_type: IOCType) -> EnricherResult:
        path = {
            "ipv4": f"/ip_addresses/{value}",
            "ipv6": f"/ip_addresses/{value}",
            "domain": f"/domains/{value}",
            "sha256": f"/files/{value}",
            "md5": f"/files/{value}",
        }[ioc_type]
        try:
            resp = await self.http.get(
                self.BASE + path,
                headers={"x-apikey": self._api_key},
            )
        except httpx.HTTPError as exc:
            return EnricherResult(source=self.name, found=False, error=str(exc))
        if resp.status_code == 404:
            return EnricherResult(source=self.name, found=False)
        if resp.status_code != 200:
            return EnricherResult(
                source=self.name, found=False, error=f"http {resp.status_code}"
            )
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        total = sum(int(v) for v in stats.values()) or 1
        score = (malicious + 0.5 * suspicious) / total
        tags = list(attrs.get("tags", []))[:32]
        return EnricherResult(
            source=self.name, found=True, score=round(score, 3), tags=tags, raw=stats
        )


class OTXEnricher(BaseEnricher):
    """AlienVault OTX pulse lookup."""

    name = "otx"
    BASE = "https://otx.alienvault.com/api/v1/indicators"

    def __init__(self, http: httpx.AsyncClient, api_key: str) -> None:
        super().__init__(http)
        self._api_key = api_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in ("ipv4", "ipv6", "domain", "url", "sha256", "md5")

    async def lookup(self, value: str, ioc_type: IOCType) -> EnricherResult:
        bucket = {
            "ipv4": "IPv4",
            "ipv6": "IPv6",
            "domain": "domain",
            "url": "url",
            "sha256": "file",
            "md5": "file",
        }[ioc_type]
        url = f"{self.BASE}/{bucket}/{value}/general"
        try:
            resp = await self.http.get(url, headers={"X-OTX-API-KEY": self._api_key})
        except httpx.HTTPError as exc:
            return EnricherResult(source=self.name, found=False, error=str(exc))
        if resp.status_code != 200:
            return EnricherResult(
                source=self.name, found=False, error=f"http {resp.status_code}"
            )
        data = resp.json()
        pulse_count = int(data.get("pulse_info", {}).get("count", 0))
        # Heuristic score: any pulse → 0.5; >5 pulses → 0.9.
        score = 0.0 if pulse_count == 0 else min(0.5 + 0.1 * pulse_count, 0.9)
        tags: list[str] = []
        for pulse in data.get("pulse_info", {}).get("pulses", [])[:10]:
            tags.extend(pulse.get("tags", []))
        return EnricherResult(
            source=self.name,
            found=pulse_count > 0,
            score=round(score, 3),
            tags=tags[:32],
            raw={"pulse_count": pulse_count},
        )


class AbuseIPDBEnricher(BaseEnricher):
    """AbuseIPDB confidence-of-abuse score for IPs."""

    name = "abuseipdb"
    BASE = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, http: httpx.AsyncClient, api_key: str) -> None:
        super().__init__(http)
        self._api_key = api_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type in ("ipv4", "ipv6")

    async def lookup(self, value: str, ioc_type: IOCType) -> EnricherResult:
        try:
            resp = await self.http.get(
                self.BASE,
                params={"ipAddress": value, "maxAgeInDays": "90"},
                headers={"Key": self._api_key, "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            return EnricherResult(source=self.name, found=False, error=str(exc))
        if resp.status_code != 200:
            return EnricherResult(
                source=self.name, found=False, error=f"http {resp.status_code}"
            )
        data = resp.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        return EnricherResult(
            source=self.name,
            found=confidence > 0,
            score=round(confidence / 100.0, 3),
            tags=[c for c in (data.get("usageType") or "").split(",") if c],
            raw={"confidence": confidence, "country": data.get("countryCode")},
        )


class MISPEnricher(BaseEnricher):
    """MISP attribute search. URL pattern matches a default MISP install."""

    name = "misp"

    def __init__(self, http: httpx.AsyncClient, base_url: str, api_key: str) -> None:
        super().__init__(http)
        self._base = base_url.rstrip("/")
        self._api_key = api_key

    def supports(self, ioc_type: IOCType) -> bool:
        return ioc_type != "unknown"

    async def lookup(self, value: str, ioc_type: IOCType) -> EnricherResult:
        try:
            resp = await self.http.post(
                f"{self._base}/attributes/restSearch",
                headers={
                    "Authorization": self._api_key,
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
                json={"value": value, "limit": 25},
            )
        except httpx.HTTPError as exc:
            return EnricherResult(source=self.name, found=False, error=str(exc))
        if resp.status_code != 200:
            return EnricherResult(
                source=self.name, found=False, error=f"http {resp.status_code}"
            )
        attrs = resp.json().get("response", {}).get("Attribute", [])
        return EnricherResult(
            source=self.name,
            found=len(attrs) > 0,
            score=0.6 if attrs else 0.0,
            tags=[t.get("name", "") for a in attrs for t in a.get("Tag", [])][:32],
            raw={"hits": len(attrs)},
        )


# ── Aggregator ────────────────────────────────────────────────────────────────


class Aggregator:
    """Drives parallel enrichment + cache + result merge."""

    def __init__(
        self,
        settings: Settings,
        http: httpx.AsyncClient | None = None,
        cache: _Cache | None = None,
        enrichers: list[BaseEnricher] | None = None,
    ) -> None:
        self._settings = settings
        self._http = http or httpx.AsyncClient(timeout=settings.enricher_timeout_seconds)
        self._cache = cache or _build_cache(settings)
        self._enrichers = enrichers or self._default_enrichers()

    def _default_enrichers(self) -> list[BaseEnricher]:
        out: list[BaseEnricher] = []
        if self._settings.vt_api_key:
            out.append(VirusTotalEnricher(self._http, self._settings.vt_api_key))
        if self._settings.otx_api_key:
            out.append(OTXEnricher(self._http, self._settings.otx_api_key))
        if self._settings.abuseipdb_api_key:
            out.append(AbuseIPDBEnricher(self._http, self._settings.abuseipdb_api_key))
        if self._settings.misp_url and self._settings.misp_api_key:
            out.append(
                MISPEnricher(self._http, self._settings.misp_url, self._settings.misp_api_key)
            )
        return out

    @property
    def active_sources(self) -> list[str]:
        return [e.name for e in self._enrichers]

    async def aclose(self) -> None:
        await self._http.aclose()

    async def enrich(self, iocs: list[str]) -> list[EnrichedIOC]:
        return await asyncio.gather(*(self._enrich_one(v) for v in iocs))

    async def _enrich_one(self, value: str) -> EnrichedIOC:
        ioc_type = classify_ioc(value)
        if ioc_type == "unknown" or not self._enrichers:
            return EnrichedIOC(value=value, type=ioc_type)
        coros = [
            self._lookup_with_cache(e, value, ioc_type)
            for e in self._enrichers
            if e.supports(ioc_type)
        ]
        results = await asyncio.gather(*coros)
        return _merge(value, ioc_type, list(results))

    async def _lookup_with_cache(
        self, enricher: BaseEnricher, value: str, ioc_type: IOCType
    ) -> EnricherResult:
        key = f"opencsirt:enrich:{enricher.name}:{ioc_type}:{value}"
        cached = await self._cache.get(key)
        if cached is not None:
            return cached
        result = await enricher.lookup(value, ioc_type)
        if result.error is None:
            await self._cache.set(key, result, self._settings.enrich_cache_ttl_seconds)
        return result


def _merge(value: str, ioc_type: IOCType, results: list[EnricherResult]) -> EnrichedIOC:
    """Combine per-source results into a single EnrichedIOC.

    Score policy: take the maximum over sources that reported a score
    (so one strong signal wins over silence). Tags are de-duplicated
    case-insensitively while preserving first-seen order.
    """
    scored = [r.score for r in results if r.score is not None]
    score = max(scored) if scored else 0.0
    seen: set[str] = set()
    tags: list[str] = []
    for r in results:
        for t in r.tags:
            key = t.lower()
            if key not in seen:
                seen.add(key)
                tags.append(t)
    return EnrichedIOC(value=value, type=ioc_type, score=round(score, 3), tags=tags, sources=results)
