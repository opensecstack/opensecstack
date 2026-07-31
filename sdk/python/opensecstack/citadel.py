"""
opensecstack SDK — CITADEL governance platform client.

Provides both a synchronous ``CITADELClient`` (backed by ``requests``) and
an asynchronous ``AsyncCITADELClient`` (backed by ``httpx.AsyncClient``) for
delivering structured security events to the CITADEL WORM audit chain and
querying the event log.

Authentication
--------------
Every outbound HTTP POST is HMAC-SHA256 signed with the shared secret.  The
signature is placed in the ``X-Citadel-Signature: sha256=<hex>`` header so
CITADEL can verify the request was sent by a trusted producer.

Chain verification
------------------
The CITADEL audit chain is a linked list of ``SecurityEvent`` records where
each event's ``chain_hash`` is::

    SHA-256(prev_event.chain_hash + current_event.payload_bytes)

``verify_chain()`` checks this invariant across a contiguous slice of events
and raises ``ValueError`` with a human-readable description when any link is
broken.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SecurityEvent:
    """A structured audit event delivered to / retrieved from CITADEL."""

    id: str
    event_type: str  # e.g. "apiguard.scan.completed"
    source: str  # "apiguard" | "nis2compass"
    actor_id: str
    actor_type: str  # "api_key" | "system"
    resource_type: str
    resource_id: str
    severity: str  # "info" | "warning" | "critical"
    payload: dict[str, Any]
    chain_hash: str
    timestamp: datetime
    prev_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a JSON-compatible dict."""
        d: dict[str, Any] = {
            "id": self.id,
            "event_type": self.event_type,
            "source": self.source,
            "actor_id": self.actor_id,
            "actor_type": self.actor_type,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "severity": self.severity,
            "payload": self.payload,
            "chain_hash": self.chain_hash,
            "timestamp": self.timestamp.isoformat(),
        }
        if self.prev_hash is not None:
            d["prev_hash"] = self.prev_hash
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SecurityEvent":
        """Deserialise from a dict returned by the CITADEL API."""
        ts = data["timestamp"]
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return cls(
            id=data["id"],
            event_type=data["event_type"],
            source=data["source"],
            actor_id=data["actor_id"],
            actor_type=data["actor_type"],
            resource_type=data["resource_type"],
            resource_id=data["resource_id"],
            severity=data["severity"],
            payload=data.get("payload") or {},
            chain_hash=data["chain_hash"],
            timestamp=ts,
            prev_hash=data.get("prev_hash"),
        )


@dataclass
class AdvisoryAffects:
    """Describes the component and version range affected by an advisory."""

    component: str
    version_min: str = ""
    version_max: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"component": self.component}
        if self.version_min:
            d["version_min"] = self.version_min
        if self.version_max:
            d["version_max"] = self.version_max
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AdvisoryAffects":
        return cls(
            component=data["component"],
            version_min=data.get("version_min", ""),
            version_max=data.get("version_max", ""),
        )


@dataclass
class Advisory:
    """An AUGUR security advisory retrieved from CITADEL."""

    id: str
    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "none"
    status: str  # "draft" | "published" | "revoked"
    affects: list[AdvisoryAffects] = field(default_factory=list)
    cve: str = ""
    references: list[str] = field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "status": self.status,
            "affects": [a.to_dict() for a in self.affects],
        }
        if self.cve:
            d["cve"] = self.cve
        if self.references:
            d["references"] = self.references
        if self.created_at:
            d["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            d["updated_at"] = self.updated_at.isoformat()
        return d

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Advisory":
        created = data.get("created_at")
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        updated = data.get("updated_at")
        if isinstance(updated, str):
            updated = datetime.fromisoformat(updated.replace("Z", "+00:00"))
        affects = [AdvisoryAffects.from_dict(a) for a in (data.get("affects") or [])]
        return cls(
            id=data["id"],
            title=data["title"],
            description=data.get("description", ""),
            severity=data.get("severity", "none"),
            status=data.get("status", "draft"),
            affects=affects,
            cve=data.get("cve", ""),
            references=data.get("references") or [],
            created_at=created,
            updated_at=updated,
        )


@dataclass
class CreateAdvisoryRequest:
    """Payload for creating a new AUGUR advisory."""

    title: str
    description: str
    severity: str  # "critical" | "high" | "medium" | "low" | "none"
    affects: list[AdvisoryAffects] = field(default_factory=list)
    cve: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
        }
        if self.affects:
            d["affects"] = [a.to_dict() for a in self.affects]
        if self.cve:
            d["cve"] = self.cve
        if self.references:
            d["references"] = self.references
        return d


@dataclass
class PatchAdvisoryRequest:
    """Payload for updating an existing AUGUR advisory. All fields are optional."""

    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    affects: Optional[list[AdvisoryAffects]] = None
    cve: Optional[str] = None
    references: Optional[list[str]] = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {}
        if self.title is not None:
            d["title"] = self.title
        if self.description is not None:
            d["description"] = self.description
        if self.severity is not None:
            d["severity"] = self.severity
        if self.status is not None:
            d["status"] = self.status
        if self.affects is not None:
            d["affects"] = [a.to_dict() for a in self.affects]
        if self.cve is not None:
            d["cve"] = self.cve
        if self.references is not None:
            d["references"] = self.references
        return d


@dataclass
class ListAdvisoriesOptions:
    """Optional filters for ``list_advisories``."""

    page: int = 1
    per_page: int = 50
    status: Optional[str] = None
    severity: Optional[str] = None

    def to_params(self) -> dict[str, str]:
        p: dict[str, str] = {"page": str(self.page), "per_page": str(self.per_page)}
        if self.status:
            p["status"] = self.status
        if self.severity:
            p["severity"] = self.severity
        return p


@dataclass
class GetEventsOptions:
    """Optional filter and pagination parameters for ``get_events``."""

    source: Optional[str] = None
    event_type: Optional[str] = None
    since: Optional[datetime] = None
    until: Optional[datetime] = None
    limit: int = 50
    page: int = 1

    def to_params(self) -> dict[str, str]:
        p: dict[str, str] = {}
        if self.source:
            p["source"] = self.source
        if self.event_type:
            p["event_type"] = self.event_type
        if self.since:
            p["since"] = self.since.astimezone(timezone.utc).isoformat()
        if self.until:
            p["until"] = self.until.astimezone(timezone.utc).isoformat()
        if self.limit > 0:
            p["limit"] = str(self.limit)
        if self.page > 0:
            p["page"] = str(self.page)
        return p


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sign_body(secret: bytes, body: bytes) -> str:
    """Return ``'sha256=<hex_digest>'`` of *body* under *secret*."""
    digest = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return "sha256=" + digest


def _verify_chain_integrity(events: list[SecurityEvent]) -> None:
    """
    Raise ``ValueError`` if *events* do not form a valid SHA-256 chain.

    For each consecutive pair ``(events[i], events[i+1])`` the function
    recomputes::

        SHA-256(events[i].chain_hash + JSON(events[i+1].payload))

    and checks that the result equals ``events[i+1].chain_hash``.
    """
    if len(events) < 2:
        return
    for i in range(len(events) - 1):
        prev = events[i]
        nxt = events[i + 1]
        payload_bytes = json.dumps(
            nxt.payload, separators=(",", ":"), sort_keys=True
        ).encode()
        raw = prev.chain_hash.encode() + payload_bytes
        computed = hashlib.sha256(raw).hexdigest()
        if computed != nxt.chain_hash:
            raise ValueError(
                f"CITADEL chain broken at index {i} → {i + 1}: "
                f"expected chain_hash {nxt.chain_hash!r}, "
                f"computed {computed!r} "
                f"(event_ids: {prev.id!r} → {nxt.id!r})"
            )


def _parse_events(data: Any) -> list[SecurityEvent]:
    """Parse a raw API response (list or envelope dict) into SecurityEvent objects."""
    if isinstance(data, list):
        return [SecurityEvent.from_dict(item) for item in data]
    # Paginated envelope: {"items": [...]} or {"data": [...]}
    items = data.get("items") or data.get("data") or []
    return [SecurityEvent.from_dict(item) for item in items]


# ---------------------------------------------------------------------------
# Synchronous client
# ---------------------------------------------------------------------------


class CITADELClient:
    """
    Synchronous HTTPS client for the CITADEL governance platform.

    Parameters
    ----------
    base_url:
        Root URL of the CITADEL instance, e.g. ``https://citadel.internal``.
        A trailing slash is stripped.  Pass an empty string to put the client
        in **disabled / no-op** mode — every method returns immediately.
    shared_secret:
        HMAC-SHA256 signing key.  Used to generate the
        ``X-Citadel-Signature`` header on every outbound POST.
    max_retries:
        Maximum number of retry attempts on 5xx responses (default: 3).
    retry_wait_base:
        Base backoff duration in seconds (doubles on each attempt, default: 0.5).
    timeout:
        Per-request HTTP timeout in seconds (default: 30).
    """

    def __init__(
        self,
        base_url: str,
        shared_secret: str,
        *,
        max_retries: int = 3,
        retry_wait_base: float = 0.5,
        timeout: float = 30.0,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._secret_bytes = shared_secret.encode()
        self._max_retries = max_retries
        self._retry_wait_base = retry_wait_base
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Accept": "application/json"})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _url(self, path: str) -> str:
        return f"{self._base}/api/v1/{path.lstrip('/')}"

    def _sign_body(self, body: bytes) -> str:
        """Return ``'sha256=<hex_digest>'`` for *body*."""
        return _sign_body(self._secret_bytes, body)

    def _post_with_retry(self, url: str, body: bytes) -> requests.Response:
        """POST *body* to *url* with HMAC signature and exponential-backoff retry."""
        sig = self._sign_body(body)
        headers = {
            "Content-Type": "application/json",
            "X-Citadel-Signature": sig,
        }
        last_exc: Optional[Exception] = None
        for attempt in range(self._max_retries + 1):
            if attempt > 0:
                wait = self._retry_wait_base * (2 ** (attempt - 1))
                time.sleep(wait)
            try:
                resp = self._session.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=self._timeout,
                )
            except requests.RequestException as exc:
                last_exc = exc
                logger.warning(
                    "citadel: POST %s attempt %d failed: %s", url, attempt + 1, exc
                )
                continue

            if resp.status_code < 500:
                # 2xx success or 4xx client error — do not retry.
                return resp
            last_exc = None  # will raise generic error below if all attempts used
            logger.warning(
                "citadel: POST %s attempt %d returned HTTP %d",
                url,
                attempt + 1,
                resp.status_code,
            )

        if last_exc is not None:
            raise last_exc
        raise IOError(
            f"CITADEL POST {url} failed after {self._max_retries + 1} attempts "
            f"with a 5xx error"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send_event(self, event: SecurityEvent) -> None:
        """
        Deliver *event* to CITADEL.

        The request body is serialised to JSON and HMAC-SHA256 signed.
        Raises on transport or server error after exhausting retries.

        If ``base_url`` is empty (disabled mode) returns immediately.
        """
        if not self._base:
            return
        body = json.dumps(event.to_dict(), separators=(",", ":")).encode()
        resp = self._post_with_retry(self._url("events"), body)
        if not resp.ok:
            raise IOError(
                f"send_event: CITADEL returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

    def get_events(
        self, opts: Optional[GetEventsOptions] = None
    ) -> list[SecurityEvent]:
        """
        Query the CITADEL audit chain with optional filters.

        Returns an empty list when ``base_url`` is empty (disabled mode).
        """
        if not self._base:
            return []
        params = (opts or GetEventsOptions()).to_params()
        resp = self._session.get(
            self._url("events"),
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return _parse_events(resp.json())

    def get_event(self, event_id: str) -> SecurityEvent:
        """
        Fetch a single event by ID.

        Raises ``ValueError`` if ``base_url`` is empty (disabled mode).
        Raises ``requests.HTTPError`` on HTTP errors (e.g. 404 not found).
        """
        if not self._base:
            raise ValueError("CITADELClient is disabled (base_url is empty)")
        resp = self._session.get(
            self._url(f"events/{event_id}"),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return SecurityEvent.from_dict(resp.json())

    def verify_chain(self, events: list[SecurityEvent]) -> None:
        """
        Verify the SHA-256 hash chain across *events*.

        Raises ``ValueError`` if any link in the chain is broken.
        """
        _verify_chain_integrity(events)

    # ------------------------------------------------------------------
    # AUGUR advisories
    # ------------------------------------------------------------------

    def create_advisory(self, req: CreateAdvisoryRequest) -> Advisory:
        """Create a new AUGUR advisory. Returns the created advisory."""
        if not self._base:
            raise ValueError("CITADELClient is disabled (base_url is empty)")
        body = json.dumps(req.to_dict(), separators=(",", ":")).encode()
        resp = self._post_with_retry(self._url("augur/advisories"), body)
        resp.raise_for_status()
        return Advisory.from_dict(resp.json())

    def list_advisories(
        self, opts: Optional[ListAdvisoriesOptions] = None
    ) -> list[Advisory]:
        """List AUGUR advisories with optional filters. Returns [] when disabled."""
        if not self._base:
            return []
        params = (opts or ListAdvisoriesOptions()).to_params()
        resp = self._session.get(
            self._url("augur/advisories"),
            params=params,
            timeout=self._timeout,
        )
        resp.raise_for_status()
        data = resp.json()
        items = (
            data
            if isinstance(data, list)
            else (data.get("items") or data.get("data") or [])
        )
        return [Advisory.from_dict(item) for item in items]

    def get_advisory(self, advisory_id: str) -> Advisory:
        """Fetch a single advisory by ID."""
        if not self._base:
            raise ValueError("CITADELClient is disabled (base_url is empty)")
        resp = self._session.get(
            self._url(f"augur/advisories/{advisory_id}"),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return Advisory.from_dict(resp.json())

    def patch_advisory(self, advisory_id: str, req: PatchAdvisoryRequest) -> Advisory:
        """Update an existing advisory. Returns the updated advisory."""
        if not self._base:
            raise ValueError("CITADELClient is disabled (base_url is empty)")
        body = json.dumps(req.to_dict(), separators=(",", ":"))
        resp = self._session.patch(
            self._url(f"augur/advisories/{advisory_id}"),
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return Advisory.from_dict(resp.json())

    def delete_advisory(self, advisory_id: str) -> None:
        """Delete an advisory by ID."""
        if not self._base:
            return
        resp = self._session.delete(
            self._url(f"augur/advisories/{advisory_id}"),
            timeout=self._timeout,
        )
        resp.raise_for_status()

    def get_active_advisories(self) -> list[Advisory]:
        """Convenience wrapper — returns only published advisories."""
        return self.list_advisories(ListAdvisoriesOptions(status="published"))


# ---------------------------------------------------------------------------
# Async client
# ---------------------------------------------------------------------------


try:
    import httpx

    class AsyncCITADELClient:
        """
        Async HTTPS client for the CITADEL governance platform.

        Use as an async context manager::

            async with AsyncCITADELClient(url, secret) as client:
                await client.send_event(event)

        Parameters
        ----------
        base_url:
            Root URL of the CITADEL instance.  Empty string disables the client.
        shared_secret:
            HMAC-SHA256 signing key.
        max_retries:
            Maximum retry attempts on 5xx responses (default: 3).
        retry_wait_base:
            Base backoff in seconds, doubles per attempt (default: 0.5).
        timeout:
            Per-request HTTP timeout in seconds (default: 30).
        """

        def __init__(
            self,
            base_url: str,
            shared_secret: str,
            *,
            max_retries: int = 3,
            retry_wait_base: float = 0.5,
            timeout: float = 30.0,
        ) -> None:
            self._base = base_url.rstrip("/")
            self._secret_bytes = shared_secret.encode()
            self._max_retries = max_retries
            self._retry_wait_base = retry_wait_base
            self._timeout = timeout
            self._client: Optional[httpx.AsyncClient] = None

        # ------------------------------------------------------------------
        # Context manager
        # ------------------------------------------------------------------

        async def __aenter__(self) -> "AsyncCITADELClient":
            self._client = httpx.AsyncClient(
                headers={"Accept": "application/json"},
                timeout=self._timeout,
            )
            return self

        async def __aexit__(self, *args: Any) -> None:
            if self._client is not None:
                await self._client.aclose()
                self._client = None

        # ------------------------------------------------------------------
        # Internal helpers
        # ------------------------------------------------------------------

        def _url(self, path: str) -> str:
            return f"{self._base}/api/v1/{path.lstrip('/')}"

        def _sign_body(self, body: bytes) -> str:
            return _sign_body(self._secret_bytes, body)

        def _http(self) -> httpx.AsyncClient:
            if self._client is None:
                raise RuntimeError(
                    "AsyncCITADELClient must be used as an async context manager "
                    "or _client must be set manually."
                )
            return self._client

        async def _post_with_retry(self, url: str, body: bytes) -> httpx.Response:
            import asyncio

            sig = self._sign_body(body)
            headers = {
                "Content-Type": "application/json",
                "X-Citadel-Signature": sig,
            }
            last_exc: Optional[Exception] = None
            for attempt in range(self._max_retries + 1):
                if attempt > 0:
                    wait = self._retry_wait_base * (2 ** (attempt - 1))
                    await asyncio.sleep(wait)
                try:
                    resp = await self._http().post(url, content=body, headers=headers)
                except httpx.RequestError as exc:
                    last_exc = exc
                    logger.warning(
                        "citadel: async POST %s attempt %d failed: %s",
                        url,
                        attempt + 1,
                        exc,
                    )
                    continue
                if resp.status_code < 500:
                    return resp
                logger.warning(
                    "citadel: async POST %s attempt %d returned HTTP %d",
                    url,
                    attempt + 1,
                    resp.status_code,
                )
            if last_exc is not None:
                raise last_exc
            raise IOError(
                f"CITADEL POST {url} failed after {self._max_retries + 1} attempts"
            )

        # ------------------------------------------------------------------
        # Public API
        # ------------------------------------------------------------------

        async def send_event(self, event: SecurityEvent) -> None:
            """
            Deliver *event* to CITADEL asynchronously.

            No-op when ``base_url`` is empty.
            """
            if not self._base:
                return
            body = json.dumps(event.to_dict(), separators=(",", ":")).encode()
            resp = await self._post_with_retry(self._url("events"), body)
            if resp.is_error:
                raise IOError(
                    f"send_event: CITADEL returned HTTP {resp.status_code}: "
                    f"{resp.text[:200]}"
                )

        async def get_events(
            self, opts: Optional[GetEventsOptions] = None
        ) -> list[SecurityEvent]:
            """Query the CITADEL audit chain. Returns [] when disabled."""
            if not self._base:
                return []
            params = (opts or GetEventsOptions()).to_params()
            resp = await self._http().get(self._url("events"), params=params)
            resp.raise_for_status()
            return _parse_events(resp.json())

        async def get_event(self, event_id: str) -> SecurityEvent:
            """Fetch a single event by ID."""
            if not self._base:
                raise ValueError("AsyncCITADELClient is disabled (base_url is empty)")
            resp = await self._http().get(self._url(f"events/{event_id}"))
            resp.raise_for_status()
            return SecurityEvent.from_dict(resp.json())

        async def verify_chain(self, events: list[SecurityEvent]) -> None:
            """Verify SHA-256 chain integrity. Raises ``ValueError`` on broken link."""
            _verify_chain_integrity(events)

        # ------------------------------------------------------------------
        # AUGUR advisories (async)
        # ------------------------------------------------------------------

        async def create_advisory(self, req: CreateAdvisoryRequest) -> Advisory:
            """Create a new AUGUR advisory."""
            if not self._base:
                raise ValueError("AsyncCITADELClient is disabled (base_url is empty)")
            body = json.dumps(req.to_dict(), separators=(",", ":")).encode()
            resp = await self._post_with_retry(self._url("augur/advisories"), body)
            resp.raise_for_status()
            return Advisory.from_dict(resp.json())

        async def list_advisories(
            self, opts: Optional[ListAdvisoriesOptions] = None
        ) -> list[Advisory]:
            """List AUGUR advisories with optional filters."""
            if not self._base:
                return []
            params = (opts or ListAdvisoriesOptions()).to_params()
            resp = await self._http().get(self._url("augur/advisories"), params=params)
            resp.raise_for_status()
            data = resp.json()
            items = (
                data
                if isinstance(data, list)
                else (data.get("items") or data.get("data") or [])
            )
            return [Advisory.from_dict(item) for item in items]

        async def get_advisory(self, advisory_id: str) -> Advisory:
            """Fetch a single advisory by ID."""
            if not self._base:
                raise ValueError("AsyncCITADELClient is disabled (base_url is empty)")
            resp = await self._http().get(self._url(f"augur/advisories/{advisory_id}"))
            resp.raise_for_status()
            return Advisory.from_dict(resp.json())

        async def patch_advisory(
            self, advisory_id: str, req: PatchAdvisoryRequest
        ) -> Advisory:
            """Update an existing advisory."""
            if not self._base:
                raise ValueError("AsyncCITADELClient is disabled (base_url is empty)")
            body = json.dumps(req.to_dict(), separators=(",", ":"))
            resp = await self._http().patch(
                self._url(f"augur/advisories/{advisory_id}"),
                content=body,
                headers={"Content-Type": "application/json"},
            )
            resp.raise_for_status()
            return Advisory.from_dict(resp.json())

        async def delete_advisory(self, advisory_id: str) -> None:
            """Delete an advisory by ID."""
            if not self._base:
                return
            resp = await self._http().delete(
                self._url(f"augur/advisories/{advisory_id}")
            )
            resp.raise_for_status()

        async def get_active_advisories(self) -> list[Advisory]:
            """Convenience wrapper — returns only published advisories."""
            return await self.list_advisories(ListAdvisoriesOptions(status="published"))

except ImportError:
    # httpx is an optional dependency; only the sync client is available.
    pass
