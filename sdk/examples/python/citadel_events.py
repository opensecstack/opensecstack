"""
citadel_events.py — demonstrates the CITADEL client in both sync and async modes.

Steps performed:
  1. Build a sync CITADELClient and send a test SecurityEvent.
  2. Query recent events with optional filters.
  3. Verify the SHA-256 hash chain across the returned events.
  4. Fetch a single event by ID.
  5. (Async) Repeat steps 1-3 using AsyncCITADELClient.

Usage::

    CITADEL_URL=https://citadel.internal \\
    CITADEL_SHARED_SECRET=supersecret \\
    python citadel_events.py

Required environment variables:
  CITADEL_URL            Base URL of your CITADEL instance
  CITADEL_SHARED_SECRET  HMAC-SHA256 shared signing secret

Optional:
  CITADEL_SOURCE         Source filter for get_events (default: "apiguard")
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Import from the opensecstack SDK
# ---------------------------------------------------------------------------
try:
    from opensecstack import (
        CITADELClient,
        GetEventsOptions,
        SecurityEvent,
    )
except ImportError:
    # Running directly from the repo without installing the package.
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "python"))
    from opensecstack import (  # type: ignore[no-redef]
        CITADELClient,
        GetEventsOptions,
        SecurityEvent,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"error: required environment variable {name} is not set", file=sys.stderr)
        sys.exit(1)
    return value


def build_test_event(chain_hash: str = "0" * 64) -> SecurityEvent:
    """Build a synthetic APIGuard scan-completed event."""
    return SecurityEvent(
        id=f"evt_{uuid.uuid4().hex}",
        event_type="apiguard.scan.completed",
        source="apiguard",
        actor_id="ak_example_key",
        actor_type="api_key",
        resource_type="scan",
        resource_id="scan_abc123",
        severity="info",
        payload={
            "scan_id": "scan_abc123",
            "spec_hash": "sha256:deadbeef",
            "findings_summary": {"critical": 0, "high": 1, "medium": 3},
        },
        chain_hash=chain_hash,
        timestamp=datetime.now(tz=timezone.utc),
    )


# ---------------------------------------------------------------------------
# Synchronous demo
# ---------------------------------------------------------------------------


def run_sync(base_url: str, shared_secret: str, source: str) -> None:
    print("=" * 60)
    print("SYNC CITADEL CLIENT DEMO")
    print("=" * 60)

    client = CITADELClient(
        base_url=base_url,
        shared_secret=shared_secret,
        max_retries=3,
        retry_wait_base=0.5,
    )

    # 1. Send a test event -------------------------------------------------
    event = build_test_event()
    print(f"\n[1] Sending event {event.id} ({event.event_type}) …")
    try:
        client.send_event(event)
        print("    Delivered successfully.")
    except Exception as exc:
        print(f"    send_event failed: {exc}")

    # 2. Query recent events -----------------------------------------------
    since = datetime.now(tz=timezone.utc) - timedelta(hours=24)
    opts = GetEventsOptions(source=source, since=since, limit=20, page=1)

    print(f"\n[2] Querying events: source={source}, since={since.isoformat()}")
    try:
        events = client.get_events(opts)
        print(f"    Retrieved {len(events)} event(s)")
        for ev in events:
            print(
                f"      [{ev.timestamp.isoformat()}] "
                f"{ev.id} | {ev.event_type} | {ev.severity}"
            )
    except Exception as exc:
        print(f"    get_events failed: {exc}")
        events = []

    # 3. Verify hash chain -------------------------------------------------
    if len(events) >= 2:
        print(f"\n[3] Verifying hash chain across {len(events)} events …")
        try:
            client.verify_chain(events)
            print("    Chain intact — all links verified.")
        except ValueError as exc:
            print(f"    Chain verification FAILED: {exc}")
    else:
        print("\n[3] Skipping chain verification (fewer than 2 events returned)")

    # 4. Fetch single event by ID ------------------------------------------
    if events:
        target_id = events[-1].id
        print(f"\n[4] Fetching single event by ID: {target_id}")
        try:
            single = client.get_event(target_id)
            print(
                f"    Fetched: {single.id} | {single.event_type} "
                f"| chain_hash: {single.chain_hash[:16]}…"
            )
        except Exception as exc:
            print(f"    get_event failed: {exc}")


# ---------------------------------------------------------------------------
# Asynchronous demo
# ---------------------------------------------------------------------------


async def run_async(base_url: str, shared_secret: str, source: str) -> None:
    print("\n" + "=" * 60)
    print("ASYNC CITADEL CLIENT DEMO")
    print("=" * 60)

    try:
        from opensecstack import AsyncCITADELClient
    except ImportError:
        print("AsyncCITADELClient not available — install httpx to enable async support.")
        return

    async with AsyncCITADELClient(
        base_url=base_url,
        shared_secret=shared_secret,
        max_retries=3,
        retry_wait_base=0.5,
    ) as client:
        # 1. Send a test event -----------------------------------------------
        event = build_test_event()
        print(f"\n[1] Sending event {event.id} ({event.event_type}) …")
        try:
            await client.send_event(event)
            print("    Delivered successfully.")
        except Exception as exc:
            print(f"    send_event failed: {exc}")

        # 2. Query recent events ---------------------------------------------
        since = datetime.now(tz=timezone.utc) - timedelta(hours=24)
        opts = GetEventsOptions(source=source, since=since, limit=20, page=1)

        print(f"\n[2] Querying events: source={source}, since={since.isoformat()}")
        try:
            events = await client.get_events(opts)
            print(f"    Retrieved {len(events)} event(s)")
            for ev in events:
                print(
                    f"      [{ev.timestamp.isoformat()}] "
                    f"{ev.id} | {ev.event_type} | {ev.severity}"
                )
        except Exception as exc:
            print(f"    get_events failed: {exc}")
            events = []

        # 3. Verify hash chain -----------------------------------------------
        if len(events) >= 2:
            print(f"\n[3] Verifying hash chain across {len(events)} events …")
            try:
                await client.verify_chain(events)
                print("    Chain intact — all links verified.")
            except ValueError as exc:
                print(f"    Chain verification FAILED: {exc}")
        else:
            print("\n[3] Skipping chain verification (fewer than 2 events returned)")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    base_url = require_env("CITADEL_URL")
    shared_secret = require_env("CITADEL_SHARED_SECRET")
    source = os.environ.get("CITADEL_SOURCE", "apiguard")

    run_sync(base_url, shared_secret, source)
    asyncio.run(run_async(base_url, shared_secret, source))

    print("\nDone.")


if __name__ == "__main__":
    main()
