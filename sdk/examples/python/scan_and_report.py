"""
scan_and_report.py — full APIGuard scan lifecycle using the opensecstack Python SDK.

Steps performed:
  1. Create an APIGuardClient from environment variables.
  2. Start a scan against a publicly reachable OpenAPI spec.
  3. Poll until the scan reaches "completed" or "failed".
  4. Stream the JSON report directly to a file (no full in-memory buffer).
  5. List findings and print a severity summary.

Usage
-----
  # Install the SDK (from the sdk/python directory):
  pip install -e sdk/python

  # Set required environment variables:
  export APIGUARD_URL=https://apiguard.example.com
  export APIGUARD_API_KEY=<your-api-key>

  # Optional overrides:
  export APIGUARD_SPEC_URL=https://petstore3.swagger.io/api/v3/openapi.json
  export APIGUARD_TARGET=https://petstore3.swagger.io

  python sdk/examples/python/scan_and_report.py
"""

from __future__ import annotations

import logging
import os
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Optional

from opensecstack.apiguard import APIGuardClient
from opensecstack.exceptions import APIError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

TERMINAL_STATUSES = {"completed", "failed", "cancelled"}
POLL_INTERVAL_SECONDS = 5
POLL_TIMEOUT_SECONDS = 600  # 10 minutes


def require_env(key: str) -> str:
    """Return the value of *key* or exit with a descriptive error."""
    value = os.environ.get(key, "").strip()
    if not value:
        sys.exit(f"ERROR: required environment variable {key!r} is not set")
    return value


def env_or_default(key: str, default: str) -> str:
    """Return the value of *key* or *default* when unset/empty."""
    return os.environ.get(key, "").strip() or default


def wait_for_scan(client: APIGuardClient, scan_id: str, timeout: int = POLL_TIMEOUT_SECONDS) -> dict:
    """
    Poll GET /api/v1/scans/{scan_id} every 5 seconds until the scan reaches
    a terminal state or *timeout* seconds elapse.

    Returns the final scan dict.
    Raises RuntimeError on timeout.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            scan = client.get_scan(scan_id)
        except APIError as exc:
            log.warning("get_scan warning: %s (will retry)", exc)
            time.sleep(POLL_INTERVAL_SECONDS)
            continue

        status = scan.get("status", "")
        log.info("Scan %s status: %s", scan_id, status)
        if status in TERMINAL_STATUSES:
            return scan

        time.sleep(POLL_INTERVAL_SECONDS)

    raise RuntimeError(f"Timed out after {timeout}s waiting for scan {scan_id}")


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------


def main() -> None:
    # ------------------------------------------------------------------
    # 1. Build the client.
    # ------------------------------------------------------------------
    base_url = require_env("APIGUARD_URL")
    api_key = require_env("APIGUARD_API_KEY")

    client = APIGuardClient(base_url=base_url, api_key=api_key, timeout=30)

    # ------------------------------------------------------------------
    # 2. Start the scan.
    # ------------------------------------------------------------------
    spec_url: Optional[str] = env_or_default(
        "APIGUARD_SPEC_URL",
        "https://petstore3.swagger.io/api/v3/openapi.json",
    )
    target: Optional[str] = os.environ.get("APIGUARD_TARGET") or None

    log.info("Starting scan: spec=%s target=%s", spec_url, target or "(derived from spec host)")
    scan = client.create_scan(spec_url=spec_url, target=target)
    scan_id: str = scan["id"]
    log.info("Scan created: id=%s status=%s", scan_id, scan.get("status"))

    # ------------------------------------------------------------------
    # 3. Poll until completion.
    # ------------------------------------------------------------------
    scan = wait_for_scan(client, scan_id)
    if scan.get("status") == "failed":
        sys.exit(f"Scan {scan_id} failed: {scan.get('error_message', '(no message)')}")

    log.info(
        "Scan %s completed: total_findings=%s",
        scan_id,
        scan.get("total_findings", 0),
    )

    # ------------------------------------------------------------------
    # 4. Stream the JSON report to a local file.
    #
    # stream_report() writes the response body in chunks so large reports
    # (HTML, PDF) never consume unbounded memory.
    # ------------------------------------------------------------------
    report_path = Path(f"report-{scan_id}.json")
    log.info("Streaming JSON report to %s …", report_path)
    with report_path.open("wb") as fh:
        client.stream_report(scan_id=scan_id, format="json", dest=fh)
    log.info("Report written to %s (%d bytes)", report_path, report_path.stat().st_size)

    # ------------------------------------------------------------------
    # 5. List findings and print a severity summary.
    # ------------------------------------------------------------------
    findings = client.get_findings(scan_id=scan_id, per_page=100)
    severity_counts: Counter[str] = Counter(f["severity"] for f in findings)

    print("\n--- Findings summary ---")
    for severity in ("critical", "high", "medium", "low", "info"):
        print(f"  {severity:<10}: {severity_counts[severity]}")
    print(f"  {'total':<10}: {len(findings)}")


if __name__ == "__main__":
    main()
