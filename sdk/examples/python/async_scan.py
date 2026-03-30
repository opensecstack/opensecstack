"""
async_scan.py — Async example for the opensecstack Python SDK.

Demonstrates how to run an APIGuard security scan and create a NIS2 Compass
organisation concurrently using asyncio, cutting the total round-trip time
roughly in half compared to executing them sequentially.

Requirements
------------
    pip install opensecstack httpx

Usage
-----
    export APIGUARD_BASE_URL=https://apiguard.example.com
    export APIGUARD_CLIENT_ID=my-client-id
    export APIGUARD_CLIENT_SECRET=my-secret

    export NIS2_BASE_URL=https://nis2.example.com
    export NIS2_CLIENT_ID=my-client-id
    export NIS2_CLIENT_SECRET=my-secret

    python async_scan.py
"""

from __future__ import annotations

import asyncio
import io
import os

from opensecstack import AsyncAPIGuardClient, AsyncNIS2CompassClient


# ---------------------------------------------------------------------------
# Configuration — read from environment variables (never hard-code secrets)
# ---------------------------------------------------------------------------

APIGUARD_BASE_URL = os.environ.get("APIGUARD_BASE_URL", "https://apiguard.example.com")
APIGUARD_CLIENT_ID = os.environ.get("APIGUARD_CLIENT_ID", "change-me")
APIGUARD_CLIENT_SECRET = os.environ.get("APIGUARD_CLIENT_SECRET", "change-me")

NIS2_BASE_URL = os.environ.get("NIS2_BASE_URL", "https://nis2.example.com")
NIS2_CLIENT_ID = os.environ.get("NIS2_CLIENT_ID", "change-me")
NIS2_CLIENT_SECRET = os.environ.get("NIS2_CLIENT_SECRET", "change-me")


# ---------------------------------------------------------------------------
# Main coroutine
# ---------------------------------------------------------------------------

async def main() -> None:
    """
    Open both async clients, fire off a scan and an organisation creation
    concurrently with asyncio.gather, then stream the resulting report.
    """
    async with (
        AsyncAPIGuardClient(
            APIGUARD_BASE_URL,
            APIGUARD_CLIENT_ID,
            APIGUARD_CLIENT_SECRET,
            timeout=60.0,
        ) as ag,
        AsyncNIS2CompassClient(
            NIS2_BASE_URL,
            NIS2_CLIENT_ID,
            NIS2_CLIENT_SECRET,
            timeout=60.0,
        ) as nis2,
    ):
        # ------------------------------------------------------------------
        # Step 1: Kick off both operations concurrently.
        # asyncio.create_task schedules the coroutines immediately so they
        # run interleaved while we await each result.
        # ------------------------------------------------------------------
        scan_task = asyncio.create_task(
            ag.create_scan(
                spec_url="https://petstore3.swagger.io/api/v3/openapi.json",
                target="https://petstore3.swagger.io",
                modules=["auth", "injection", "broken_object_level_auth"],
            ),
            name="apiguard-create-scan",
        )

        org_task = asyncio.create_task(
            nis2.create_organisation(
                name="Acme Corp",
                industry="Technology",
                country="DE",
                size="medium",
                entity_type="important",
                contact_email="security@acme.example.com",
            ),
            name="nis2-create-org",
        )

        # Wait for both to finish; if either raises the exception propagates here.
        scan, org = await asyncio.gather(scan_task, org_task)

        print(f"Scan created  : id={scan['id']}  status={scan.get('status', 'unknown')}")
        print(f"Org created   : id={org['id']}  name={org.get('name', '')}")

        # ------------------------------------------------------------------
        # Step 2: Create a NIS2 assessment under the new organisation while
        # polling the scan status — again, both run concurrently.
        # ------------------------------------------------------------------
        assessment_task = asyncio.create_task(
            nis2.create_assessment(
                org_id=org["id"],
                title="Initial NIS2 gap assessment",
                scope="All production systems",
                assessor="security-team@acme.example.com",
            ),
            name="nis2-create-assessment",
        )

        scan_status_task = asyncio.create_task(
            ag.get_scan(scan["id"]),
            name="apiguard-poll-scan",
        )

        assessment, refreshed_scan = await asyncio.gather(
            assessment_task, scan_status_task
        )

        print(f"Assessment    : id={assessment['id']}  status={assessment.get('status', 'unknown')}")
        print(f"Scan status   : {refreshed_scan.get('status', 'unknown')}")

        # ------------------------------------------------------------------
        # Step 3: Stream the NIS2 report to an in-memory buffer (swap
        # io.BytesIO for an open file handle in production).
        # ------------------------------------------------------------------
        report_buffer = io.BytesIO()
        await nis2.stream_report(
            assessment_id=assessment["id"],
            format="pdf",
            dest=report_buffer,
            chunk_size=16_384,
        )
        print(f"Report bytes  : {report_buffer.tell():,}")

        # ------------------------------------------------------------------
        # Step 4: Fetch scan findings — only meaningful once the scan has
        # completed; shown here for illustration.
        # ------------------------------------------------------------------
        if refreshed_scan.get("status") == "completed":
            findings = await ag.get_findings(scan["id"])
            print(f"Findings      : {len(findings)} total")
            for finding in findings[:3]:  # print first 3 for brevity
                print(f"  [{finding.get('severity', '?').upper()}] {finding.get('title', 'untitled')}")
        else:
            print("Scan not yet complete — poll get_scan() again later.")

        # ------------------------------------------------------------------
        # Step 5: List existing scans — demonstrates list_scans pagination.
        # ------------------------------------------------------------------
        recent_scans = await ag.list_scans(page=1, per_page=5)
        print(f"Recent scans  : {len(recent_scans)} returned on page 1")


if __name__ == "__main__":
    asyncio.run(main())
