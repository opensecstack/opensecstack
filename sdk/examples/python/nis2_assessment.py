"""
nis2_assessment.py — NIS2 Compass assessment workflow using the opensecstack Python SDK.

Steps performed:
  1. Create a NIS2CompassClient from environment variables.
  2. Register a new organisation.
  3. Create a NIS2 assessment under that organisation.
  4. Stream the SARIF report to a local file.

Usage
-----
  # Install the SDK (from the sdk/python directory):
  pip install -e sdk/python

  # Set required environment variables:
  export NIS2_URL=https://nis2.example.com
  export NIS2_API_KEY=<your-api-key>

  # Optional overrides:
  export NIS2_ORG_NAME="Example Organisation"
  export NIS2_ORG_COUNTRY=DE

  python sdk/examples/python/nis2_assessment.py
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from opensecstack.nis2compass import NIS2CompassClient
from opensecstack.exceptions import APIError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger(__name__)

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------


def require_env(key: str) -> str:
    """Return the value of *key* or exit with a descriptive error."""
    value = os.environ.get(key, "").strip()
    if not value:
        sys.exit(f"ERROR: required environment variable {key!r} is not set")
    return value


def env_or_default(key: str, default: str) -> str:
    """Return the value of *key* or *default* when unset/empty."""
    return os.environ.get(key, "").strip() or default


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------


def main() -> None:
    # ------------------------------------------------------------------
    # 1. Build the NIS2 Compass client.
    # ------------------------------------------------------------------
    base_url = require_env("NIS2_URL")
    api_key = require_env("NIS2_API_KEY")

    client = NIS2CompassClient(base_url=base_url, api_key=api_key, timeout=30)

    # ------------------------------------------------------------------
    # 2. Register a new organisation.
    # ------------------------------------------------------------------
    org_name = env_or_default("NIS2_ORG_NAME", "Example Organisation")
    org_country = env_or_default("NIS2_ORG_COUNTRY", "DE")

    log.info("Creating organisation: name=%r country=%s", org_name, org_country)
    org = client.create_organisation(
        name=org_name,
        industry="Technology",
        country=org_country,
        size="medium",
        entity_type="important",
    )
    org_id: str = org["id"]
    log.info("Organisation created: id=%s name=%s", org_id, org.get("name"))

    # ------------------------------------------------------------------
    # 3. Create a NIS2 assessment.
    #
    # The server automatically seeds 10 control entries (NIS2 Article 21(2)
    # measures a–j) when a new assessment is created.
    # ------------------------------------------------------------------
    log.info("Creating NIS2 assessment for org %s …", org_id)
    assessment = client.create_assessment(
        org_id=org_id,
        title="Initial NIS2 Compliance Assessment",
        framework_version="NIS2-2022/0383",
        scope="All production systems and supporting infrastructure",
        assessor="Security Team",
    )
    assessment_id: str = assessment["id"]
    log.info(
        "Assessment created: id=%s status=%s",
        assessment_id,
        assessment.get("status"),
    )

    # ------------------------------------------------------------------
    # 4. Stream the SARIF report to a local file.
    #
    # SARIF is the recommended format for integrating NIS2 gap findings
    # into code-review pipelines and GitHub Advanced Security.
    # stream_report() writes the response body in chunks so large reports
    # never consume unbounded memory.
    # ------------------------------------------------------------------
    report_path = Path(f"nis2-assessment-{assessment_id}.sarif")
    log.info("Streaming SARIF report to %s …", report_path)
    with report_path.open("wb") as fh:
        try:
            client.stream_report(
                assessment_id=assessment_id,
                format="sarif",
                dest=fh,
            )
        except APIError as exc:
            sys.exit(f"Failed to retrieve SARIF report: {exc}")

    log.info(
        "SARIF report written to %s (%d bytes)",
        report_path,
        report_path.stat().st_size,
    )

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n--- Summary ---")
    print(f"  Organisation : {org.get('name')} ({org_id})")
    print(f"  Assessment   : {assessment.get('title')} ({assessment_id})")
    print(f"  SARIF report : {report_path}")
    print("\nTip: call delete_assessment / delete_organisation to clean up test data.")


if __name__ == "__main__":
    main()
