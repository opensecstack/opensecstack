# opensecstack Python SDK

Python client library for the opensecstack platform APIs — NIS2 Compass and APIGuard.

## Installation

```bash
pip install opensecstack-sdk
```

Or directly from source:

```bash
pip install ./sdk/python
```

## Requirements

- Python 3.10+
- `requests >= 2.31`
- `pydantic >= 2.0` (optional — falls back to plain dataclasses)

---

## Usage

### APIGuard — upload a spec and run a scan

```python
from opensecstack import APIGuardClient

client = APIGuardClient(
    base_url="https://apiguard.example.com",
    api_key="sk-your-api-key-here",
)

# Upload a local OpenAPI spec file.
upload = client.upload_spec("./openapi.yaml")
spec_path = upload["spec_path"]   # server-side path, pass to create_scan

# Create a scan (runs asynchronously on the server).
scan = client.create_scan(
    spec_path=spec_path,
    target="https://api.example.com",
    modules=["owasp-api1", "owasp-api2", "owasp-api3"],
)
scan_id = scan["id"]
print(f"Scan {scan_id} started — status: {scan['status']}")

# Poll until completed (status: pending → running → completed/failed).
import time

while True:
    scan = client.get_scan(scan_id)
    if scan["status"] in ("completed", "failed"):
        break
    time.sleep(5)

print(f"Scan finished: {scan['status']}, {scan['total_findings']} findings")

# Fetch findings.
findings = client.get_findings(scan_id)
for f in findings:
    print(f"[{f['severity'].upper()}] {f['title']} — {f['endpoint_method']} {f['endpoint_path']}")

# Fetch recent audit log entries.
audit = client.get_audit_log(limit=10)
for entry in audit:
    print(entry["action"], entry.get("created_at"))
```

### NIS2 Compass — create an organisation and run an assessment

```python
from opensecstack import NIS2CompassClient

client = NIS2CompassClient(
    base_url="https://nis2.example.com",
    api_key="nis2-your-api-key-here",
)

# Create an organisation.
org = client.create_organisation(
    name="Acme GmbH",
    industry="Energy",
    country="DE",
    size="large",
    entity_type="essential",
)
org_id = org["id"]

# Create a NIS2 assessment.
assessment = client.create_assessment(
    org_id=org_id,
    title="Annual NIS2 Review 2026",
    assessor="jane.doe@acme.example",
    due_date="2026-06-30",
)
assessment_id = assessment["id"]

# Mark control measures.
client.patch_control(
    assessment_id=assessment_id,
    measure_ref="a",           # Art.21(2)(a) — Risk Analysis & Policies
    status="compliant",
    notes="ISO 27001 certified, reviewed Q1 2026",
)
client.patch_control(
    assessment_id=assessment_id,
    measure_ref="b",           # Art.21(2)(b) — Incident Handling
    status="partially_compliant",
    gap_description="Playbooks exist but not tested in 2025",
    risk_score=6.5,
)

# Download the PDF compliance report.
client.generate_report(assessment_id, output_path="./nis2-report.pdf")
print("Report saved to ./nis2-report.pdf")

# Fetch audit log.
audit = client.get_audit_log(limit=20)
for entry in audit:
    print(entry["action"], entry["actor"], entry["timestamp"])
```

### Models

All model classes are importable from the top-level package:

```python
from opensecstack import (
    Organisation, Assessment, Control,
    Scan, Finding, AuditEntry, CitadelEvent,
)
```

When `pydantic >= 2.0` is installed the models are full Pydantic `BaseModel`
subclasses (validation, serialisation, JSON schema). Without pydantic they
fall back to Python dataclasses.

---

## Error handling

```python
from opensecstack import APIError, AuthenticationError, NotFoundError

try:
    scan = client.get_scan("non-existent-id")
except NotFoundError:
    print("Scan not found")
except AuthenticationError:
    print("Check your API key")
except APIError as exc:
    print(f"API error {exc.status_code}: {exc.detail}")
```

---

## Licence

Apache 2.0
