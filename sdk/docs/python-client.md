# SDK Python Client

The Python SDK provides typed clients for APIGuard and NIS2Compass, plus dataclasses for the opensecstack integration contracts.

---

## Installation

```bash
pip install opensecstack
```

Requires Python 3.11+.

---

## APIGuard Client

### Creating a client

```python
from opensecstack import APIGuardClient

client = APIGuardClient(
    base_url="https://apiguard.internal",
    api_key="ag_key_...",
    timeout=30,
)
```

### Starting a scan

```python
scan = client.start_scan(
    target="https://api.example.com",
    spec_url="https://api.example.com/openapi.json",
    modules=["bola", "broken_auth", "injection"],
    metadata={"project": "ABISSNET_TCL_001"},
)
print(f"Scan ID: {scan.id}")
```

### Polling for results

```python
result = client.wait_for_scan(
    scan_id=scan.id,
    poll_interval=5,
    timeout=600,
)

for finding in result.findings:
    print(f"[{finding.severity}] {finding.owasp} — {finding.title}")
```

### Getting scan results directly

```python
result = client.get_scan(scan_id)
```

### Listing recent scans

```python
scans = client.list_scans(limit=20, status="completed")
```

### Async client

```python
from opensecstack import AsyncAPIGuardClient

async with AsyncAPIGuardClient(base_url=..., client_id=..., client_secret=...) as client:
    scan = await client.create_scan(spec_url=...)
    result = await client.get_scan(scan["id"])
```

---

## NIS2Compass Client

### Creating a client

```python
from opensecstack import NIS2CompassClient

client = NIS2CompassClient(
    base_url="https://nis2compass.internal",
    api_key="nc_key_...",
)
```

### Managing organisations

```python
# Create
org = client.create_organisation(
    name="Acme Corp",
    industry="finance",
    country="AL",
    size="large",
    entity_type="essential",
)

# Get
org = client.get_organisation(org_id)

# List
orgs = client.list_organisations()
```

### Managing assessments

```python
# Create
assessment = client.create_assessment(
    org_id=org.id,
    title="Q1 2026 NIS2 Assessment",
    framework_version="NIS2-2022/0383",
)

# Get with controls
assessment = client.get_assessment(org.id, assessment.id)
for control in assessment.controls:
    print(f"{control.measure_ref}: {control.status}")
```

### Updating a control

```python
updated = client.patch_control(
    org_id=org.id,
    assessment_id=assessment.id,
    measure_ref="art21_e",
    status="compliant",
    notes="APIGuard scan completed — zero critical findings",
    evidence_refs=["sha256:abc123..."],
)
```

---

## CITADEL Client

```python
from opensecstack.citadel import CITADELClient, Kerkese, Action, Principal, Evidence

client = CITADELClient(
    base_url="https://citadel.internal",
    key_id=KEY_ID,
    secret=SECRET,
)

# Check advisory
advisory = client.get_advisory("ABISSNET_TCL_001", "deploy_change")
if advisory.has_critical():
    print(f"CITADEL advisory: {advisory.advisories}")

# Submit Kerkese
result = client.evaluate(Kerkese(
    project_id="ABISSNET_TCL_001",
    action=Action(type="deploy_change", description="Deploy v2.1.0"),
    actor=Principal(user_id="alice@example.com", role="group_sig_operator"),
    verifier=Principal(user_id="bob@example.com", role="group_sig_verifier"),
    evidence=Evidence(change_id="CHG-001"),
))

if result["outcome"] != "EXECUTE":
    raise GovernanceError(result["reasons"])
```

---

## Error Handling

```python
from opensecstack.exceptions import RateLimitError, AuthError, NotFoundError
import time

try:
    result = client.start_scan(...)
except RateLimitError as e:
    time.sleep(e.retry_after)
    result = client.start_scan(...)  # retry
except AuthError:
    raise  # re-raise — fix the API key
except NotFoundError:
    raise
```

Exception types:

| Exception | HTTP status | Meaning |
|-----------|------------|---------|
| `AuthError` | 401 | Invalid API key |
| `NotFoundError` | 404 | Resource not found |
| `RateLimitError` | 429 | Rate limited; has `retry_after` attribute |
| `ServerError` | 5xx | Server-side error |

---

## Context Manager

```python
from opensecstack import APIGuardClient

with APIGuardClient(base_url=..., api_key=...) as client:
    result = client.get_scan(scan_id)
# Session closed automatically
```

---

## Type Hints

All client methods are fully typed. Key dataclasses:

```python
from opensecstack.types import (
    Scan,           # id, status, target, spec_url, created_at, completed_at
    Finding,        # id, severity, owasp, title, description, evidence
    Organisation,   # id, name, industry, country, size, entity_type
    Assessment,     # id, title, status, framework_version, controls
    Control,        # id, measure_ref, status, notes, evidence_refs
    ArtifactUpload, # hash, url, created_at
)
```

---

## Complete Example: Scan and Update NIS2 Control

```python
from opensecstack import APIGuardClient, NIS2CompassClient

apiguard = APIGuardClient(base_url=APIGUARD_URL, api_key=APIGUARD_KEY)
nis2 = NIS2CompassClient(base_url=NIS2_URL, api_key=NIS2_KEY)

# Run scan
scan = apiguard.start_scan(target=target, spec_url=spec_url)
result = apiguard.wait_for_scan(scan.id)

# Export evidence
bundle = apiguard.export_nis2_evidence(scan.id)

# Upload to NIS2Compass
artifact = nis2.upload_artifact(org_id, bundle)

# Mark control compliant
nis2.patch_control(
    org_id=org_id,
    assessment_id=assessment_id,
    measure_ref="art21_e",
    status="compliant",
    notes=f"APIGuard scan {scan.id} — {result.stats.critical} critical findings",
    evidence_refs=[artifact.hash],
)
```
