# NIS2 Compass Integration Guide

This guide describes how to connect NIS2 Compass with external systems. All integrations are API-driven. No direct database writes from external systems are supported or sanctioned.

---

## Overview

NIS2 Compass exposes a REST API on **port 8090**. The full OpenAPI specification is available at `http://<host>:8090/docs` when the service is running.

**Authentication**: All endpoints except `GET /health` require a Bearer JWT in the `Authorization` header:

```
Authorization: Bearer <token>
```

Tokens are signed with `NIS2_JWT_SECRET` and have a 1-hour TTL. External systems should implement token refresh logic before the TTL expires to avoid 401 responses mid-operation.

**Base URL**: `http://<host>:8090/api/v1`

---

## SIEM Integration

Supported targets: Splunk, Elastic (ECS), Microsoft Sentinel.

### Polling the Audit Log

NIS2 Compass does not push events; external SIEMs must poll `GET /api/v1/audit`. Poll on a schedule (e.g., every 2–5 minutes) and filter by timestamp to retrieve only new entries:

```
GET /api/v1/audit?after=<ISO8601_timestamp>
```

Persist the `timestamp` of the last ingested entry and use it as the `after` parameter on the next poll cycle.

### Field Mapping

Map `risk_class` to SIEM severity as follows:

| NIS2 `risk_class` | SIEM Severity |
|---|---|
| `INFO` | Low |
| `WARNING` | Medium |
| `CRITICAL` | High |

Index these fields for efficient querying:

- `action` — event type (e.g., `assessment_created`, `control_updated`)
- `actor` — identity of the user or service that performed the action
- `resource_type` — the entity type affected
- `resource_id` — UUID of the affected entity
- `chain_hash` — SHA-256 chain anchor; retain this for tamper-evidence correlation
- `timestamp` — event time (store in UTC)

### Example: Splunk HEC Forwarder (Python)

The following script polls the audit endpoint and forwards new entries to Splunk via the HTTP Event Collector:

```python
import os, time, requests
from datetime import datetime, timezone

NIS2_BASE    = os.environ["NIS2_BASE_URL"]          # e.g. http://nis2compass:8090/api/v1
NIS2_TOKEN   = os.environ["NIS2_TOKEN"]
SPLUNK_HEC   = os.environ["SPLUNK_HEC_URL"]         # e.g. https://splunk:8088/services/collector
SPLUNK_TOKEN = os.environ["SPLUNK_HEC_TOKEN"]
STATE_FILE   = "/var/lib/nis2-siem/last_seen.txt"

RISK_TO_SEVERITY = {"INFO": "low", "WARNING": "medium", "CRITICAL": "high"}

def load_cursor():
    try:
        return open(STATE_FILE).read().strip()
    except FileNotFoundError:
        return "1970-01-01T00:00:00Z"

def save_cursor(ts):
    os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
    open(STATE_FILE, "w").write(ts)

def poll_and_forward():
    cursor = load_cursor()
    resp = requests.get(
        f"{NIS2_BASE}/audit",
        params={"after": cursor},
        headers={"Authorization": f"Bearer {NIS2_TOKEN}"},
        timeout=10,
    )
    resp.raise_for_status()
    entries = resp.json().get("items", [])
    if not entries:
        return
    events = [
        {"time": entry["timestamp"], "sourcetype": "nis2:audit",
         "event": {**entry, "severity": RISK_TO_SEVERITY.get(entry["risk_class"], "low")}}
        for entry in entries
    ]
    requests.post(
        SPLUNK_HEC, json={"events": events},
        headers={"Authorization": f"Splunk {SPLUNK_TOKEN}"}, timeout=10,
    ).raise_for_status()
    save_cursor(max(e["timestamp"] for e in entries))

while True:
    poll_and_forward()
    time.sleep(120)
```

---

## Ticketing System Integration

Supported targets: Jira, ServiceNow.

### Polling for Non-Compliant Controls

Query non-compliant controls for a given assessment:

```
GET /api/v1/assessments/{assessment_id}/controls?status=non_compliant
```

Run this on a schedule (e.g., nightly or after each assessment update). For each returned control, create or update a ticket in your ticketing system.

### Risk Score to Ticket Priority Mapping

| `risk_score` | Ticket Priority |
|---|---|
| 8.0 – 10.0 | P1 (Critical) |
| 6.0 – 7.9 | P2 (High) |
| 4.0 – 5.9 | P3 (Medium) |
| 0.0 – 3.9 | P4 (Low) |

### Example: Create Jira Issues from Non-Compliant Controls (Python)

```python
import os, requests

NIS2_BASE      = os.environ["NIS2_BASE_URL"]
NIS2_TOKEN     = os.environ["NIS2_TOKEN"]
JIRA_BASE      = os.environ["JIRA_BASE_URL"]    # e.g. https://yourorg.atlassian.net
JIRA_EMAIL     = os.environ["JIRA_EMAIL"]
JIRA_API_TOKEN = os.environ["JIRA_API_TOKEN"]
JIRA_PROJECT   = os.environ["JIRA_PROJECT_KEY"] # e.g. NIS2

SCORE_TO_PRIORITY = {range(0, 40): "Low", range(40, 60): "Medium",
                     range(60, 80): "High", range(80, 101): "Highest"}

def score_priority(score):
    s = int((score or 0) * 10)
    for r, p in SCORE_TO_PRIORITY.items():
        if s in r:
            return p
    return "Low"

def sync_controls(assessment_id):
    controls = requests.get(
        f"{NIS2_BASE}/assessments/{assessment_id}/controls",
        params={"status": "non_compliant"},
        headers={"Authorization": f"Bearer {NIS2_TOKEN}"},
    ).json().get("items", [])

    for ctrl in controls:
        payload = {
            "fields": {
                "project": {"key": JIRA_PROJECT},
                "summary": f"[NIS2] {ctrl['article_ref']} — {ctrl['title']}",
                "description": {
                    "type": "doc", "version": 1,
                    "content": [{"type": "paragraph", "content": [
                        {"type": "text",
                         "text": f"Gap: {ctrl.get('gap_description','')}\n"
                                 f"Remediation: {ctrl.get('remediation_plan','')}"}
                    ]}]
                },
                "priority": {"name": score_priority(ctrl.get("risk_score", 0))},
                "issuetype": {"name": "Task"},
            }
        }
        requests.post(
            f"{JIRA_BASE}/rest/api/3/issue", json=payload,
            auth=(JIRA_EMAIL, JIRA_API_TOKEN),
        ).raise_for_status()
```

---

## Dashboard and BI Integration

Supported targets: Grafana, Microsoft Power BI.

### Read-Only Database Access

For dashboards that query data directly from PostgreSQL, create a dedicated read-only database user. Do not expose the `nis2compass` application user credentials to BI tools.

```sql
CREATE USER nis2_readonly WITH PASSWORD 'choose_a_strong_password';
GRANT CONNECT ON DATABASE nis2compass TO nis2_readonly;
GRANT USAGE ON SCHEMA public TO nis2_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO nis2_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO nis2_readonly;
```

Use a read-only replica if available. For single-node deployments, the primary is acceptable for dashboard reads, but long-running BI queries should be scheduled during off-peak hours.

### Key Dashboard Queries

**Controls by compliance status per assessment:**

```sql
SELECT
    a.title               AS assessment,
    c.status,
    count(*)              AS control_count
FROM controls c
JOIN assessments a ON a.id = c.assessment_id
GROUP BY a.title, c.status
ORDER BY a.title, c.status;
```

**Risk score trend over time (average score per day, rolling):**

```sql
SELECT
    date_trunc('day', c.assessed_at) AS day,
    round(avg(c.risk_score)::numeric, 2) AS avg_risk_score
FROM controls c
WHERE c.assessed_at IS NOT NULL
GROUP BY 1
ORDER BY 1;
```

**Audit event frequency by actor (last 30 days):**

```sql
SELECT
    actor,
    count(*)              AS event_count,
    max(timestamp)        AS last_seen
FROM audit_log
WHERE timestamp >= NOW() - INTERVAL '30 days'
GROUP BY actor
ORDER BY event_count DESC;
```

---

## CI/CD Pipeline Integration

### Use Case

Block a deployment if any NIS2 control has a `risk_score` above 8.0 and a status of `non_compliant`. This acts as a compliance posture gate in the deployment pipeline.

### GitHub Actions Step Example

```yaml
- name: NIS2 compliance posture gate
  env:
    NIS2_BASE_URL: ${{ vars.NIS2_BASE_URL }}
    NIS2_TOKEN: ${{ secrets.NIS2_TOKEN }}
    ASSESSMENT_ID: ${{ vars.NIS2_ASSESSMENT_ID }}
  run: |
    RESPONSE=$(curl -sf \
      -H "Authorization: Bearer $NIS2_TOKEN" \
      "$NIS2_BASE_URL/api/v1/assessments/$ASSESSMENT_ID/controls?status=non_compliant")

    HIGH_RISK=$(echo "$RESPONSE" | jq '[.items[] | select(.risk_score >= 8.0)] | length')

    if [ "$HIGH_RISK" -gt 0 ]; then
      echo "Deployment blocked: $HIGH_RISK NIS2 control(s) have risk_score >= 8.0 and status non_compliant."
      echo "$RESPONSE" | jq '.items[] | select(.risk_score >= 8.0) | {article_ref, title, risk_score}'
      exit 1
    fi

    echo "NIS2 posture gate passed. No high-risk non-compliant controls."
```

This step fails the pipeline job (exit 1) if any critical non-compliant controls are detected, preventing the deployment from proceeding until compliance is restored.

---

## APIGuard Integration

APIGuard is the sibling API security scanning platform within the OpenSecStack suite. It produces findings mapped to the OWASP API Security Top 10. NIS2 Compass and APIGuard are designed to interoperate.

### Conceptual Architecture

```
APIGuard scan completes
         |
         v
APIGuard findings API (OWASP API Top 10 findings)
         |
         v
Integration service (reads findings, maps to NIS2 controls)
         |
         v
NIS2 Compass API (PATCH control status / POST audit event)
```

### OWASP to NIS2 Control Mapping

APIGuard findings map primarily to NIS2 Article 21(2)(e): Network and Information Systems Security. This measure covers vulnerability management, technical hardening, and secure network architecture — the domain in which API security findings are most directly relevant.

| APIGuard Finding Severity | NIS2 Control Action |
|---|---|
| High / Critical | Set control `Art.21(2)(e)` status to `non_compliant`, `risk_score` proportional to CVSS, trigger audit log entry with `risk_class = CRITICAL` |
| Medium | Set status to `partially_compliant`, `risk_class = WARNING` |
| Low / Informational | Append to evidence JSONB, `risk_class = INFO` |

### Integration Service Responsibilities

1. After each APIGuard scan, retrieve findings via the APIGuard findings API.
2. Aggregate findings by severity.
3. Determine the composite `risk_score` for `Art.21(2)(e)` based on finding severity distribution.
4. Call `PATCH /api/v1/assessments/{id}/controls/e` with updated `status`, `risk_score`, `gap_description`, and a JSONB `evidence` payload referencing the APIGuard scan report ID.
5. The NIS2 Compass API will append a `control_status_changed` entry to the `audit_log` automatically.

This integration ensures that API security posture measured by APIGuard flows automatically into the NIS2 compliance record without manual data entry.

---

## Webhook Delivery

NIS2 Compass can deliver audit events to a configured webhook endpoint in near-real-time, avoiding the need for external systems to poll.

### Payload Format

Each webhook delivery sends the audit log entry as a JSON object:

```json
{
  "id": "uuid",
  "action": "control_updated",
  "actor": "user@example.com",
  "resource_type": "control",
  "resource_id": "uuid",
  "risk_class": "WARNING",
  "metadata": {},
  "object_fingerprint": "sha256hex",
  "prev_hash": "sha256hex",
  "chain_hash": "sha256hex",
  "timestamp": "2026-03-25T12:00:00Z"
}
```

### Retry Policy

Deliveries are retried up to 3 times with exponential backoff: 10 seconds, 30 seconds, 90 seconds. If all three attempts fail, the event is logged as undelivered. No further automatic retry occurs; manual redelivery via the API is available if required.

### Signature Verification

Each webhook request includes an `X-NIS2-Signature` header containing an HMAC-SHA256 signature of the raw request body, computed using the configured webhook shared secret:

```
X-NIS2-Signature: sha256=<hex_digest>
```

Receiving systems must verify this signature before processing the payload:

```python
import hashlib, hmac

def verify_signature(secret: str, body: bytes, signature_header: str) -> bool:
    expected = "sha256=" + hmac.new(
        secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)
```

Reject any delivery where the signature does not match. Do not process the payload before verifying the signature.
