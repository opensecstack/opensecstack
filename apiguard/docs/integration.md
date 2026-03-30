# APIGuard Integration Guide

APIGuard integrates with other opensecstack platforms by emitting signed webhook events. All integration is one-way outbound: APIGuard pushes events; no platform writes back to APIGuard scan data.

---

## Integration Architecture

```
APIGuard
    │
    ├── scan_completed ──────────► ThreatFlow   (findings as IOC context)
    │                ──────────► NIS2 Compass  (compliance evidence)
    │                ──────────► IRFlow        (auto-incident on CRITICAL)
    │
    └── all events   ──────────► CITADEL       (immutable governance log)
```

---

## CITADEL Integration

CITADEL receives every scan lifecycle event and logs them to the immutable WORM chain.

### Configuration

```yaml
citadel:
  enabled: true
  webhook_url: "https://citadel.internal/ingest/apiguard"
  api_key: "${CITADEL_API_KEY}"
  emit_events:
    - scan_started
    - scan_completed
    - finding_critical
    - finding_high
  verify_tls: true
```

### Event Payload

```json
{
  "event": "scan_completed",
  "source": "apiguard",
  "source_version": "0.2.0",
  "ts_utc": "2026-03-30T14:00:00Z",
  "scan_id": "uuid",
  "target_url": "https://api.example.com",
  "spec_hash": "sha256:abc123",
  "summary": {
    "total": 12,
    "critical": 1,
    "high": 3,
    "medium": 5,
    "low": 3
  },
  "signature": "hmac-sha256:..."
}
```

CITADEL verifies the HMAC-SHA256 signature using the shared `api_key` before logging. Events that fail signature verification are rejected with HTTP 401.

---

## NIS2 Compass Integration

APIGuard scan results become compliance evidence for NIS2 Article 21(2)(e) — vulnerability handling and disclosure.

### Configuration

```yaml
integrations:
  nis2compass:
    enabled: true
    url: "https://nis2compass.internal"
    api_key: "${NIS2COMPASS_API_KEY}"
    org_id: "uuid-of-org-in-nis2compass"
    # Map scan findings to specific NIS2 measure references
    measure_mapping:
      default: "art21_e"          # vulnerability handling
      a8_misconfig: "art21_h"     # network security
      a2_auth: "art21_i"          # access control
```

### What Gets Sent

On `scan_completed`, APIGuard posts a compliance evidence bundle to NIS2 Compass:

```json
{
  "source": "apiguard",
  "scan_id": "uuid",
  "evidence_type": "api_security_scan",
  "scan_date": "2026-03-30T14:00:00Z",
  "target_url": "https://api.example.com",
  "spec_hash": "sha256:abc123",
  "findings_summary": {
    "total": 12,
    "critical": 1,
    "high": 3
  },
  "measure_ref": "art21_e",
  "report_url": "https://apiguard.internal/reports/uuid.html"
}
```

NIS2 Compass stores this as an evidence artifact linked to the configured `org_id` and `measure_ref`.

---

## IRFlow Integration

CRITICAL findings trigger automatic incident creation in IRFlow.

### Configuration

```yaml
integrations:
  irflow:
    enabled: true
    url: "https://irflow.internal"
    api_key: "${IRFLOW_API_KEY}"
    auto_incident:
      enabled: true
      severity_threshold: critical    # critical | high
      tags:
        - api-security
        - apiguard
```

### Auto-Incident Payload

```json
{
  "title": "CRITICAL API finding: Broken Object Level Authorization on /api/v1/users/{id}",
  "source": "apiguard",
  "severity": "critical",
  "scan_id": "uuid",
  "finding_id": "uuid",
  "owasp_id": "API1:2023",
  "endpoint": "GET /api/v1/users/{id}",
  "cvss_score": 9.1,
  "evidence_url": "https://apiguard.internal/findings/uuid",
  "tags": ["api-security", "apiguard"]
}
```

---

## ThreatFlow Integration

APIGuard findings contribute context to ThreatFlow's threat intelligence feeds. HIGH and CRITICAL findings on publicly exposed APIs are submitted as structured indicators.

### Configuration

```yaml
integrations:
  threatflow:
    enabled: true
    url: "https://threatflow.internal"
    api_key: "${THREATFLOW_API_KEY}"
    submit_findings:
      - critical
      - high
```

---

## SDK Integration

Use the opensecstack SDK to integrate APIGuard programmatically.

### Go

```go
import "github.com/opensecstack/sdk/go/opensecstack"

client := opensecstack.NewAPIGuardClient("https://apiguard.internal", "Bearer "+token)

// Create a scan
scan, err := client.CreateScan(ctx, opensecstack.CreateScanRequest{
    SpecURL: "https://api.example.com/openapi.json",
    Target:  "https://api.example.com",
    Modules: []string{"a1_bola", "a2_auth", "a8_misconfig"},
})

// Poll until complete
for scan.Status == opensecstack.ScanStatusRunning {
    time.Sleep(5 * time.Second)
    scan, err = client.GetScan(ctx, scan.ID)
}

// Get findings
findings, err := client.ListFindings(ctx, scan.ID, opensecstack.ListFindingsOptions{})
```

### Python

```python
from opensecstack import APIGuardClient

client = APIGuardClient(base_url="https://apiguard.internal", api_key="sk-...")

scan = client.create_scan(
    spec_url="https://api.example.com/openapi.json",
    target="https://api.example.com",
)

scan = client.wait_for_scan(scan["id"])  # blocks until completed or failed
findings = client.list_findings(scan_id=scan["id"])
```

---

## Webhook Event Reference

All webhooks include an `X-APIGuard-Signature` header containing `hmac-sha256=<hex>`. Compute the HMAC using the `api_key` as the secret and the raw request body as the message.

| Event | Trigger | Payload |
|-------|---------|---------|
| `scan_started` | Scan transitions from `pending` to `running` | scan_id, target_url, spec_hash, ts_utc |
| `scan_completed` | Scan reaches `completed` state | scan_id, summary (counts by severity), report_url |
| `scan_failed` | Scan reaches `failed` state | scan_id, error_message |
| `finding_critical` | A CRITICAL finding is recorded during a scan | finding_id, scan_id, owasp_id, endpoint, cvss_score |
| `finding_high` | A HIGH finding is recorded during a scan | finding_id, scan_id, owasp_id, endpoint, cvss_score |

### Verifying Signatures (Go)

```go
func verifySignature(secret, body []byte, header string) bool {
    mac := hmac.New(sha256.New, secret)
    mac.Write(body)
    expected := "hmac-sha256=" + hex.EncodeToString(mac.Sum(nil))
    return hmac.Equal([]byte(expected), []byte(header))
}
```

---

## Integration Checklist

Before enabling any integration in production:

- [ ] Shared API keys stored in secrets manager, not config files
- [ ] TLS verification enabled (`verify_tls: true`) for all webhook targets
- [ ] CITADEL integration tested in dry-run mode first
- [ ] IRFlow auto-incident threshold reviewed — avoid alert storms on large scans
- [ ] NIS2 Compass `org_id` and `measure_mapping` verified against live org
