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

APIGuard is an HTTP **client** of CITADEL — it is not a webhook receiver, and CITADEL does not push events into APIGuard. apiguard's `internal/citadel.Client` (`internal/citadel/client.go`) calls two CITADEL endpoints:

- `POST /api/v1/marshal/evaluate` — submit a scan for a MARSHAL governance decision (see [Scan Governance](#scan-governance-marshal-evaluation-and-two-person-approval) below).
- `POST /api/v1/worm/emit` — forward an audit event to the immutable WORM chain. Called from the audit log worker for every local audit entry via `Client.LogEvent`, fire-and-forget, in a bounded background goroutine.
- `GET /api/v1/worm/verify` — verify WORM chain integrity for a time range (`Client.VerifyChain`).

When `citadel.api_url` (env `APIGUARD_CITADEL_URL`) is empty, the client is a complete no-op: every method returns immediately without making a network request, so apiguard runs normally with CITADEL disabled.

### Configuration

```yaml
citadel:
  api_url: "http://citadel-api:8099"
  key_id: "${APIGUARD_CITADEL_KEY_ID}"
  key_secret: "${APIGUARD_CITADEL_KEY_SECRET}"
  project_id: "apiguard"
  dry_run: true
  webhook_secret: "${APIGUARD_CITADEL_WEBHOOK_SECRET}"
  require_approval: false
```

See [Configuration Guide — CITADEL Integration](configuration.md#citadel-integration) for the full field/env-var table.

### Authentication: HMAC-SHA256 connector auth

Every request apiguard sends to CITADEL is signed, not bearer-token authenticated. `Client.do` (`internal/citadel/client.go`) attaches three headers to each request:

```
X-CITADEL-KEY  = key_id
X-CITADEL-TS   = current Unix timestamp (seconds)
X-CITADEL-SIG  = hmac-sha256=hex(HMAC-SHA256(key_secret, key_id + ":" + ts + ":" + hex(sha256(body))))
```

CITADEL recomputes the signature server-side using the shared `key_secret` for that `key_id` and rejects requests where it doesn't match. Requests also retry with exponential backoff (3 attempts, 500ms base) on 5xx responses and network errors; 4xx responses are returned immediately without retry.

### WORM Event Payload

`EmitWORM` posts to `POST /api/v1/worm/emit` with:

```json
{
  "source": "audit",
  "event_type": "scan_created",
  "project_id": "apiguard",
  "payload": { "...": "audit entry fields, e.g. actor_user_id, actor_role, result_status, system_module, resource_id" }
}
```

CITADEL responds with `worm_entry_id`, `chain_hash`, and `prev_hash`. apiguard tracks the last `chain_hash` it received and logs a warning (does not block) if the next response's `prev_hash` doesn't match — a best-effort local check for WORM chain continuity, not a substitute for `VerifyChain`/`GET /api/v1/worm/verify`.

### Scan Governance: MARSHAL Evaluation and Two-Person Approval

Beyond WORM audit logging, `POST /api/v1/scans` also submits every scan to CITADEL MARSHAL for a governance decision before it launches, via `POST /api/v1/marshal/evaluate` on the CITADEL client (`internal/citadel/client.go`), using the same HMAC connector auth (`citadel.key_id` / `citadel.key_secret`) described above.

The governance payload (the "Kerkese") carries:

- **Actor** — the real authenticated caller's sinauth user ID (from the request's JWT claims), plus `ActorToken`: the caller's own sinauth bearer token, forwarded so CITADEL can verify it directly against sinauth. This replaced a previous bug where scan creation submitted a hardcoded `UserID: 0` instead of the real requester.
- **Verifier** — by default, a fixed placeholder identity (`apiguard-system-verifier`) with no token. This is a known, deliberate gap: apiguard does not yet have a real second-approver flow for scan initiation *unless* `citadel.require_approval` is enabled (see below).
- **SoD** (Separation of Duties) — `operator_user_id` / `verifier_user_id`, evaluated by CITADEL Gate 3 (NDS).

A `REFUSE` or `HARD_STOP` decision blocks the scan with `403 Forbidden`; a MARSHAL call that errors (e.g. CITADEL unreachable) logs a warning and the scan proceeds — CITADEL evaluation is currently fail-open, not fail-closed.

**Known gap — Gate 2 (AuthZ) is not fully wired end-to-end.** CITADEL's RBAC map does not yet recognize apiguard's `deploy_change` action type for real REFUSE enforcement based on role. This is a gap on the CITADEL side, not something apiguard papers over — treat scan "governance" today as audited and SoD-checked, not yet as fully policy-enforced.

#### Optional: real two-person approval (`citadel.require_approval`)

Set `citadel.require_approval: true` (env: `APIGUARD_CITADEL_REQUIRE_APPROVAL`) to require a genuine, distinct second authenticated user to approve every scan before it runs. **Default: `false`** — with the flag off, apiguard's behavior is unchanged from before this feature: scans launch immediately using the placeholder Verifier described above.

When enabled:

1. `POST /api/v1/scans` no longer launches the scan. It creates a `scan_approvals` row (migration `008_create_scan_approvals`), returns `202 Accepted` with `"status": "pending_approval"`, and holds the scan's request details (spec/target/auth config) and the requester's bearer token in memory only — never persisted — for up to 24 hours (`pendingApprovalTTL`).
2. A **different** authenticated user calls `POST /api/v1/scans/{id}/approve`. The API rejects same-identity approval attempts with `403` before ever contacting CITADEL. On success, apiguard submits a Kerkese to MARSHAL with both a real Actor (the requester) and a real Verifier (the approver) — each with their own live sinauth bearer token — then launches the scan.
3. Alternatively, `POST /api/v1/scans/{id}/reject` (optional `{"reason": "..."}` body) declines the request; the scan never runs.
4. `GET /api/v1/scans/{id}/approval` returns the current approval state (`pending` / `approved` / `rejected`, who requested it, who decided it and when).

If the approval window expires (server restart or the 24-hour TTL) before a decision is made, `Approve` returns `410 Gone` and the requester must create a new scan — the ephemeral request details are gone.

Note that even with `require_approval` enabled, `SigOperator`/`SigVerifier` (Ed25519 signatures) and `VerifierToken` freshness are soft-gated: apiguard does not hold per-user signing keys, and an approver's token captured at request time may have expired by the time they act on it. CITADEL treats both as WARN-level, not a hard block, while `citadel.enforce_signatures` remains `false`.

---

## NIS2 Compass Integration

> **Not yet implemented.** No `nis2compass` client, config key, or
> outbound call exists anywhere in `apiguard/`. Everything below is
> target design.

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

> **Not yet implemented.** No `irflow` client or auto-incident code exists
> anywhere in `apiguard/`. Everything below is target design.

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

> **Not yet implemented.** No `threatflow` client exists anywhere in
> `apiguard/`. Everything below is target design.

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

> **Not yet implemented.** apiguard's webhook handling today is
> inbound-only (receiving CITADEL webhooks) — no outbound event emitter
> exists for any of the events below.

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
