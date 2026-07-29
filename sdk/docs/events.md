# SDK Events

The SDK defines a typed event system for webhooks and async notifications from opensecstack platforms.

---

## Overview

Platforms emit events to registered webhook endpoints when significant actions occur. The SDK provides:
- Typed event structs for each event type
- Webhook signature verification
- An event router for handling multiple event types in a single handler

---

## Event Envelope

All events share a common envelope:

```go
type Event struct {
    EventID   string         `json:"event_id"`
    EventType string         `json:"event_type"`
    Source    string         `json:"source"`      // "apiguard" | "nis2compass" | "citadel"
    TsUTC     time.Time      `json:"ts_utc"`
    ProjectID string         `json:"project_id,omitempty"`
    Payload   map[string]any `json:"payload"`
}
```

```python
@dataclass
class Event:
    event_id: str
    event_type: str
    source: str
    ts_utc: datetime
    project_id: str | None
    payload: dict
```

---

## APIGuard Events

### `apiguard.scan.completed`

Emitted when a scan finishes successfully.

```json
{
  "event_type": "apiguard.scan.completed",
  "source": "apiguard",
  "ts_utc": "2026-03-30T14:05:00Z",
  "payload": {
    "scan_id": "uuid",
    "target": "https://api.example.com",
    "spec_hash": "sha256:abc123",
    "status": "completed",
    "stats": {"total": 5, "critical": 0, "high": 2, "medium": 3, "low": 0}
  }
}
```

### `apiguard.scan.failed`

Emitted when a scan fails (parse error, target unreachable, etc.).

```json
{
  "event_type": "apiguard.scan.failed",
  "payload": {
    "scan_id": "uuid",
    "target": "https://api.example.com",
    "error": "spec parse failed: unexpected token at line 42"
  }
}
```

### `apiguard.finding.critical`

Emitted immediately when a critical-severity finding is detected (before scan completes).

```json
{
  "event_type": "apiguard.finding.critical",
  "payload": {
    "scan_id": "uuid",
    "finding_id": "uuid",
    "owasp": "a2_broken_auth",
    "title": "JWT signature not verified",
    "endpoint": "GET /api/v1/users/{id}"
  }
}
```

---

## NIS2Compass Events

### `nis2compass.control.updated`

Emitted when a control's status changes.

```json
{
  "event_type": "nis2compass.control.updated",
  "source": "nis2compass",
  "payload": {
    "org_id": "uuid",
    "assessment_id": "uuid",
    "measure_ref": "art21_e",
    "previous_status": "partially_compliant",
    "new_status": "compliant",
    "updated_by": "alice@example.com"
  }
}
```

### `nis2compass.assessment.completed`

Emitted when all controls in an assessment reach a terminal status.

```json
{
  "event_type": "nis2compass.assessment.completed",
  "payload": {
    "org_id": "uuid",
    "assessment_id": "uuid",
    "stats": {
      "compliant": 8,
      "partially_compliant": 2,
      "non_compliant": 0,
      "not_applicable": 0
    }
  }
}
```

---

## CITADEL Events

### `citadel.hard_stop`

Emitted immediately on any HARD STOP outcome.

```json
{
  "event_type": "citadel.hard_stop",
  "source": "citadel",
  "project_id": "ABISSNET_TCL_001",
  "payload": {
    "execution_id": "uuid",
    "worm_entry_id": "uuid",
    "actor_user_id": "alice@example.com",
    "trigger": "sod_violation",
    "irflow_incident_id": "INC-2026-001"
  }
}
```

### `citadel.vigil_red` (planned)

> VIGIL is design-stage as of CITADEL v1.0.0 — this event type does not
> exist yet. It ships with VIGIL in CITADEL v2.0. Documented here so
> integrators can plan ahead. See
> [citadel/docs/vigil.md](../../citadel/docs/vigil.md).

Will be emitted when VIGIL transitions to RED.

```json
{
  "event_type": "citadel.vigil_red",
  "payload": {
    "previous_state": "AMBER",
    "reason": "active_hard_stop",
    "active_hard_stops": 1
  }
}
```

### `citadel.vigil_amber` (planned)

Will be emitted when VIGIL transitions to AMBER (see the VIGIL note above —
design-stage as of CITADEL v1.0.0, ships v2.0).

```json
{
  "event_type": "citadel.vigil_amber",
  "payload": {
    "previous_state": "GREEN",
    "reason": "mirror_stale",
    "mirror_id": "Mirror_Odoo18_TCL_001",
    "age_seconds": 947
  }
}
```

---

## Receiving Webhooks

### Signature verification

All webhook payloads are signed with `X-CITADEL-SIG` (CITADEL) or `X-APIGUARD-SIG` (APIGuard) using HMAC-SHA256:

```go
import "github.com/opensecstack/sdk/go/opensecstack/webhook"

func myWebhookHandler(w http.ResponseWriter, r *http.Request) {
    body, _ := io.ReadAll(r.Body)

    // Verify signature before processing
    sig := r.Header.Get("X-APIGUARD-SIG")
    if !webhook.VerifySignature(body, sig, webhookSecret) {
        http.Error(w, "invalid signature", http.StatusUnauthorized)
        return
    }

    event, err := webhook.ParseEvent(body)
    if err != nil {
        http.Error(w, "parse error", http.StatusBadRequest)
        return
    }

    // Route by event type
    switch event.EventType {
    case "apiguard.scan.completed":
        handleScanCompleted(event)
    case "citadel.hard_stop":
        handleHardStop(event)
    }

    w.WriteHeader(http.StatusOK)
}
```

```python
from opensecstack.webhook import verify_signature, parse_event

def webhook_handler(request):
    body = request.body
    sig = request.headers.get("X-APIGUARD-SIG")

    if not verify_signature(body, sig, WEBHOOK_SECRET):
        return HttpResponse(status=401)

    event = parse_event(body)

    if event.event_type == "apiguard.scan.completed":
        handle_scan_completed(event)
    elif event.event_type == "citadel.hard_stop":
        handle_hard_stop(event)

    return HttpResponse(status=200)
```

### Using the event router

```go
router := webhook.NewRouter(webhookSecret)

router.On("apiguard.scan.completed", func(e *opensecstack.Event) error {
    // handle scan completion
    return nil
})

router.On("citadel.hard_stop", func(e *opensecstack.Event) error {
    // handle hard stop
    return nil
})

http.Handle("/webhooks/opensecstack", router)
```

---

## Event Delivery Guarantees

| Platform | Retry policy | Ordering guarantee |
|----------|-------------|-------------------|
| APIGuard | No retry (v0.1.x) | Best-effort in-order per scan |
| NIS2Compass | No retry (v0.1.x) | Best-effort |
| CITADEL | No retry (v0.1.x) | Guaranteed in WORM log order |

Always poll as a fallback. Do not rely solely on webhooks for critical alerting paths.
