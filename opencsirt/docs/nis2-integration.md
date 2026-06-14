# NIS2 Compass Integration — Article 23 Notification

> v1.0.0. OpenCSIRT pushes Article 23 incident notifications to
> NIS2 Compass when an incident reaches severity ≥ HIGH. The
> implementation is `*NIS2Client` in
> [internal/integrations/nis2.go](../internal/integrations/nis2.go).
> This is **outbound only**; OpenCSIRT does not consume anything
> from NIS2 Compass.

## Why

NIS2 Article 23 obliges essential and important entities to notify
their CSIRT (and through it the competent authority) of significant
incidents within tight deadlines:

- **24 hours** for the early warning,
- **72 hours** for the incident notification,
- one month for the final report.

OpenCSIRT is the CSIRT-side leg of that pipeline. NIS2 Compass is
the compliance dashboard that tracks the deadlines. This integration
is the wire between them — when OpenCSIRT opens or escalates an
incident at severity ≥ HIGH, Compass starts the clock.

## Trigger model & threshold

The threshold is enforced inside `(*NIS2Client).Notify`:

```go
if n.Severity != "high" && n.Severity != "critical" {
    return errors.New("nis2: severity below notification threshold")
}
```

Calls below the threshold return immediately with a sentinel error
that the caller treats as a no-op (not a failure). Concretely:

| Severity | Outcome |
|---|---|
| `low` | no notification; no error surfaced upstream |
| `medium` | no notification |
| `high` | `POST /api/v1/notifications/article23` |
| `critical` | `POST /api/v1/notifications/article23` |

The severity values are the same enum as the `incidents.severity`
CHECK constraint in [migrations/0001_init.up.sql](../migrations/0001_init.up.sql).

## Wire contract

```
POST {OPENCSIRT_NIS2COMPASS_API_URL}/api/v1/notifications/article23
Content-Type: application/json
```

Body is the `NIS2Notification` struct, JSON-encoded:

```go
type NIS2Notification struct {
    IncidentID     uuid.UUID  `json:"incident_id"`
    ConstituencyID *uuid.UUID `json:"constituency_id,omitempty"`
    Severity       string     `json:"severity"`
    Title          string     `json:"title"`
    OpenedAt       time.Time  `json:"opened_at"`
    Source         string     `json:"source"`
}
```

Field semantics:

| Field | Source in OpenCSIRT |
|---|---|
| `incident_id` | `incidents.id` |
| `constituency_id` | `incidents.constituency_id` (nullable; omitted on the wire when nil) |
| `severity` | `incidents.severity` |
| `title` | `incidents.title` |
| `opened_at` | `incidents.opened_at` |
| `source` | `incidents.source` (`irflow`, `manual`, `abuse_mailbox`, or `peer_csirt`) |

The HTTP client has a 15-second timeout
(`http.Client{Timeout: 15 * time.Second}` in `NewNIS2Client`), short
enough to not block an inbound API request for a meaningful time
even when Compass is wedged.

## Deadline calculation (operator-owned)

OpenCSIRT records `opened_at` and emits the severity. The 24h-early /
72h-full deadlines are computed by NIS2 Compass against `opened_at +
24h` and `opened_at + 72h`. OpenCSIRT does not compute or persist
these deadlines locally — Compass owns the regulatory timer. This
keeps a single authoritative deadline per incident across the
ecosystem.

## Best-effort delivery

`Notify` is invoked from the API request goroutine that opened the
incident, but its failure is **not** propagated to the upstream
caller's response. Concretely:

1. The API handler creates the incident row in Postgres.
2. The CITADEL `opencsirt.incident_opened` event is enqueued in
   `citadel_outbox`.
3. `(*NIS2Client).Notify(ctx, n)` is called.
4. If `Notify` returns an error, the handler logs at WARN and
   returns 201 to the upstream caller with the new incident id.

The rationale is that the incident record and CITADEL evidence are
the durable artefacts; the Compass notification is recoverable
(operator can replay; Compass has its own backfill).

## Disabling

Setting `OPENCSIRT_NIS2COMPASS_API_URL=""` (the v1.0.0 default in
`.env.example`) disables the integration. `Notify` short-circuits:

```go
if c.apiURL == "" {
    c.logger.Debug().Msg("nis2: API URL empty, notification suppressed")
    return nil
}
```

It returns `nil` (not an error) so callers can invoke `Notify`
unconditionally without a feature flag at the call site. This is
the recommended posture for non-NIS2-scope deployments.

## Failure modes

| Symptom | Cause | Behaviour |
|---|---|---|
| `nis2: severity below notification threshold` | severity ∈ {low, medium} | swallowed by caller; not a real failure |
| `nis2: notify <code>` (4xx) | Compass schema rejection | logged WARN; no retry in v1.0.0 |
| `nis2: notify <code>` (5xx) | Compass transient | logged WARN; no retry in v1.0.0 |
| HTTP timeout (15s) | Compass wedged | logged WARN; incident still recorded |
| Connection refused | Compass down or wrong URL | logged WARN; incident still recorded |

v1.1 will move this onto the same outbox / retry pattern used for
CITADEL (`citadel_outbox` + `*citadel.Watcher`); v1.0.0 leaves
retries to the operator (replay via a manual API call when Compass
returns from an outage).

## Configuration

```bash
# OpenCSIRT side — empty disables the integration
OPENCSIRT_NIS2COMPASS_API_URL=https://nis2compass.internal:8090
```

No bearer token is sent in v1.0.0 — same trust-zone assumption as
[threatflow-integration.md § Auth contract](threatflow-integration.md).
A bearer token (`OPENCSIRT_NIS2COMPASS_TOKEN`) and mTLS option are
v1.1 hardening items.

## Related

- [internal/integrations/nis2.go](../internal/integrations/nis2.go) — implementation
- [security/compliance-map.md](security/compliance-map.md) — Article 23 row referencing this page
- [irflow-integration.md](irflow-integration.md) — high/critical incidents arriving via the IRFlow webhook trigger this notification
- [citadel-integration.md](citadel-integration.md) — every Article 23 notification is preceded by an `opencsirt.incident_opened` (or `..._escalation_sent`) WORM event
- [../../docs/deployment-topology.md](../../docs/deployment-topology.md) — port 8088 (OpenCSIRT) ↔ 8090 (NIS2 Compass) trust zone
- [../../nis2compass/docs/](../../nis2compass/docs/) — receiver-side contract and Article 23 timer model
