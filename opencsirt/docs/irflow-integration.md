# IRFlow Integration

> v1.0.0. **IRFlow is the upstream incident-response orchestrator;
> OpenCSIRT is the downstream CSIRT operations plane.** When IRFlow
> determines an incident requires CSIRT coordination, it POSTs the
> incident to OpenCSIRT's webhook. The receiver is implemented by
> [internal/integrations/irflow.go](../internal/integrations/irflow.go),
> which calls into the canonical `incident.Service` to create a
> first-class OpenCSIRT incident.

## Why this integration

The ecosystem [data-flow rule](../../ECOSYSTEM.md) declares:

> IRFlow incidents → OpenCSIRT (CSIRT coordination)

IRFlow runs the per-organisation playbook (containment, comms,
ticketing). OpenCSIRT runs the per-constituency CSIRT workflow
(advisories, peer-CSIRT escalation, NIS2 Article 23 notification).
The two responsibilities overlap on **incident records that need
both** — a banking-sector phishing wave is both an IRFlow incident
for the bank and a constituency-level escalation for the sector
CSIRT.

The webhook closes the gap mechanically rather than relying on
operators to copy fields between dashboards.

## Endpoint

```
POST /api/v1/integrations/irflow/incident
Content-Type: application/json
X-Timestamp: <RFC3339 UTC>
X-Signature: <hex of HMAC-SHA256(secret, ts || "." || body)>
```

The handler is `*integrations.IRFlowWebhook` — registered on the
chi router by `cmd/opencsirt-api`. It satisfies `http.Handler` (see
the compile-time `var _ http.Handler = (*IRFlowWebhook)(nil)`
assertion at the bottom of `irflow.go`).

## HMAC verification

Signature verification is delegated to `VerifyHMAC` in
[internal/integrations/webhook_hmac.go](../internal/integrations/webhook_hmac.go),
the same routine used everywhere else inbound webhooks land. The
scheme:

| Element | Value |
|---|---|
| Algorithm | HMAC-SHA256 |
| Signed input | `ts || "." || raw_body` |
| Encoding | hex (lowercase, no `0x`) |
| Timestamp format | RFC3339 (e.g. `2026-05-10T10:24:01Z`) |
| Replay window | ±5 minutes |
| Secret source | `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` (env, must match IRFlow signer side) |

`VerifyHMAC` enforces:

- `time.Parse(time.RFC3339, ts)` — fail-closed on a malformed
  timestamp.
- `drift > 5*time.Minute || drift < -5*time.Minute` rejection.
- `hmac.Equal(want, got)` — constant-time compare. **Do not** swap
  this for `bytes.Equal`; it is the timing-attack mitigation.

A failure path returns `401 signature invalid` with a logged WARN
including the underlying reason (`invalid timestamp`, `timestamp
outside replay window`, `signature mismatch`, etc.). The body is
*not* echoed in the error response.

## Payload mapping

The receiver decodes the IRFlow payload into the package-private
`irflowIncident` struct:

```go
type irflowIncident struct {
    ID       string         `json:"id"`
    Severity string         `json:"severity"`
    Title    string         `json:"title"`
    Summary  string         `json:"summary"`
    OpenedAt string         `json:"opened_at"`
    Tenant   string         `json:"tenant_id"`
    Metadata map[string]any `json:"metadata,omitempty"`
}
```

Mapping into `incident.CreateInput`:

| OpenCSIRT field | IRFlow source | Notes |
|---|---|---|
| `Source` | hard-coded `"irflow"` | Matches the `source` enum in `incidents` table CHECK constraint |
| `Severity` | passthrough of `Severity` | Validated against `{low, medium, high, critical}`; **anything else defaults to `"medium"`** |
| `Title` | `Title` | Verbatim |
| `Description` | `Summary` | IRFlow's `summary` becomes the OpenCSIRT description |
| `Metadata.irflow_id` | `ID` | Always set |
| `Metadata.irflow_tenant` | `Tenant` | Always set |
| `Metadata.<rest>` | `Metadata` | IRFlow-side metadata is merged in |

The handler invokes:

```go
inc, err := h.svc.Create(r.Context(), incident.CreateInput{...},
                         uuid.Nil /* actor */, "irflow_webhook" /* source tag */)
```

The `uuid.Nil` actor is intentional — the action originates from a
machine principal, not a JWT subject. The audit log row records
`actor_id = NULL`, `actor_role = NULL`, `action = "irflow_webhook"`.

On success the response is:

```json
{ "incident_id": "<uuid>" }
```

with `Content-Type: application/json` and HTTP 200.

## Idempotency

IRFlow may retry a delivery (network blip, missed ack). v1.0.0
relies on:

1. The `metadata.irflow_id` field is preserved verbatim. A query
   like `SELECT id FROM incidents WHERE metadata->>'irflow_id' =
   $1` finds the existing row. The `incident.Service.Create` path
   short-circuits when this returns a hit, returning the existing
   `id` without inserting a duplicate.
2. The HMAC replay window (±5 min) bounds adversarial replays
   independently of idempotency.

Note: the v1.0.0 schema does not have a unique index on
`metadata->>'irflow_id'`. Concurrent retries within a few
milliseconds of each other can race; the loser's insert is rolled
back by application-level dedup. A `CREATE UNIQUE INDEX` on the
JSONB expression is tracked as a v1.1 hardening item.

## Failure modes & diagnostics

| Symptom | Likely cause | Diagnostic |
|---|---|---|
| `401 signature invalid` | `OPENCSIRT_IRFLOW_WEBHOOK_SECRET` mismatch between sides | compare hex of `sha256(secret)` between IRFlow and OpenCSIRT pods |
| `401` after a clock change | replay window busted | `chronyc tracking` on both ends; the ±5-min window is intentionally tight |
| `400 invalid json` | IRFlow encoder shipping a non-decodable payload | capture the raw body via tcpdump on the receiver side; do not log the raw body in OpenCSIRT |
| `400 read failed` | request body > 1 MiB (the `io.LimitReader(r.Body, 1<<20)` cap) | should not happen for legitimate IRFlow incidents; investigate as a possible DoS or misconfiguration |
| `500 create failed` | `incident.Service.Create` returned an error (DB down, schema migration pending) | OpenCSIRT API logs the wrapped error at ERROR; check Postgres connectivity |
| Severity collapses to `medium` | IRFlow shipped a non-canonical severity string | normalise on IRFlow side; the default-to-`medium` is permissive by design |

## Configuration

```bash
# OpenCSIRT side — receiver
OPENCSIRT_IRFLOW_WEBHOOK_SECRET=<64 random bytes hex>
```

The OpenCSIRT API refuses to register the route if the secret is
empty (production gate); dev mode logs a warning and registers
anyway so the OpenAPI surface is still served.

## Related

- [internal/integrations/irflow.go](../internal/integrations/irflow.go) — receiver
- [internal/integrations/webhook_hmac.go](../internal/integrations/webhook_hmac.go) — `VerifyHMAC`
- [internal/integrations/webhook_hmac_test.go](../internal/integrations/webhook_hmac_test.go) — replay-window edge cases (G2 in [pre-audit-plan](security/pre-audit-plan.md))
- [migrations/0001_init.up.sql](../migrations/0001_init.up.sql) — `incidents.source` CHECK constraint includes `'irflow'`
- [citadel-integration.md](citadel-integration.md) — `opencsirt.incident_opened` event emitted on the resulting create
- [nis2-integration.md](nis2-integration.md) — high/critical incidents from this path trigger Article 23 notification
- [../../irflow/docs/webhook-spec.md](../../irflow/docs/webhook-spec.md) — canonical signing scheme inherited from the IRFlow side
