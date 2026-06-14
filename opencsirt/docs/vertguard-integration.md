# VertGuard Integration — Cross-CSIRT AI Threat Sharing

> **v1.0.0 status: scope-contract.** The OpenCSIRT subscriber side
> is fully implemented in
> [internal/integrations/vertguard.go](../internal/integrations/vertguard.go).
> The VertGuard `/api/v1/ai-advisories` endpoint it polls is **not
> yet implemented** — VertGuard is currently scaffolded
> (`v0.0.0-scaffold`, see [../../ECOSYSTEM.md](../../ECOSYSTEM.md)).
> This document is the contract OpenCSIRT will consume against, so
> the VertGuard side can build the publisher to match.

## Why

The ecosystem [data-flow rule](../../ECOSYSTEM.md) declares:

> VertGuard → OpenCSIRT (cross-border AI attack coordination)

When VertGuard's AI-attack defence module flags an emerging threat
(prompt-injection campaign, deepfake disinformation, AI-generated
malware variant), national CSIRTs need to know quickly so they can
issue advisories to their constituency. VertGuard is the
detection/intel surface; OpenCSIRT is the coordination surface. The
subscriber is the wire between them.

## Subscriber model

The subscriber is `*VertGuardSubscriber`, constructed via:

```go
func NewVertGuardSubscriber(
    apiURL string,
    onAdvisory func(ctx context.Context, advisoryID string, payload map[string]any) error,
    logger zerolog.Logger,
) *VertGuardSubscriber
```

`Run(ctx)` opens a hard-coded `time.NewTicker(2 * time.Minute)`. On
every tick, `pullOnce(ctx)`:

1. `GET {apiURL}/api/v1/ai-advisories?since=1h`
2. reads up to 4 MiB via `io.LimitReader(resp.Body, 4*1024*1024)`,
3. JSON-decodes into the package-local `feed` struct
   (`{advisories: [{id, payload}]}`),
4. for each advisory, invokes the `onAdvisory` callback.

Empty `apiURL` → the loop logs `vertguard: API URL empty,
subscriber disabled` and returns. Same zero-config posture as the
ThreatFlow poller.

## Wire contract (expected from VertGuard)

```
GET {OPENCSIRT_VERTGUARD_API_URL}/api/v1/ai-advisories?since=1h
Accept: application/json
```

Expected response:

```json
{
  "advisories": [
    {
      "id": "<advisory uuid string>",
      "payload": { "title": "...", "atlas_technique": "...", "tlp": "AMBER", "...": "..." }
    }
  ]
}
```

The OpenCSIRT side is intentionally permissive on `payload` — it's
treated as an opaque `map[string]any` that gets stored in the
incident metadata. The schema is **not** locked at the subscriber
side; the publisher side defines it. v1.0.0 expects, at minimum,
that each advisory has a stable `id` (string).

## Side effect — incident creation

The wiring in `cmd/opencsirt-api` constructs the subscriber with an
`onAdvisory` callback that calls into the same `incident.Service`
the rest of the API uses. The resulting incident:

| Field | Value |
|---|---|
| `source` | `"peer_csirt"` (matches the CHECK constraint in [migrations/0001_init.up.sql](../migrations/0001_init.up.sql)) |
| `metadata.vertguard_advisory_id` | `advisoryID` from the feed item |
| `metadata.<...>` | merged from `payload` |
| `severity` | derived from `payload.severity` (defaulted to `medium` like the IRFlow path) |
| `title` | derived from `payload.title` |

Idempotency: the callback dedups on
`metadata->>'vertguard_advisory_id'` before insert, the same pattern
used for `irflow_id` (see [irflow-integration.md](irflow-integration.md)).

## "since=1h" lookback

The `since=1h` query parameter is intentionally larger than the
ticker interval (2 min) so a single missed tick doesn't drop
advisories on the floor. The cost is occasional re-delivery of
advisories already seen, which the dedup-on-`vertguard_advisory_id`
absorbs.

## Failure modes

| Symptom | Cause | Behaviour |
|---|---|---|
| empty `OPENCSIRT_VERTGUARD_API_URL` | not configured | subscriber disabled at startup |
| connection refused / DNS fail | VertGuard down or scaffolded (the v1.0.0 reality) | `pullOnce` returns error; loop logs `vertguard: pull failed` at WARN; next tick retries |
| 4xx from VertGuard | scaffold returns 501 today | same WARN + retry |
| body > 4 MiB | publisher misbehaving | LimitReader truncates → JSON decode fails → cycle aborts |
| `onAdvisory` returns an error | downstream incident-create failed | logged WARN with `advisory_id`; loop continues to next advisory |

The loop is fail-loud and forward-progress: a single bad advisory
does not kill the subscriber.

## Auth contract (proposed)

v1.0.0 sends the `GET` without an `Authorization` header — same
trust-zone posture as the rest of the integrations. When VertGuard
ships v0.1.0+, the proposed contract is:

- bearer token: `OPENCSIRT_VERTGUARD_TOKEN`, sent as `Authorization:
  Bearer …`,
- per-OpenCSIRT-instance, scoped to the `/api/v1/ai-advisories`
  feed only,
- 90-day rotation per [security/security-checklist.md § Secrets](security/security-checklist.md).

Until then, network-level isolation is the only control.

## v1.0.0 scope summary

| Side | Status |
|---|---|
| OpenCSIRT subscriber | **Implemented** — see `internal/integrations/vertguard.go` |
| VertGuard `/api/v1/ai-advisories` endpoint | **Not implemented** — VertGuard is scaffolded |
| End-to-end test against a real VertGuard | **Deferred** until VertGuard ships its publisher |
| Local fixture against a stub server | shipped as a unit test |

The integration is therefore **inert in production v1.0.0
deployments** that haven't built their own VertGuard stub. Setting
`OPENCSIRT_VERTGUARD_API_URL=""` (the default in `.env.example`)
keeps it cleanly disabled.

## Related

- [internal/integrations/vertguard.go](../internal/integrations/vertguard.go) — subscriber
- [migrations/0001_init.up.sql](../migrations/0001_init.up.sql) — `incidents.source` enum includes `peer_csirt`
- [../../ECOSYSTEM.md](../../ECOSYSTEM.md) — VertGuard scaffolded; data-flow line declaring this subscriber
- [../../vertguard/](../../vertguard/) — publisher side (scaffolded)
- [citadel-integration.md](citadel-integration.md) — incidents created from this path emit `opencsirt.incident_opened`
