# CITADEL Integration

> v1.0.0. OpenCSIRT emits **four** event types into CITADEL WORM as
> the auditor-facing evidence trail of every state transition that
> matters: `opencsirt.incident_opened`, `opencsirt.incident_closed`,
> `opencsirt.advisory_published`, and `opencsirt.escalation_sent`.
> This page documents the wire schema, the outbox state machine,
> the MARSHAL governance checks on advisory publish / incident close,
> and the operational toggles. The implementation lives in
> [internal/citadel/](../internal/citadel/) (WORM emission) and
> [internal/api/handlers/advisory.go](../internal/api/handlers/advisory.go) /
> [internal/api/handlers/incident.go](../internal/api/handlers/incident.go)
> (MARSHAL governance).
>
> **Corrected 2026-07:** earlier revisions of this integration posted
> WORM events to `POST {CITADEL_API_URL}/api/v1/events`, which is not
> a route CITADEL exposes. Every event silently failed delivery (the
> outbox retried, exhausted its budget, and marked rows `failed`) from
> the day the integration was built until this fix. The correct route
> is `POST {CITADEL_API_URL}/api/v1/worm/emit`, documented below. If
> you operate an existing OpenCSIRT deployment, check your
> `citadel_outbox` table for a backlog of `failed` rows predating this
> fix — those events never reached CITADEL and are not recoverable
> from the outbox itself.

## Why

NIS2 Article 21(2)(c) (incident handling) and Article 23 (incident
reporting) require auditable evidence. A row in OpenCSIRT's own
Postgres is not audit-grade — it can be tampered with by anyone
holding the DB credential. CITADEL WORM (TripleHash + Ed25519 chain
anchor) is the canonical evidence store the rest of the ecosystem
already uses; OpenCSIRT plugs into it on the same wire pattern as
OpenScrub, IRFlow, and CyberPath.

## Transport

```
POST {OPENCSIRT_CITADEL_API_URL}/api/v1/worm/emit
Content-Type: application/json
X-Event-Type:  opencsirt.<event_type>
X-Event-ID:    <UUIDv4 stable per emission>
X-Key-ID:      <rotation key id>
X-Timestamp:   <RFC3339 UTC>
X-Signature:   hex(HMAC-SHA256(secret, ts || "." || body))
```

`Body` is a JSON envelope, not the raw event — CITADEL's
`POST /api/v1/worm/emit` (see `citadel/internal/api/handlers/worm.go`)
expects `{source, event_type, project_id, payload}`, where `payload`
is the event JSON documented per-type below:

```json
{
  "source": "opencsirt",
  "event_type": "opencsirt.incident_opened",
  "project_id": "opencsirt",
  "payload": { "...": "the event body shown in the sections below" }
}
```

`project_id` is `OPENCSIRT_CITADEL_PROJECT_ID` (default `"opencsirt"`,
see [configuration.md](configuration.md)). The full envelope — not
just `payload` — is the exact byte stream signed by `X-Signature`.
Replay window is enforced **server-side** by CITADEL at ±5 minutes.
Implementation: `(*Client).deliver` in
[internal/citadel/client.go](../internal/citadel/client.go).

**Note on signing today:** `/api/v1/worm/emit` does not currently
verify `X-Signature`/`X-Key-ID`/`X-Timestamp` on CITADEL's side (no
HMAC check is wired up on that route as of this writing — see
`citadel/internal/api/server.go`). OpenCSIRT still computes and sends
them, both for the audit/log value on this side and so delivery keeps
working with no client change if CITADEL adds verification to
`worm/emit` later. Do not rely on these headers as an access-control
boundary until CITADEL enforces them.

## Event types

The four constants are defined in
[internal/citadel/events.go](../internal/citadel/events.go):

```go
const (
    EventIncidentOpened    = "opencsirt.incident_opened"
    EventIncidentClosed    = "opencsirt.incident_closed"
    EventAdvisoryPublished = "opencsirt.advisory_published"
    EventEscalationSent    = "opencsirt.escalation_sent"
)
```

### `opencsirt.incident_opened`

Emitted when a new row lands in `incidents`, regardless of source
(`irflow`, `manual`, `abuse_mailbox`, `peer_csirt`).

```json
{
  "type": "opencsirt.incident_opened",
  "version": "1",
  "id": "0c2d0a3a-3a6e-4c8d-9f8d-9a7f1b2c3d4e",
  "ts": "2026-05-10T10:24:01Z",
  "source": "opencsirt",
  "incident": {
    "id": "01J5VK…",
    "constituency_id": "01J5W2…",
    "source": "irflow",
    "severity": "high",
    "title": "Phishing wave against banking sector",
    "opened_at": "2026-05-10T10:24:00Z"
  },
  "principal": "irflow_webhook"
}
```

`principal` is the JWT subject for operator-driven creates,
`"irflow_webhook"` for the IRFlow path, `"vertguard_subscriber"`
for the VertGuard path, and `"abuse_mailbox"` for parsed abuse
mail.

### `opencsirt.incident_closed`

Emitted on the `open|triaged|contained → closed` transition.

```json
{
  "type": "opencsirt.incident_closed",
  "version": "1",
  "id": "1d3e1b4b-…",
  "ts": "2026-05-10T18:30:00Z",
  "source": "opencsirt",
  "incident": {
    "id": "01J5VK…",
    "severity": "high",
    "opened_at": "2026-05-10T10:24:00Z",
    "closed_at": "2026-05-10T18:30:00Z"
  },
  "principal": "operator-iuni",
  "reason": "phishing infrastructure taken down upstream"
}
```

### `opencsirt.advisory_published`

Emitted on the `draft → published` transition.

```json
{
  "type": "opencsirt.advisory_published",
  "version": "1",
  "id": "2e4f2c5c-…",
  "ts": "2026-05-10T10:55:00Z",
  "source": "opencsirt",
  "advisory": {
    "id": "01J5W4…",
    "csaf_id": "CSAF-2026-0042",
    "csaf_version": "2.0",
    "tlp": "AMBER",
    "incident_id": "01J5VK…"
  },
  "principal": "csirt_lead-zonjushe"
}
```

The publish endpoint requires `csirt_lead`+ (see
[internal/auth/auth.go](../internal/auth/auth.go) `RequireRole(RoleCSIRTLead)`),
so `principal` is always at least that role.

### `opencsirt.escalation_sent`

Emitted when an incident is escalated to a peer CSIRT — one event
per `(incident_id, peer_id)` pair from the `escalations` table.

```json
{
  "type": "opencsirt.escalation_sent",
  "version": "1",
  "id": "3f5a3d6d-…",
  "ts": "2026-05-10T11:10:00Z",
  "source": "opencsirt",
  "incident": { "id": "01J5VK…", "severity": "high" },
  "peer": {
    "id": "01J5W6…",
    "name": "CERT-EU",
    "jurisdiction": "EU"
  },
  "principal": "csirt_lead-zonjushe"
}
```

## HMAC signing

Signed material:

```
ts || "." || body
```

— exactly the pattern used everywhere else in the ecosystem. The
implementation in `(*Client).deliver`:

```go
mac := hmac.New(sha256.New, c.hmacSecrets[0])
mac.Write([]byte(ts))
mac.Write([]byte("."))
mac.Write(body)
sig := hex.EncodeToString(mac.Sum(nil))
```

`hmacSecrets[0]` is the **active signing key**. Additional entries
in the slice are accepted-during-rotation keys that the verifier
peer (CITADEL) recognises during the overlap window. The slice is
sourced from `OPENCSIRT_CITADEL_HMAC_SECRETS` (comma-separated hex,
new key first).

`X-Key-ID` carries the rotation identifier so CITADEL can pick the
right verifier from its own ring. The replay window (±5 min) is
verified by CITADEL against `X-Timestamp`.

## Outbox state machine

Every event lands in `citadel_outbox` (see [migrations/0001_init.up.sql](../migrations/0001_init.up.sql))
before any HTTP call. States and transitions:

```
   [pending] ─MarkSending─► [sending] ─MarkSent────► [sent]
                                  │
                                  └──MarkFailed──► [failed]
```

- **pending**: row written by the API request goroutine that
  performed the underlying state transition. Synchronous insert,
  same DB transaction as the incident/advisory state change.
- **sending**: claimed by the watcher; `attempts` is incremented.
- **sent**: terminal success. CITADEL acknowledged delivery.
- **failed**: terminal after `maxRetries` (5) exhaustions or a
  permanent error (4xx from CITADEL).

A crash between `MarkSending` and `MarkSent`/`MarkFailed` orphans
the row in `sending`. The watcher's `(*OutboxStore).RequeueSending`
runs at startup to put orphans back to `pending`. Pattern:

```go
if n, err := w.store.RequeueSending(ctx); err != nil { … }
```

## Watcher loop

`(*Watcher).Run` in
[internal/citadel/watcher.go](../internal/citadel/watcher.go):

1. `RequeueSending` on boot.
2. Spawn `consumeConfirmations` to handle async retry results.
3. On each tick (configurable, default 1s):
   - `(*OutboxStore).Pending(ctx, 50)` claims up to 50 pending rows.
   - For each row: `MarkSending`, then `(*Client).Submit`.

`Submit` returns one of four outcomes (`SubmitOutcome` enum in
`client.go`):

| Outcome | Meaning | Watcher reaction |
|---|---|---|
| `SubmitDelivered` | sync POST returned 2xx | `MarkSent` immediately |
| `SubmitDryRun` | dry-run mode (see below) | `MarkSent` (idempotent in dev) |
| `SubmitQueued` | transient failure, enqueued for async retry | row stays in `sending`; final state set by confirmation channel |
| `SubmitDropped` | retry buffer full or permanent error | `MarkFailed` with the error message |

## Confirmation channel

Async retries happen inside the `*Client`'s own goroutine (started
by `client.Run(ctx)`). Each retry attempt produces a
`Confirmation`:

```go
type Confirmation struct {
    EventID string
    Outcome SubmitOutcome
    Err     error
}
```

The watcher's `consumeConfirmations` reads from `client.Confirmations()`
and finalises the matching outbox row (`MarkSent` on `Delivered`,
`MarkFailed` on `Dropped`). The `inFlight` map (event_id → outbox
row id) bridges the async hop.

## DryRun mode

`OPENCSIRT_CITADEL_DRY_RUN=true` (constructor flag `dryRun`) flips
`Submit` into log-only mode:

```go
if c.dryRun {
    c.logger.Info().Str("event_type", eventType).Str("event_id", eventID).Msg("citadel: dry-run submit")
    return SubmitDryRun, nil
}
```

Use cases:

- **Local dev** — no CITADEL instance to point at; events still
  land in the outbox so the schema and JSON shape can be inspected
  with `psql`.
- **Schema testing** — bring up the API against a fresh DB,
  exercise endpoints, observe the outbox grow without polluting a
  real WORM stream.

DryRun is **off by default**. The
[security/security-checklist.md](security/security-checklist.md)
gates this explicitly: production must verify `OPENCSIRT_CITADEL_DRY_RUN=false`.

## Replay window

CITADEL ingest enforces ±5 min on `X-Timestamp`. A row in
`pending` for longer than that — for instance because the watcher
was down — produces a fresh `ts` on every retry inside
`(*Client).deliver`, so backlog drainage is not blocked by the
window. The replay window is for adversarial replays, not for
operational latency.

## Schema versioning

`version: "1"` is the current event schema. Breaking changes ship
as `version: "2"` events alongside `"1"` for at least one minor
release; consumers (auditor tooling) migrate during the overlap.

## Configuration

```bash
OPENCSIRT_CITADEL_API_URL=https://citadel.internal:8099
OPENCSIRT_CITADEL_HMAC_SECRETS=<new-hex>,<old-hex-during-rotation>
OPENCSIRT_CITADEL_KEY_ID=opencsirt-2026q2
OPENCSIRT_CITADEL_PROJECT_ID=opencsirt    # forwarded on worm/emit AND marshal/evaluate
OPENCSIRT_CITADEL_DRY_RUN=false           # production
```

Empty `OPENCSIRT_CITADEL_HMAC_SECRETS` while `OPENCSIRT_CITADEL_API_URL`
is set is a startup-blocking misconfiguration. Empty
`OPENCSIRT_CITADEL_API_URL` falls back to `SubmitDryRun` so dev
deployments do not accumulate failed rows.

## MARSHAL governance (advisory publish / incident close)

The four events above are **audit-only** — WORM records a fact after
it already happened, and nothing blocks on the outcome. Two actions
are additionally **governed**: they are evaluated against CITADEL
MARSHAL (`POST {OPENCSIRT_CITADEL_API_URL}/api/v1/marshal/evaluate`)
*before* they are allowed to happen, and a `REFUSE` or `HARD_STOP`
verdict blocks the request with HTTP 403 and the verdict's reasons.

| Action | Handler | Kerkese `Action.Type` |
|---|---|---|
| Advisory publication | `(*Advisory).Publish` in [internal/api/handlers/advisory.go](../internal/api/handlers/advisory.go) | `ADVISORY_PUBLISH` |
| Incident closure | `(*Incident).Close` in [internal/api/handlers/incident.go](../internal/api/handlers/incident.go) | `INCIDENT_CLOSE` |

Both handlers build a real `sdkcitadel.Kerkese` (SDK type from
[sdk/go/citadel](../../sdk/go/citadel)) with:

- **Actor** = the authenticated caller's real identity/role, the same
  `actor`/`role` `actorAndRole()` derives from the request's
  JWT/sinauth claims for the audit log — not a placeholder.
- **ActorToken** = the caller's own bearer token (stripped of the
  `Bearer ` prefix), forwarded so CITADEL can verify it directly
  against sinauth.
- **ProjectID** = `OPENCSIRT_CITADEL_PROJECT_ID`.
- **DryRun** = `OPENCSIRT_CITADEL_DRY_RUN`.

The check is skipped entirely (`h.Citadel == nil`) when
`OPENCSIRT_CITADEL_API_URL` is unset, matching the outbox/watcher's
existing posture for unconfigured deployments. If `Evaluate` itself
errors (network, CITADEL down), the handler logs a warning and
**proceeds with the action** — a MARSHAL outage does not itself block
incident/advisory workflow; only an explicit `REFUSE`/`HARD_STOP`
verdict does.

### Known gap: no real second approver (Verifier is a placeholder)

MARSHAL's Gate 3 (NDS, Separation of Duties) expects a genuine second
identity as `Verifier`, distinct from `Actor`. OpenCSIRT has no
draft→review→publish or close→countersign workflow today — confirmed
there is no `reviewed_by`/`approved_by` concept anywhere in
`db.Advisory`, `db.Incident`, `advisory.Service`, or
`incident.Service`. A single `csirt_lead` both authors/requests and
publishes an advisory; a single operator/admin closes an incident.

Both handlers therefore set `Verifier` to a **fixed system
placeholder** (`"opencsirt-system-verifier"`, role
`group_sig_verifier`, no token) — distinct from `Actor` so it can
never trip Gate 3's `NDS_SAME_IDENTITY` hard-stop, but not a genuine
second person either. With `VerifierToken` left empty, CITADEL's soft
mode (`citadel.enforce_identity` / `citadel.enforce_signatures` both
`false`) treats the missing verifier signature as a warning, not a
block, today. Building real two-person approval for advisory
publication and incident closure is a separate, larger product change
(new draft→review states) and is out of scope of this fix — it is
tracked, not hidden.

### Known gap: CITADEL's RBAC map does not fully cover OpenCSIRT yet

**This is the limitation most likely to surprise an operator, so it
is stated plainly:** CITADEL's AuthZ gate (Gate 2) evaluates
`Action.Type` and `Actor.Role` against a role→action RBAC map that is
maintained on the CITADEL side. As of this writing that map:

- does **not** recognize `ADVISORY_PUBLISH` as an action type at all, and
- for `INCIDENT_CLOSE`, only permits the `admin` role — `csirt_lead`,
  `operator`, and every other OpenCSIRT role that can legitimately
  close an incident in practice are **not** in the map.

The practical consequence: most real `Evaluate()` calls from
`Publish`/`Close` will legitimately **REFUSE at CITADEL's AuthZ gate
today**, for any actor role that CITADEL doesn't yet recognize for
that action — not because OpenCSIRT's governance code is broken, but
because CITADEL's own RBAC map hasn't been extended to know about
OpenCSIRT's action types and roles yet. That is a CITADEL-side change
(citadel's RBAC map / policy configuration), out of scope for
OpenCSIRT.

In short: the governance wiring in OpenCSIRT is real, calls the real
MARSHAL endpoint with the real caller identity, and will genuinely
block on an actual `REFUSE`/`HARD_STOP` — but **end-to-end enforcement
for non-admin publishers/closers is not fully live yet**, pending that
CITADEL-side RBAC extension. Do not read "governance code shipped" as
"publish/close are fully gated in production today."

## Related

- [internal/citadel/client.go](../internal/citadel/client.go) — HTTP client + retry buffer (WORM emission)
- [internal/citadel/watcher.go](../internal/citadel/watcher.go) — outbox watcher
- [internal/citadel/events.go](../internal/citadel/events.go) — event-type constants
- [internal/api/handlers/advisory.go](../internal/api/handlers/advisory.go) — `Publish` MARSHAL governance check
- [internal/api/handlers/incident.go](../internal/api/handlers/incident.go) — `Close` MARSHAL governance check
- [go.mod](../go.mod) — `sdk/go/citadel` dependency (Kerkese types, `Evaluate` client)
- [migrations/0001_init.up.sql](../migrations/0001_init.up.sql) — `citadel_outbox` schema
- [security/threat-model.md](security/threat-model.md) — STRIDE rows for CITADEL credential exposure & replay
- [security/compliance-map.md](security/compliance-map.md) — Article 21(2)(c)/(h) row referencing this page
- [../../citadel/docs/](../../citadel/docs/) — CITADEL receiver-side spec
