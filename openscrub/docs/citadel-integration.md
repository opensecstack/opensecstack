# CITADEL Integration

> v1.0.0. OpenScrub emits two event types into CITADEL WORM:
> `openscrub.mitigation` (per drop / rate-limit window) and
> `openscrub.rule_change` (per rule create / withdraw). This page
> documents the wire schema.
>
> **Both event types are audit-only** — an append to CITADEL's
> immutable WORM chain, not a governance decision. A separate,
> narrower mechanism gates *manual* mitigation-rule creation on a
> CITADEL MARSHAL policy evaluation before the rule is installed; see
> [Governance: manual rule creation](#governance-manual-rule-creation)
> below. Do not confuse the two — audit-only emission cannot block
> anything, by design.
>
> Earlier revisions of this document (and of
> `internal/citadel/client.go`) described posting to
> `/api/v1/evidence` (and, before that, `/api/v1/events`). **Neither
> route ever existed on CITADEL** — every submission on those paths
> failed silently, so no `openscrub.*` event actually reached CITADEL
> WORM until this was fixed. The current client posts to CITADEL's
> real WORM ingest endpoint, `POST /api/v1/worm/emit` (see
> `citadel/internal/api/handlers/worm.go`). The schema below reflects
> the fixed, working transport.

## Why

NIS2 Article 21(2)(c) — incident handling — wants documented
evidence of mitigation action. A CSV from a vendor scrubber is not
audit-grade. CITADEL WORM (TripleHash + Ed25519 chain anchor) is.

## Transport

```
POST {CITADEL_API_URL}/api/v1/worm/emit
Content-Type: application/json
X-Source: openscrub
X-Signature: HMAC-SHA256({CITADEL_HMAC_SECRET}, timestamp + "." + body)
X-Timestamp: <unix epoch seconds>
X-Key-Id: <optional, set when HMAC secret rotation is in progress>

body: {
  "source": "openscrub",
  "event_type": "<the event's own \"type\" field, e.g. \"openscrub.rule_change\">",
  "project_id": "<OPENSCRUB_CITADEL_PROJECT_ID, default \"openscrub\">",
  "payload": <the marshalled openscrub.* event, verbatim — see schemas below>
}
```

The `openscrub.mitigation` / `openscrub.rule_change` JSON shown below
is the **`payload`** field of that envelope, not the top-level HTTP
body — `internal/citadel/client.go`'s `wrapWORMEmit` builds the
envelope around it.

CITADEL's `/worm/emit` handler does **not currently verify**
`X-Signature` / `X-Timestamp` server-side (no signature or
replay-window enforcement on this endpoint as of CITADEL v1.0.0 — see
`citadel/docs/security-model.md` "Known limitations"). OpenScrub still
computes and sends them for defense-in-depth and forward
compatibility, but do not rely on the replay window as an enforced
control today.

## Event: `openscrub.mitigation`

Emitted once per (rule, source-IP, 1-second window) tuple. The API
process aggregates the per-CPU stats map every second and produces
one event per active dropper.

```json
{
  "type": "openscrub.mitigation",
  "version": "1",
  "id": "0c2d0a3a-3a6e-4c8d-9f8d-9a7f1b2c3d4e",
  "ts": "2026-05-09T10:24:01.000Z",
  "source": "openscrub",
  "node": "edge-fra-1",
  "rule": {
    "id": "01J5VK…",
    "cidr": "198.51.100.0/24",
    "type": "blocklist",
    "source": "threatflow"
  },
  "src_ip": "198.51.100.7",
  "action": "drop",
  "packets": 4823,
  "bytes": 2891204,
  "window_seconds": 1
}
```

## Event: `openscrub.rule_change`

```json
{
  "type": "openscrub.rule_change",
  "version": "1",
  "id": "01J5VKR…",
  "ts": "2026-05-09T10:23:00.000Z",
  "source": "openscrub",
  "node": "edge-fra-1",
  "operation": "insert",
  "rule": {
    "id": "01J5VK…",
    "cidr": "203.0.113.0/24",
    "type": "blocklist",
    "pps": null,
    "ttl_seconds": 3600,
    "source": "operator"
  },
  "principal": "operator-iuni",
  "reason": "manual rule from incident IRF-2026-0142"
}
```

`operation` ∈ `{insert, withdraw, expire, ioc_pull_apply}`.
`principal` is the JWT subject for operator-driven changes;
`threatflow-puller` for IOC-driven changes.

## Delivery semantics

The two event types are **not delivered the same way** — this is a
real distinction in the current code, not a simplification:

- **`openscrub.mitigation`** goes through a durable, Postgres-backed
  outbox: each `mitigations` row carries a `(pending → sent | failed)`
  state and an `attempts` counter (`internal/citadel/mitigation_watcher.go`,
  `internal/db/mitigation_store.go`). The watcher polls
  `PendingForEmit`, submits, and only flips a row to `sent` on a
  confirmed CITADEL 2xx (`MarkSent`) via `Client.Confirmations()`. A
  row survives a process restart — the next tick re-selects it.
- **`openscrub.rule_change`** (emitted from `rules.Service.emitChange`
  on every insert/withdraw/expire/IOC-pull-apply) is **not persisted
  in an outbox**. It is fire-and-forget through the same
  `citadel.Client.Submit`, but a transient failure only lands the
  event in the client's **in-memory** retry queue
  (`Config.RetryBufferSize`, default **1024** events, not currently
  exposed as an env var — there is no `OPENSCRUB_CITADEL_OUTBOX_MAX`).
  If the process restarts or the queue fills before delivery succeeds,
  that `rule_change` event is lost — the underlying `rules` row is
  still the source of truth in Postgres, but the WORM audit trail for
  that specific mutation can have a gap. This is a known, deliberate
  v1.0.0 gap (see `internal/rules/service.go`'s `emitChange` doc
  comment), not a documentation error — if you need a hard guarantee
  that every rule mutation reaches WORM, that's open work, not
  something the current code provides.
- **Retry/backoff** (both event types, via `citadel.Client`): base
  delay 2s, doubling up to 60s, max 5 attempts
  (`Config.RetryBaseDelay` / `RetryMaxDelay` / `MaxRetries`), then the
  event is dropped and counted in
  `openscrub_citadel_emit_total{outcome="dropped"}`.
- **Replay-safe.** Each event has a UUIDv4 `id` in its envelope. Note
  CITADEL's `/worm/emit` handler does not enforce idempotency on that
  field today — a retried event that CITADEL actually received but
  whose response was lost in transit could theoretically be
  double-appended. In practice this is rare because `send` only
  retries on transport-level / 5xx failures.

## Verification path (auditor-side)

CITADEL v1.0.0 exposes exactly two WORM-related routes:
`POST /api/v1/worm/emit` (write) and `GET /api/v1/worm/verify`
(integrity check — see `citadel/internal/api/server.go`). **There is
no `GET` endpoint to query/list WORM entries by source or event type**
in v1.0.0 — `/worm/verify` returns pass/fail + entry count for a chain
segment, not the entries themselves. So today:

1. `GET /api/v1/worm/verify?from=...&to=...` confirms the chain
   segment covering the window is intact (TripleHash + Ed25519 anchor
   unbroken) — it proves nothing in that window was tampered with or
   deleted, but it does not return the `openscrub.*` payloads.
2. Reading the actual event content (to reconstruct which IP was
   blocked, when, and why) requires direct read access to CITADEL's
   WORM table — there is no self-service query API for it yet. Treat
   this as a real operational gap when planning an audit, not
   something to work around by inventing a client-side cache of
   "what we sent" (that would defeat the point of an independent WORM
   log).
3. `rule_change` events (when they arrive — see the outbox caveat
   above) reconstruct the rule-set lifecycle; `mitigation` events
   reconstruct what each rule actually did.

## Governance: manual rule creation

Everything above is **audit-only** — an append to WORM, with no power
to block anything. Separately, `POST /api/v1/rules` (rule creation)
carries a real **governance gate** through CITADEL MARSHAL, implemented
in `internal/api/handlers/handlers.go`'s `Rules.Create`. This is a
distinct mechanism from WORM emission, on a distinct CITADEL endpoint
(`POST /api/v1/marshal/evaluate`), and it applies to **only one of the
two ways a rule can be created**:

| Path | Entry point | Goes through MARSHAL? | Still WORM-audited? |
|---|---|:-:|:-:|
| **Manual** — a human operator (or any authenticated API caller) hits `POST /api/v1/rules` | `handlers.Rules.Create` | **Yes** | Yes |
| **Automated** — the ThreatFlow IOC puller inserts a threat-intel-sourced block | `internal/ioc/puller.go` `Tick()` → `rules.Service.Create` directly | **No** | Yes |
| **Withdrawal** — `DELETE /api/v1/rules/{id}`, manual or automated | `handlers.Rules.Delete` → `rules.Service.Delete` | **No** | Yes |

Why the split:

- **Manual creation is gated** because a human pulling the trigger on a
  null-route or rate-limit is a high-blast-radius, low-frequency
  action — worth a synchronous MARSHAL round-trip to catch a REFUSE /
  HARD_STOP before the block is installed.
- **The IOC puller bypasses the gate on purpose.** `puller.go` calls
  `rules.Service.Create` directly — it never goes through the HTTP
  handler, so it never touches `Rules.Create`'s CITADEL check at all.
  Automated threat-response blocking is high-frequency and
  time-sensitive; forcing every IOC-driven insert through a synchronous
  human-governance round-trip would defeat the purpose of automated
  mitigation. This is a deliberate design choice, not an oversight.
- **The gate is not decided by a client-supplied field.** `Rules.Create`
  does *not* trust `req.Source` to decide whether governance applies —
  it gates unconditionally, because the handler is reached only by a
  human/API caller in the first place (the puller never calls it). If
  the gate were instead conditioned on `source != "threatflow"`, an
  operator could bypass it by simply setting `source: "threatflow"` in
  the request body. There is a regression test proving this can't be
  spoofed.
- **Withdrawal (`DELETE`) is deliberately left ungated.** Withdrawal is
  reversible — re-inserting the same rule fully restores the block —
  and the route already requires admin/operator role via RBAC. Adding
  a second synchronous MARSHAL round-trip on top of an
  already-authorized, reversible, incident-response action would slow
  down operators trying to undo a mistaken block, for no proportional
  safety benefit.

Mechanics of the manual-creation gate:

- Builds a real `sdkcitadel.Kerkese` using the **authenticated caller's
  real identity** (`claims.Sub` from the request's JWT/sinauth token)
  and forwards their bearer token as `ActorToken` so CITADEL can verify
  it against sinauth's JWKS directly.
- `Verifier` is a **fixed placeholder**, `openscrub-system-verifier`,
  with no token — OpenScrub has no real second-approver / two-person
  concept for mitigation rules today (unlike, e.g., APIGuard's scan
  approval flow). This is a known, documented gap, not a hidden one. It
  does not trip CITADEL's Gate 3 (NDS / separation-of-duties) same-identity
  check because the placeholder string is never a valid sinauth user id
  and so can never equal the real `Actor`.
- Submits to `POST /api/v1/marshal/evaluate`. On `REFUSE` or
  `HARD_STOP`, the API returns `403 citadel_refused` with the
  decision's reasons and does **not** install the rule.
- On a CITADEL outage (`Evaluate` returns an error, as opposed to a
  decision), the handler **fails open** — it logs a warning and
  proceeds with rule insertion. This matches APIGuard's documented
  pattern: a CITADEL outage must not take down emergency mitigation
  capability. It means the gate provides no protection while CITADEL is
  down; that tradeoff is intentional, not a bug.
- `h.Citadel` is `nil` (gate fully disabled) when `OPENSCRUB_CITADEL_API_URL`
  is unset, e.g. unit tests or a standalone deployment without CITADEL.

## Schema versioning

`version: "1"` is the current schema. Schema changes ship a `version: "2"`
event type alongside `version: "1"` for at least one minor release.
The schema is also documented in the SDK contract registry — see
`../sdk/eventschemas/openscrub/`.

## Related

- [SECURITY.md](../SECURITY.md) — disclosure tiers
- [security/threat-model.md](security/threat-model.md) — STRIDE #8 (audit-log gaps)
- ECOSYSTEM.md — CITADEL row in the platform table
