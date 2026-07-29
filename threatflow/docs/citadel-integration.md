# CITADEL Integration

ThreatFlow integrates with CITADEL for governance (MARSHAL decision gating) and auditability (WORM chain logging). All mutation operations are WORM-logged, and high-impact operations are MARSHAL-gated.

---

## Authentication

ThreatFlow authenticates to CITADEL as a **connector** using HMAC-SHA256:

| Header | Value |
|--------|-------|
| `X-CITADEL-KEY` | Connector key ID (from `THREATFLOW_CITADEL_KEY_ID`) |
| `X-CITADEL-TS` | Unix timestamp |
| `X-CITADEL-SIG` | `hmac-sha256=<hex(HMAC(secret, key_id:ts:sha256(body)))>` |

The shared secret is configured via `THREATFLOW_CITADEL_KEY_SECRET`.

---

## WORM Events

ThreatFlow emits the following events to the CITADEL WORM chain:

| Event Type | Trigger | Payload |
|-----------|---------|---------|
| `threatflow.ioc.ingested` | New IOC persisted | IOC ID, type, value, source, confidence |
| `threatflow.ioc.updated` | IOC metadata changed | IOC ID, changed fields |
| `threatflow.ioc.revoked` | IOC marked as revoked/expired | IOC ID, reason |
| `threatflow.feed.polled` | Successful feed poll | Feed name, new IOC count, duration |
| `threatflow.feed.error` | Feed poll failure | Feed name, error message, attempt count |
| `threatflow.bundle.imported` | STIX bundle ingested | Bundle ID, object count, source |
| `threatflow.bundle.exported` | STIX bundle exported | Bundle ID, object count, consumer |
| `threatflow.sighting.created` | IOC observed in ecosystem | IOC ID, platform, resource ID |
| `threatflow.correlation.match` | Cross-feed correlation hit | IOC IDs, confidence, relationship type |

### Event Format

```json
{
  "source": "threatflow",
  "event_type": "threatflow.ioc.ingested",
  "project_id": "threatflow",
  "payload": {
    "ioc_id": "ioc-550e8400...",
    "type": "ipv4-addr",
    "value": "198.51.100.42",
    "source": "alienvault-otx",
    "confidence": 85,
    "stix_id": "indicator--abc123",
    "ttp": ["T1071.001"]
  }
}
```

---

## MARSHAL Gating

Every mutation goes through `citadel.Client.Evaluate` before it is persisted. The
current gated operations, and the CITADEL `action.type` each one submits, are:

| Operation | MARSHAL Action Type | Handler |
|-----------|-------------------|---------|
| IOC ingest (`POST /api/v1/iocs`) | `IOC_INGEST` | `internal/api/handlers/ioc.go` |
| STIX bundle import (`POST /api/v1/stix/bundles`) | `STIX_BUNDLE_IMPORT` | `internal/api/handlers/stix.go` |
| Feed create (`POST /api/v1/feeds`) | `FEED_CREATE` | `internal/api/handlers/feed.go` |
| Feed enable/disable (`PATCH /api/v1/feeds/{id}`) | `FEED_TOGGLE` | `internal/api/handlers/feed.go` |
| Feed delete (`DELETE /api/v1/feeds/{id}`) | `FEED_DELETE` | `internal/api/handlers/feed.go` |

`IOC_REVOKE` is reserved in `internal/citadel/types.go` for a future IOC revoke
endpoint but is not currently wired to any handler.

If MARSHAL returns **REFUSE**, the mutation is rejected (HTTP 403) and not
persisted. If **HARD_STOP**, the same 403 is returned and the reasons array
carries the hard-stop cause — ThreatFlow does not currently take a further
automated action (e.g. pausing a feed) on `HARD_STOP`, beyond refusing the
single request.

### Actor identity

Every Kerkese carries the *real* identity of the caller who triggered the
mutation, not a placeholder:

- `actor.user_id` — the sinauth UUID (`Identity.Subject`) of the authenticated
  caller, taken from the request's verified JWT. When the caller authenticated
  through ThreatFlow's own API-key or bootstrap HS256 fallback (no sinauth
  token involved), this is the fallback subject instead (`apikey:<uuid>` or
  `bootstrap:<name>`) — still a real, traceable identity, just not a sinauth
  UUID.
- `actor_token` — the raw bearer token forwarded from the incoming request's
  `Authorization` header, but **only** when the caller authenticated with a
  genuine sinauth RS256 token (`Identity.Source == "sinauth"`). API-key and
  bootstrap callers have no real sinauth token to forward, so `actor_token` is
  left empty for them — this is expected, not a gap.
- When a request reaches the handler with no identity at all (dev mode with
  auth disabled), the actor falls back to `user_id: "unauthenticated"`,
  `role: "operator"` so the Kerkese still carries a non-empty Actor.

This wiring lives in `actorFromRequest()` in
`internal/api/handlers/ioc.go`, shared by all three governed handler files.

> **Fixed in the identity rework (2026-07):** prior to this change, `Evaluate`
> never received the caller's identity at all — `Actor.UserID` was left at its
> Go zero value, and `Verifier`/`SoD` were entirely unset. Every Kerkese
> ThreatFlow submitted carried an empty operator identity and a zero-value
> verifier identity, which is a live risk of an accidental
> `NDS_SAME_IDENTITY` collision at Gate 3 (both roles resolving to the same
> "identity"). See the [Changelog](../CHANGELOG.md) for details.

### Verifier — single-party governance today

ThreatFlow does not have a second-approver ("who verifies the operator's
action") concept for any of its governed actions today. There is no separate
approve/review step before an IOC ingest, feed change, or STIX import takes
effect — the same request that mutates state is the request MARSHAL
evaluates. This is a **deliberate, documented scope decision**, not a hidden
gap: building real two-person approval for automated, high-frequency
threat-intel ingestion was judged out of scope for v1.0.

To keep this honest at the protocol level rather than silently reusing the
actor's own identity as the verifier (which would misrepresent single-party
review as SoD-verified review), the client submits a fixed, clearly-named
placeholder verifier for every Kerkese:

```go
const verifierPlaceholder = "threatflow-system-verifier"
```

- `verifier.user_id` / `sod.verifier_user_id` — always
  `"threatflow-system-verifier"`, `role: "group_sig_verifier"`.
- `sod.operator_user_id` — the real actor's `user_id` (see above).
- `verifier_token` — always empty; there is no real second person to forward
  a token for.

Because the placeholder never equals a real user's identity, it never
collides with the Actor and never trips Gate 3's `NDS_SAME_IDENTITY`
hard-stop. Because `citadel.enforce_signatures` stays at its ADR-004 default
(`false`), the absence of a real verifier and of `sig_operator`/`sig_verifier`
signatures surfaces as a Gate 1 / Gate 3 **WARN** reason in the decision, not
a block — governance evaluation currently runs single-party for ThreatFlow.
Two-person approval for threat-intel actions is a tracked future enhancement,
not something this integration claims to provide today.

### Kerkese Example

```json
{
  "kerkese_version": "1.0",
  "ts_utc": "2026-07-26T12:00:00Z",
  "project_id": "threatflow",
  "execution_id": "8f14e...-uuid",
  "action": {
    "type": "IOC_INGEST",
    "description": "direct IOC ingest: ipv4-addr=198.51.100.42"
  },
  "actor": {
    "user_id": "b3f2c9de-....-sinauth-uuid",
    "role": "operator"
  },
  "verifier": {
    "user_id": "threatflow-system-verifier",
    "role": "group_sig_verifier"
  },
  "sod": {
    "operator_user_id": "b3f2c9de-....-sinauth-uuid",
    "verifier_user_id": "threatflow-system-verifier"
  },
  "actor_token": "eyJhbGciOi...",
  "dry_run": false
}
```

`sig_operator`, `sig_verifier`, and `verifier_token` are always omitted —
ThreatFlow does not sign Kerkese payloads (no per-user private key custody in
this flow) and has no real verifier to hold a token for.

---

## Disabled Mode

When `THREATFLOW_CITADEL_API_URL` is empty, all CITADEL calls are no-ops:
- WORM events are silently discarded
- MARSHAL evaluations return implicit EXECUTE
- IOC operations proceed without governance checks

This mode is intended for local development and testing only.

---

## See Also

- [IOC Feeds](ioc-feeds.md) — MARSHAL gating for feed ingestion
- [Architecture](architecture.md) — governance layer in the system design
- [API Reference](api-reference.md) — 403 responses when MARSHAL refuses
- [Configuration](configuration.md) — CITADEL environment variables
- [Security Model](security-model.md) — L4 application security controls via MARSHAL
- [Troubleshooting](troubleshooting.md) — debugging CITADEL connectivity issues
