# CyberPath ↔ CITADEL Integration

> Interface contract for the `cyberpath.completion` evidence event
> emitted to CITADEL's WORM ledger. Lands with v1.0.0.
>
> The shape below mirrors VertGuard's CITADEL evidence shape (see
> `vertguard/internal/citadel/client.go`) — a fields-on-an-Evidence
> struct, async-buffered, HMAC-signed. Field names that map 1:1 to
> the existing VertGuard contract are marked. Fields specific to
> CyberPath are noted.
>
> **Verify before v1.0.0 implementation:** the CITADEL Kerkese
> schema team should confirm the `cyberpath.completion` event
> registration and the schema-extension fields below.

## Event schema (JSON)

```json
{
  "event_type":      "cyberpath.completion",
  "subject":         "user:<user_id>",
  "verdict":         "completed",
  "score":           0.87,
  "categories":      ["nis2.art21.g", "nis2.art21.b"],
  "patterns":        ["track:phishing-recognition", "lesson:phish-quiz-3"],
  "tenant":          "<tenant id, optional>",
  "timestamp":       "2027-05-14T10:21:33Z",
  "correlation_id":  "<uuid v4>",
  "project_id":      "<configured project id>",

  "cyberpath": {
    "completion_id":        "<uuid v4>",
    "user_id":              "<user_id>",
    "track_id":             "phishing-recognition",
    "track_version":        "1.4.0",
    "content_version_id":   "<content_version uuid>",
    "completion_timestamp": "2027-05-14T10:21:33Z",
    "evidence_hash":        "blake3:<64 hex chars>",
    "signed_by":            "ed25519:<key id>",
    "certification_level":  "track-cert",
    "nis2_measures":        ["art21.g", "art21.b"]
  }
}
```

### Field map to the VertGuard `Evidence` struct

| Field | Source | Notes |
|---|---|---|
| `event_type` | constant | `cyberpath.completion` (new event type, registered in CITADEL Kerkese spec) |
| `subject` | derived | `user:<user_id>` |
| `verdict` | constant | `completed`. Future: `corrected`, `revoked` (via separate `cyberpath.correction` events) |
| `score` | quiz score | 0.0 – 1.0; quiz-derived where applicable, `1.0` for non-quiz lessons |
| `categories` | NIS2 measures | each measure namespaced as `nis2.art21.<x>` |
| `patterns` | track + lesson refs | machine-readable references; useful for audit queries |
| `tenant` | config | populated for multi-tenant deployments |
| `timestamp` | server clock | RFC 3339 UTC |
| `correlation_id` | server-generated | UUID v4 |
| `project_id` | config | `CYBERPATH_CITADEL_PROJECT_ID` |
| `cyberpath.*` | new sub-object | CyberPath-specific extension fields |

### CyberPath-specific extension fields

| Field | Type | Purpose |
|---|---|---|
| `completion_id` | UUID v4 | server-generated, primary key into `completions` table |
| `user_id` | string | the learner's stable id |
| `track_id` | string | track slug (e.g. `phishing-recognition`) |
| `track_version` | semver | track-content semver at time of completion |
| `content_version_id` | UUID | references the immutable lesson revision (Module 8) |
| `completion_timestamp` | RFC 3339 | source-of-truth completion time |
| `evidence_hash` | string | `blake3:<hex>` of the canonical evidence body (reproducible) |
| `signed_by` | string | `ed25519:<key id>` of the signing key in use |
| `certification_level` | enum | `lesson`, `module`, `track-cert`, `path-cert` |
| `nis2_measures` | string array | NIS2 Article 21 measures the completion contributes evidence for |

## Submission flow

```
   Learner completes lesson / quiz / lab
                   │
                   ▼
       internal/path/ writes `completions` row
       (with content_version_id, evidence_hash, score)
                   │
                   ▼
       internal/citadel/EmitAsync(Evidence{...})
                   │
                   ▼
       Bounded async queue (default 1000)
                   │
                   ▼
       Background drain goroutine
       — HMAC-SHA256 sign body
       — POST CITADEL_API_URL + retry with backoff
       — circuit breaker: 5 failures → 30s cooldown
                   │
                   ▼
       CITADEL appends to WORM ledger
       (returns 2xx + ledger-assigned id)
                   │
                   ▼
       internal/citadel/ updates `completions.citadel_ledger_id`
       (best-effort; missing ledger id does NOT fail the
        learner-visible completion)
```

Key semantics:

- **Async + fire-and-forget.** The learner's `POST
  /api/v1/lessons/{id}/complete` does not block on CITADEL.
- **At-least-once delivery.** Replay protection is on the CITADEL
  side (Kerkese spec dedupes by `correlation_id`).
- **Hard shutdown drains for 10s.** Unflushed events are written to
  a local on-disk WAL for next-startup retry (matches the VertGuard
  pattern).

## HMAC signing

Body is signed with `CYBERPATH_CITADEL_KEY_SECRET` using HMAC-SHA256
following the same `timestamp + "." + raw_body` convention used by
VertGuard's ThreatFlow webhook (see
`vertguard/docs/threatflow-integration.md § Authentication`):

```
signed_payload = timestamp + "." + raw_body
signature      = hex(HMAC-SHA256(shared_secret, signed_payload))
```

Headers on every request:

| Header | Value |
|---|---|
| `X-Citadel-Signature` | `sha256=<hex>` |
| `X-Citadel-Timestamp` | `<unix-seconds>` |

CITADEL verifies with the same secret and rejects requests whose
timestamp falls outside a ±5-minute skew window (replay protection;
the raw body is included in the HMAC input so any body mutation
also invalidates the signature). Same scheme as VertGuard.

## Verification flow (auditor reads CITADEL)

```
   Auditor                               CITADEL
   │                                     │
   │  GET /events?event_type=            │
   │      cyberpath.completion&          │
   │      subject=user:<id>              │
   │                                     │
   ├────────────────────────────────────►│
   │                                     │
   │       JSON list of events           │
   │◄────────────────────────────────────┤
   │                                     │
   │  For each event:                    │
   │   • verify ledger signature         │
   │   • resolve content_version_id      │
   │     (against CyberPath              │
   │      /api/v1/content/versions/<id>  │
   │      — public, read-only)           │
   │   • re-hash evidence body           │
   │   • compare to evidence_hash        │
   │                                     │
   │  Result: cryptographically          │
   │  verifiable training record         │
```

Important: the `content_version_id` resolves via a CyberPath public
read endpoint that returns the exact lesson markdown the learner
saw. The auditor can independently re-render the lesson and verify
the content was as claimed.

## Error handling

| Condition | CyberPath behaviour |
|---|---|
| CITADEL returns 5xx | Retry with backoff up to 5 times, then breaker opens |
| CITADEL returns 4xx (schema error) | Log + drop. Schema mismatches surface in the next CyberPath release. |
| CITADEL unreachable for > breaker cooldown | Buffer events; on graceful shutdown, write WAL |
| Local DB write succeeds, CITADEL emit fails permanently | Reconciliation job (`make reconcile-citadel`) re-emits events whose `citadel_ledger_id` is null |

## Open questions

- Final naming: `cyberpath.completion` vs `cyberpath.training.completed`?
  Working assumption: the shorter form, matching the VertGuard
  precedent (`vertguard.detection`).
- Should `cyberpath.correction` events reference the original
  `completion_id`? Working assumption: yes, via a `corrects:
  <completion_id>` field in the `cyberpath` sub-object.
- Does CITADEL's Kerkese schema allow nested sub-objects, or should
  CyberPath-specific fields be flattened? **Verify with CITADEL
  team before v1.0.0.**

## Related

- [architecture.md](./architecture.md)
- [nis2-integration.md](./nis2-integration.md)
- VertGuard reference: `vertguard/internal/citadel/client.go`
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
