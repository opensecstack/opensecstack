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
> Shipped with v1.0.0: the `cyberpath.completion` event registration
> and the schema-extension fields below are implemented and live (see
> `internal/citadel/events.go`, `internal/citadel/client.go`,
> `internal/citadel/dispatcher.go`, `internal/citadel/worker.go`).

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

## Certification issuance & revocation events

In addition to `cyberpath.completion` (above), the certifications
handler (`internal/api/handlers/certifications.go`) emits two more
event types through the same outbox path, defined in
`internal/citadel/events.go`:

| Event type | Emitted by | Trigger |
|---|---|---|
| `cyberpath.certification.issued` | `Issue()` / `TryAutoIssue()` | A certification is issued (manual or auto-triggered by track completion) |
| `cyberpath.certification.revoked` | `Revoke()` | An admin revokes a certification |

Both are best-effort/fire-and-forget through the outbox worker, same
as `cyberpath.completion` — a failed enqueue is logged and does not
fail the API request.

`cyberpath.certification.issued` payload (`cyberpath` sub-object):

```json
{
  "certificate_id": "<uuid>",
  "user_id":        "<uuid>",
  "track_id":       "<uuid>",
  "certification_level": "track-cert",
  "issued_at":      "2027-05-14T10:21:33Z",
  "signed_by":      "ed25519:<key id>"
}
```

`cyberpath.certification.revoked` payload:

```json
{
  "certificate_id": "<uuid>",
  "revoked_by":      "<admin user_id>",
  "revoked_at":      "2027-05-14T10:21:33Z"
}
```

### Revocation also runs a MARSHAL governance check — issuance does not

This is a deliberate asymmetry, not an inconsistency to fix:

- **Issuance** is automatic and score/eligibility-gated (all lessons in
  the track complete). It only needs a WORM audit-emit, which it has
  had since v1.0.0 — `EnqueueCertificationIssued` above.
- **Revocation** is a discretionary admin action that invalidates a
  previously issued credential. Until this fix landed, it had **no**
  CITADEL integration at all — no WORM event, no governance check.
  `Revoke()` now does both:
  1. Builds a Kerkese (`ExecutionID` = cert ID, `Action.Type =
     "CONFIG_CHANGE"`, `Actor` = the real authenticated admin's
     `sub`/role, `ActorToken` = their forwarded bearer token) and
     calls `POST /api/v1/marshal/evaluate` via the `MarshalEvaluator`
     interface (satisfied by `sdk/go/citadel.Client`).
  2. On `REFUSE` / `HARD_STOP`, the revocation is blocked — the
     handler returns `403 governance_refused` with the decision's
     reasons.
  3. On any other outcome, or if MARSHAL is unreachable (`err != nil`
     from `Evaluate`), the revocation proceeds — **the governance
     check fails open**. This matches the fail-open pattern used
     elsewhere in the ecosystem (e.g. APIGuard's scan-initiation
     check) and is a deliberate availability-over-strictness choice:
     a CITADEL outage does not block an admin from revoking a
     credential, it just means that call has no governance record —
     the WORM audit-emit (step above) still happens unconditionally.
  4. `Verifier` on the Kerkese is a fixed placeholder identity
     (`cyberpath-system-verifier`, `VerifierToken` empty) — CyberPath
     has no dual-control/second-approver concept to bind a real
     Verifier to. Under CITADEL's soft-mode identity/signature
     enforcement this is a WARN, not a block. Anyone treating a
     revocation's MARSHAL decision as dual-control evidence should
     know the Verifier side is not a real second approver.
  5. `Action.Type` is `CONFIG_CHANGE` because CITADEL's MARSHAL RBAC
     map has no CyberPath-specific action types yet; a dedicated
     `CERTIFICATION_REVOKE` type is a follow-up on the CITADEL side.

## Related

- [architecture.md](./architecture.md)
- [nis2-integration.md](./nis2-integration.md)
- VertGuard reference: `vertguard/internal/citadel/client.go`
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
