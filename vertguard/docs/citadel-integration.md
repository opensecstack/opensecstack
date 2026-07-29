# CITADEL Integration

VertGuard's CITADEL integration today is a single, narrow thing: an
async **evidence emitter** that best-effort POSTs a flat, HMAC-signed
JSON record to a CITADEL WORM-emit endpoint after certain detections
complete. There is no MARSHAL gate evaluation, no Kerkese request
construction, and no auto-response action of any kind — VertGuard
never asks CITADEL for permission to do anything, because VertGuard
does not perform actions that would need governing. This document
describes what actually exists in `internal/citadel/client.go` and
where it is called from.

For VertGuard's architecture context, see [architecture.md](architecture.md).

## What VertGuard actually does

### Evidence emission (fire-and-forget, best-effort)

`internal/citadel/client.go` (`Client`) exposes `EmitAsync`, which
enqueues an `Evidence` record onto an in-memory buffered channel
(`Config.AsyncBuffer`, default 1000) and returns immediately —
`true` if accepted, `false` if the buffer was full (caller decides
whether that matters; every call site today just ignores the
return value or logs it). A background goroutine (`drain`) reads the
queue and calls `EmitWORM`, which:

- Marshals the `Evidence` struct to JSON.
- Signs the body with HMAC-SHA256 using the configured secret
  (`X-VertGuard-Signature: sha256=<hex>` header; `X-Key-Id` header if
  a key ID is configured).
- POSTs to `{BaseURL}/api/v1/worm/emit`.
- Retries up to 3 times with fixed backoff (100ms/500ms/2s) on
  network errors and 5xx responses; 4xx responses are treated as
  terminal (not retried).
- Goes through a circuit breaker (`internal/breaker`) that opens
  after 5 consecutive failures and cools down for 30s.

There is no synchronous emission anywhere in the codebase, no
outbound MARSHAL call, no Kerkese envelope, and no code path that
blocks a detection response on CITADEL's answer. If CITADEL is slow,
unreachable, or gone entirely, VertGuard's own scan/detection
responses are unaffected — the emit either lands in the async
queue or (if the queue is full) is dropped with a
`vertguard_worm_emit_total{result="dropped_buffer_full"}` metric
increment and a warn log. There is no local disk-backed retry queue;
"queue" means the in-memory channel only, and its contents are lost
on process restart or on `Close()`'s 10s drain timeout being exceeded.

### The `Evidence` payload

The actual wire shape (`internal/citadel/client.go`):

```go
type Evidence struct {
    EventType     string    `json:"event_type"`
    Subject       string    `json:"subject"`
    Verdict       string    `json:"verdict"`
    Score         float64   `json:"score"`
    Categories    []string  `json:"categories"`
    Patterns      []string  `json:"patterns"`
    Tenant        string    `json:"tenant,omitempty"`
    Timestamp     time.Time `json:"timestamp"`
    CorrelationID string    `json:"correlation_id"`
    ProjectID     string    `json:"project_id,omitempty"`
}
```

This is a flat record, not a structured "evidence envelope" with
`input_hash`, `matched_patterns[]`, `provenance_chain[]`, or similar
nested detail — those richer schemas do not exist in code. `Subject`
typically carries a hash (e.g. `result.ClaimHash`, `result.InputHash`,
a file hash) or a fixed string like `"threatfeed"`; `Patterns` is a
flat `[]string` of pattern IDs, not objects with confidence/byte-range
fields.

### Call sites (what actually triggers an emit)

| Call site | `event_type` sent | Trigger |
|---|---|---|
| `internal/api/handlers/identity.go` | `identity_verify` | Identity/synthetic-identity check |
| `internal/api/handlers/media.go` | `vertguard.detection.media_authenticity` | Media verification |
| `internal/api/handlers/phishing.go` | `phishing_scan` | Phishing scan |
| `internal/api/handlers/prompt.go` | `prompt_scan` | Prompt-injection scan |
| `internal/api/handlers/threatfeed.go` | (caller-supplied) | IOC/threatfeed admin actions |
| `internal/api/handlers/webhook_threatflow.go` | `vertguard.detection.threatfeed_ingest` | Accepted ThreatFlow webhook batch |
| `internal/ioc/puller.go` | `vertguard.threatfeed.sync_complete` | IOC feed sync completion |

Note the `event_type` values in code do **not** consistently follow a
`vertguard.detection.*` / `vertguard.threatfeed.*` namespace — some do
(`vertguard.detection.media_authenticity`,
`vertguard.detection.threatfeed_ingest`,
`vertguard.threatfeed.sync_complete`), others are bare
(`identity_verify`, `phishing_scan`, `prompt_scan`). Any consumer or
dashboard keying off event type must handle both forms as they exist
today; this is not a designed taxonomy, and it may change without
being a breaking "contract."

Emission is conditional on `h.Citadel != nil` — if no CITADEL client
was constructed at startup (see below), these call sites silently skip
emission (in some handlers with a debug log, e.g.
`"citadel emit skipped — client not configured"`).

### `internal/webhook/fanout.go`

When webhook subscribers are configured, `main.go` wraps the raw
CITADEL client in `webhookv2.NewFanoutEmitter`, which implements the
same `EmitAsync` interface and additionally re-publishes each emitted
event to VertGuard's own webhook dispatcher. This is a VertGuard-side
fanout convenience, not part of the CITADEL protocol.

## What does NOT exist

The following are not implemented anywhere in VertGuard's codebase —
there is no `internal/citadel/connector.go` (the actual file is
`internal/citadel/client.go`), and none of this exists in any form,
mock or otherwise:

- **No MARSHAL gate evaluation.** VertGuard never calls
  `/api/v1/marshal/evaluate` or any MARSHAL endpoint. There is no
  Kerkese request construction, no `actor`/`action.type`/
  `action.incident_id`/`sod` fields, and no `EXECUTE`/`REFUSE`/
  `HARD_STOP` decision handling in the codebase.
- **No auto-response actions.** VertGuard does not quarantine emails,
  block sessions, or take any governed action that would require
  MARSHAL authorization in the first place — it is a detection/scan
  service that returns a classification to the caller.
- **No Separation of Duties (SoD/NDS) integration.**
- **No `DRY_RUN` short-circuit for MARSHAL** (there is no MARSHAL call
  to short-circuit). `citadel.dry_run` / `DryRun` in `Config` does
  exist and does what it says for WORM emission only: `EmitWORM`
  logs at debug level and returns immediately without making an HTTP
  call.
- **No "standalone mode" fallback message or loud WARN gating on empty
  secret** — an empty HMAC secret is silently used as the HMAC key
  (`sign(body, "")`) rather than switching VertGuard into a documented
  standalone/no-WORM mode. This is worth treating as a real gap if
  synchronous, guaranteed WORM logging is ever required — see below.
- **No `internal/citadel/mock.go`** and **no
  `tests/integration/citadel_test.go`**. Unit coverage for the client
  lives in `internal/citadel/client_test.go`, which exercises the real
  `Client` against an `httptest.Server`, not a separate mock package.
- **No post-quantum-specific code path.** The client uses vanilla
  HMAC-SHA256; there is nothing in VertGuard that references CITADEL's
  Ed25519 anchoring or any PQC migration plan.

## Configuration

The real config knobs (`internal/config/config.go` `CitadelConfig`,
env-mapped via the `VERTGUARD_CITADEL_*` prefix; see
`internal/config/defaults.go` for defaults):

```bash
VERTGUARD_CITADEL_ENABLED=true          # gates whether a client is constructed at all
VERTGUARD_CITADEL_API_URL=...           # legacy/alternate base URL field
VERTGUARD_CITADEL_BASE_URL=http://citadel-api:8099
VERTGUARD_CITADEL_KEY_ID=vertguard-prod           # legacy single key id
VERTGUARD_CITADEL_KEY_SECRET=...                  # legacy single HMAC secret
VERTGUARD_CITADEL_HMAC_SECRET=...                 # HMACSecret (fallback if HMACSecrets unset)
VERTGUARD_CITADEL_HMAC_SECRETS=...,...,...        # 3-slot rotation [primary, next, previous]
VERTGUARD_CITADEL_KEY_IDS=...,...,...             # key ids aligned to HMAC_SECRETS
VERTGUARD_CITADEL_PROJECT_ID=prod
VERTGUARD_CITADEL_DRY_RUN=false         # true => WORM emit is a no-op (debug log only)
VERTGUARD_CITADEL_QUEUE_MAX=10000
VERTGUARD_CITADEL_ASYNC_BUFFER=1000     # in-memory EmitAsync channel size
```

If both the scalar (`HMAC_SECRET`/`KEY_SECRET`) and the multi-slot
(`HMAC_SECRETS`) knobs are set, the multi-slot list wins and
`main.go` logs a warning telling the operator to clear the scalar.

## Failure handling (as implemented)

| CITADEL state | VertGuard behaviour |
|---|---|
| Healthy | `EmitAsync` enqueues; drain goroutine POSTs, retries transient failures, updates metrics |
| Slow | Retries with fixed backoff (100ms/500ms/2s); `vertguard_citadel_latency_seconds` records it |
| Unreachable | Retries exhaust within the same drain call; event is dropped after `EmitWORM` returns an error (logged as `"WORM emit failed"`) — there is no persistent/disk-backed re-queue |
| Returns 4xx | Not retried; treated as terminal failure for that event |
| Returns 5xx | Retried up to 3 attempts, then dropped with a warn log |
| Circuit open (5 consecutive failures) | Further attempts short-circuit for 30s (`breaker.ErrOpen`), each counted as `vertguard_citadel_calls_total{result="breaker_open"}` |
| `EmitAsync` buffer full | Event dropped immediately at enqueue time; `vertguard_worm_emit_total{result="dropped_buffer_full"}` |

In every case, VertGuard's own API response to the caller is
unaffected — detection results are always returned regardless of
whether the CITADEL emit succeeds. This means today's integration
provides **best-effort** audit forwarding, not guaranteed WORM
logging: a sustained CITADEL outage or a full buffer silently loses
evidence records, with no operator-facing "detections aren't being
recorded" signal beyond the metrics/logs above.

## Metrics

These are real, defined in `internal/metrics` and referenced from the
`Metrics` interface consumed by the client:

| Metric | Purpose |
|---|---|
| `vertguard_citadel_calls_total{target,result}` | Outbound call success/failure/breaker_open |
| `vertguard_citadel_latency_seconds{target}` | Latency histogram |
| `vertguard_worm_emit_total{event_type,result}` | Emit outcome counter (`ok`/`retry`/`fail`/`dry_run`/`dropped_buffer_full`) |
| `vertguard_citadel_queue_depth` | In-memory `EmitAsync` channel depth |

There is no `vertguard_marshal_decisions_total` metric — there are no
MARSHAL decisions to count.

## Testing

`internal/citadel/client_test.go` covers the real `Client` (signing,
retry/backoff, breaker behaviour, dry-run, queue-full drop) against an
`httptest.Server`. There is no separate integration suite against a
live CITADEL instance and no `internal/citadel/mock.go`.

## Where this leaves VertGuard's governance story

VertGuard's role in the ecosystem today is primarily a detection/scan
service and a receiver of ThreatFlow webhooks
(`internal/api/handlers/webhook_threatflow.go`). Its only CITADEL
touchpoint is this best-effort evidence emitter. If VertGuard is
expected to meet the ecosystem-wide "every privileged action is
MARSHAL-evaluated and every audit-relevant event is WORM-logged"
standard (see the root `CLAUDE.md`), that work has not been built yet:
there is no MARSHAL client, no Kerkese contract usage, and WORM
emission is best-effort rather than guaranteed. Treat any other
document, diagram, or onboarding material that describes VertGuard
submitting Kerkese requests, passing actions through MARSHAL gates, or
enforcing SoD as describing a future/aspirational state, not current
behavior.

## Related

- [architecture.md](architecture.md)
- [threatflow-integration.md](threatflow-integration.md)
