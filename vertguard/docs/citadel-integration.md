# CITADEL Integration

Every VertGuard detection — positive or negative — is recorded in the
CITADEL WORM audit chain. Every auto-response action VertGuard
proposes passes through CITADEL MARSHAL for approval. This document
describes the integration contract and operational concerns.

For VertGuard's architecture context, see [architecture.md](architecture.md).
For CITADEL's interfaces, see [../../citadel/docs/api.md](../../citadel/docs/api.md)
and [../../citadel/docs/kerkese-spec.md](../../citadel/docs/kerkese-spec.md).

## What gets CITADEL-integrated

### WORM audit trail (always)

Every detection that reaches a terminal classification
(CLEAN / SUSPICIOUS / BLOCKED / AUTHENTIC / UNAUTHENTIC) is
WORM-logged. This provides:

- **Audit trail** — who scanned what, when, with what outcome
- **Appeal path** — disputed classifications reference the WORM entry
- **NIS3 evidence** — regulators can trace AI-defence claims back to
  concrete detections
- **Forensic reconstruction** — post-incident, reconstruct what
  VertGuard knew at each moment

### MARSHAL gate (when auto-responding)

When VertGuard proposes an auto-response action — e.g. quarantine an
email, block a user session, notify a CSIRT — the action passes
through MARSHAL 5-gate evaluation before execution. This ensures:

- The action is authorised for the actor (Gate 2 AuthZ)
- Separation of duties is enforced if required (Gate 3 NDS)
- Behavioural heuristics apply (Gate 4 AUGUR)

## Event taxonomy

VertGuard emits these event types to CITADEL's WORM chain:

| `event_type` | Module | Triggered by |
|---|:-:|---|
| `vertguard.detection.prompt_injection` | 3 | Any non-CLEAN prompt scan |
| `vertguard.detection.media_authenticity` | 1 | Every media verification |
| `vertguard.detection.ai_phishing` | 2 | Any non-CLEAN phishing scan (Phase 4.2+) |
| `vertguard.detection.synthetic_identity` | 5 | Any suspicious identity check (Phase 4.3+) |
| `vertguard.threatfeed.ioc_added` | 4 | New AI-IOC observed |
| `vertguard.threatfeed.ioc_deprecated` | 4 | IOC retired |
| `vertguard.threatfeed.atlas_synced` | 4 | MITRE ATLAS sync completed |

Full schema details in the CITADEL integration section of each
module's doc.

## WORM emission flow

```
VertGuard detection completes
     │
     ▼
internal/media/evidence.go (or prompt/scorer.go, etc.)
     │ - assemble evidence envelope
     │ - sign with VERTGUARD_CITADEL_KEY_SECRET (HMAC-SHA256)
     │
     ▼
internal/citadel/connector.go
     │
     ▼
POST https://citadel.internal:8099/api/v1/worm/emit
     │ - CITADEL verifies signature
     │ - CITADEL appends to WORM chain
     │ - Returns worm_entry_id
     │
     ▼
VertGuard persists worm_entry_id alongside detection metadata
     │
     ▼
API response includes worm_entry_id
```

## MARSHAL gate flow (auto-response actions)

Used for actions VertGuard wants to take (Phase 4.2+ — quarantine
email, block session, etc.):

```
Action proposed (e.g. quarantine email)
     │
     ▼
internal/citadel/connector.go constructs Kerkese
     │ - actor: vertguard service identity
     │ - action.type: QUARANTINE_EMAIL
     │ - action.incident_id: auto-created IRFlow incident
     │ - sod: operator (vertguard) + verifier (admin or peer)
     │
     ▼
POST https://citadel.internal:8099/api/v1/marshal/evaluate
     │
     ▼
CITADEL returns Decision:
     │ - EXECUTE → VertGuard performs the action
     │ - REFUSE  → action cancelled; logged
     │ - HARD_STOP → action cancelled; IRFlow P1 incident
     │
     ▼
VertGuard updates scan result with MARSHAL decision + worm_entry_id
```

## Evidence envelope schemas

### `vertguard.detection.prompt_injection`

```json
{
  "event_type":     "vertguard.detection.prompt_injection",
  "project_id":     "prod",
  "scan_id":        "scan_abc123",
  "classification": "BLOCKED",
  "confidence":     0.98,
  "input_hash":     "<SHA-256 of input bytes>",
  "input_length":   38,
  "matched_patterns": [
    { "id": "LLM01.instruction_override.v1", "confidence": 0.98, "byte_range": [0,38] }
  ],
  "context":        "user_chat_input",
  "ts_utc":         "2026-04-25T10:12:03Z"
}
```

**Privacy:** note `input_hash` not raw content. Content never enters
CITADEL — hashes and metadata only.

### `vertguard.detection.media_authenticity`

```json
{
  "event_type":     "vertguard.detection.media_authenticity",
  "project_id":     "prod",
  "scan_id":        "scan_def456",
  "classification": "authentic",
  "content_type":   "image/jpeg",
  "content_hash":   "<triple-hash-hex>",
  "content_size":   12345,
  "provenance_chain": [
    { "actor": "Adobe Photoshop", "action": "c2pa.created", "ts": "..." },
    { "actor": "BBC Editorial",    "action": "c2pa.published", "ts": "..." }
  ],
  "signer":         "BBC Editorial",
  "ts_utc":         "..."
}
```

### `vertguard.threatfeed.ioc_added`

```json
{
  "event_type":    "vertguard.threatfeed.ioc_added",
  "project_id":    "vertguard",
  "ioc": {
    "type":        "ai_attack_pattern",
    "value":       "jailbreak.persona_takeover.v3",
    "source":      "awesome-jailbreaks",
    "source_ref":  "https://github.com/.../commit/...",
    "confidence":  0.91,
    "mitre_atlas": { "technique_id": "AML.T0051.000" }
  },
  "ts_utc": "..."
}
```

## Configuration

```bash
VERTGUARD_CITADEL_API_URL=http://citadel.internal:8099
VERTGUARD_CITADEL_KEY_ID=vertguard-prod
VERTGUARD_CITADEL_KEY_SECRET=<64-byte random>
VERTGUARD_CITADEL_PROJECT_ID=prod
VERTGUARD_CITADEL_DRY_RUN=false   # true in staging
```

`DRY_RUN=true` short-circuits MARSHAL to always return EXECUTE and
skips WORM emission. Staging-only.

Empty `KEY_SECRET` → **standalone mode**: detections returned to
caller but NOT WORM-logged. Loud WARN at startup. **Never** in
production — detections are evidence; without WORM, they don't count.

## Failure handling

CITADEL integration is **synchronous for WORM emission on incident
creation** (analogous to IRFlow's pattern) but **best-effort for
routine detections**:

| CITADEL state | VertGuard behaviour |
|---|---|
| Healthy | Normal flow; every detection WORM-logged |
| Slow (p95 > 100 ms) | Normal flow; latency histogram shows the degradation |
| Unreachable (temporary) | Detection returned to caller; WORM emission queued locally for retry |
| Extended outage | After 1 hour of queueing, operator paged; detections continue to flow |
| Returns 5xx persistently | Configurable: continue accepting detections (queue) OR start returning 503 (strict) |

Queue depth exposed as `vertguard_citadel_queue_depth` metric.

## Post-quantum readiness

VertGuard inherits CITADEL's PQC migration timeline. By v2.0 (2028),
CITADEL anchor signatures will be hybrid Ed25519 + ML-DSA; VertGuard
evidence envelopes remain unchanged (they go through HMAC-SHA256 to
CITADEL, which then anchors them).

By v3.0 (2030), CITADEL defaults to ML-DSA; VertGuard's integration
requires no code change — the primitive agility lives at the CITADEL
layer.

See [ecosystem-wide PQ roadmap](../../docs/post-quantum-roadmap.md).

## Metrics

| Metric | Purpose |
|---|---|
| `vertguard_citadel_calls_total{target,result}` | Outbound call success/failure |
| `vertguard_citadel_latency_seconds` | Latency histogram |
| `vertguard_marshal_decisions_total{outcome}` | MARSHAL decision distribution |
| `vertguard_worm_emit_total{event_type,result}` | WORM emission counter |
| `vertguard_citadel_queue_depth` | Local queue (alert > 1000 sustained) |

Alert: `vertguard_marshal_decisions_total{outcome="HARD_STOP"}` rate
> 0 sustained indicates a potential policy breach under investigation.

## Testing

Integration tests in `tests/integration/citadel_test.go` run against
a live CITADEL staging instance. Mock CITADEL available in
`internal/citadel/mock.go` for unit tests.

## Related

- [architecture.md](architecture.md)
- [../../citadel/docs/kerkese-spec.md](../../citadel/docs/kerkese-spec.md)
- [../../citadel/docs/worm-log.md](../../citadel/docs/worm-log.md)
- [../../citadel/docs/marshal-engine.md](../../citadel/docs/marshal-engine.md)
- [../SECURITY.md § Data handling](../SECURITY.md)
