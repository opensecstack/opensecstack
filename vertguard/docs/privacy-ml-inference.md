## VertGuard Privacy Architecture — ML Inference (Phase 4.2)

This document is the definitive privacy reference for the ML inference
pipeline introduced in Phase 4.2. It covers what data the pipeline
touches during a scan request, what is never persisted, the isolation
guarantees that enforce those boundaries, and the alignment to EU AI Act
Article 10 data governance and GDPR obligations.

Audience: security architects, compliance officers, privacy engineers,
and auditors reviewing VertGuard's data handling. Read alongside
[`SECURITY.md`](../SECURITY.md) §Data handling and
[`ml-architecture.md`](ml-architecture.md) §Security boundary.

Cross-references: [`ml-architecture.md`](ml-architecture.md),
[`ml-model-registry.md`](ml-model-registry.md),
[`ml-models-reference.md`](ml-models-reference.md),
[`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md),
[`secrets-management.md`](secrets-management.md),
[`operator-runbook.md`](operator-runbook.md) §3.10.

## What the inference pipeline sees

A scan request passes through two processing stages before a verdict is
returned: the in-process Go scanner (regex prefilter) and, for the
SUSPICIOUS band only, the Python ML service over gRPC. The data visible
at each stage is strictly defined.

### Go scanner (regex prefilter)

| Signal              | Source                          | Visibility scope          |
|---------------------|---------------------------------|---------------------------|
| Prompt text         | Request body `text` field       | In-process, not logged    |
| Caller identity     | `X-VertGuard-Caller-ID` header  | Hashed in audit_event     |
| Tenant ID           | JWT claim / API key prefix      | Logged as plaintext label |
| Request ID          | Generated UUID per request      | Logged as correlation ID  |
| Scan module         | URL path (`/scan/prompt`, etc.) | Logged                    |
| Input length (bytes)| Derived from request body       | Logged                    |
| Input SHA-256       | Computed from raw bytes         | Logged as `input_hash`    |

The raw prompt text is consumed in-memory and discarded at the end of
the request handler. It never touches a log sink, metrics exporter, or
persistent store. The `input_hash` ("sha256:…") is the only durable
reference to the content; it enables correlation with Python-side logs
without reconstructing the original text.

### Python ML service (gRPC — SUSPICIOUS band only)

The Go scanner forwards a minimal gRPC message to the ML service when
the regex prefilter returns SUSPICIOUS. The proto payload is:

```protobuf
message ScoreRequest {
  string text        = 1;   // raw prompt text
  string request_id  = 2;   // correlation UUID from Go scanner
  string caller_id   = 3;   // hashed by Go before forwarding
  bytes  media_bytes = 4;   // optional: image/audio bytes (Phase 4.4+)
}
```

The Python service handles this payload as follows:

| Field          | Use                                          | Discarded after |
|----------------|----------------------------------------------|-----------------|
| `text`         | Tokenised, passed to the model forward pass  | Immediately     |
| `request_id`   | Tagged on Python-side log entries            | At log flush    |
| `caller_id`    | Already hashed by Go; not re-logged          | Immediately     |
| `media_bytes`  | Decoded into tensor, passed to model head    | Immediately     |

The Python service computes its own SHA-256 over the received text
before any logging. This hash matches the Go-side `input_hash` precisely
because both sides operate on the same bytes (UTF-8 encoded, no
whitespace normalisation). The match is the stitch that makes Go logs,
Python logs, and CITADEL audit_events traceable from a single hash
without storing content anywhere.

### Identity signals

VertGuard may receive identity-bearing inputs in two ways:

1. **Caller identity** — who is calling the scan API (tenant or service
   account). This flows as a JWT claim or API key prefix, and is logged
   as a pseudonymous tenant label, never as a named user.
2. **Content identity signals** — names, email addresses, or biometric
   features embedded in the scanned content itself (relevant to Module 5
   identity-verification). These are processed as classification features
   only and are not extracted, stored, or returned in the response.

For Module 5 (voice clone / identity verification, Phase 4.4):
audio features are reduced to an embedding vector inside the model; the
vector is not persisted. The audio bytes themselves are held only for the
duration of the forward pass.

## What is never stored

The following data items are explicitly excluded from all storage layers
— persistent disk, object store, metrics, logs, and audit trails:

| Item                       | Why excluded                                      |
|----------------------------|---------------------------------------------------|
| Raw prompt text            | Data minimisation; content is not VertGuard's data|
| Raw media bytes            | As above; may contain biometric / copyright data  |
| PII embedded in content    | Names, emails, phone numbers, document numbers    |
| Intermediate token tensors | Transient GPU/CPU memory; freed after forward pass|
| Model hidden-state vectors | Internal to the model; not surfaced               |
| Full caller name / email   | Pseudonymised at API ingress                      |
| Training data samples      | Training corpus lives only in the registry; never |
|                            | joined with production request data               |

`VERTGUARD_CONTENT_RETENTION` defaults to `false`. Setting it to `true`
enables an encrypted per-tenant content store for post-hoc review — see
[`SECURITY.md`](../SECURITY.md) §PII and content scanning. Even in
retention mode, ML inference inputs are not additionally persisted beyond
the normal request lifecycle; the retained object is the pre-ML scan
request, stored before the SUSPICIOUS verdict routes to the ML service.

## Inference isolation guarantees

### Process and network isolation

The Python ML service runs in a dedicated Kubernetes Pod with:

- Its own `ServiceAccount` (no `automountServiceAccountToken`).
- A `NetworkPolicy` that permits inbound gRPC only from the VertGuard Go
  Deployment and inbound scrape only from the Prometheus server. All
  other ingress and all egress are denied by default.
- `securityContext.runAsNonRoot: true`, `readOnlyRootFilesystem: true`,
  all Linux capabilities dropped.
- `hostNetwork: false`, `hostPID: false`.

gRPC between Go and Python is plaintext intra-cluster in Phase 4.2,
restricted to the NetworkPolicy described above. The mTLS gap is
documented and tracked:

| Phase       | Transport                                   |
|-------------|---------------------------------------------|
| 4.2 (now)   | Plaintext, NetworkPolicy-restricted          |
| 4.3.0       | SPIFFE/SPIRE workload certs (linkerd/istio) |
| 4.3.1       | mTLS enforced; plaintext rejected at ML pod  |

### Memory isolation

Each gRPC request is served synchronously in a thread pool worker. The
input tensor is allocated, used, and freed within that worker's stack.
There is no request-level cache or session state that could leak tensors
across concurrent callers. The model weights themselves are read-only
after load and are never modified at inference time.

### Multi-tenant isolation

In multi-tenant deployments, VertGuard runs one Go Deployment and one
ML Pod per tenant namespace, or uses namespace-scoped NetworkPolicies to
enforce strict cross-tenant isolation at the network layer. Tenant ID is
never forwarded in the gRPC message body; the Python service is unaware
of tenancy and processes each request identically. Routing decisions that
are tenant-specific (threshold configuration, module enablement) are
resolved in the Go layer before the gRPC call is made.

## Differential privacy applicability

Differential privacy (DP) is not applied to inference-time processing in
Phase 4.2. The reasons are:

1. **No aggregate release.** Inference outputs are per-request verdicts,
   not statistics over a population of inputs. DP protects statistical
   outputs; it provides no additional protection for individual
   classification outputs.
2. **No model update from production data.** The deployed model is a
   frozen artefact. Production inputs never flow back into training in
   Phase 4.2. The training corpus is managed under the separate
   governance described in [`ml-training-guide.md`](ml-training-guide.md).

DP applicability is re-evaluated in Phase 4.3 if federated fine-tuning
across CITADEL tenants is adopted. In that scenario, per-tenant gradient
updates would be clipped and noised before aggregation — see
[`ml-architecture.md`](ml-architecture.md) §Future work.

## Data residency

VertGuard is self-hosted. Scanned content never leaves the operator's
infrastructure unless the operator explicitly configures external
endpoints. Specifically:

| Data item              | Where it stays                                   |
|------------------------|--------------------------------------------------|
| Scan inputs            | Operator's cluster (ephemeral, in-memory only)   |
| Audit_events           | Operator's CITADEL WORM instance                 |
| Model weights          | Operator's model registry (S3-compatible bucket) |
| Training corpus        | Operator's registry; not mixed with prod traffic |
| Metrics                | Operator's Prometheus / Grafana stack            |

For EU-jurisdiction operators, this design supports GDPR Article 44+
(transfers to third countries) compliance by default: no transfers occur.
Operators who configure `ml.registry.url` pointing to a third-country
object store are responsible for their own transfer mechanism (SCCs,
adequacy decision, or equivalent).

## EU AI Act Article 10 — data governance alignment

AI Act Article 10 requires that providers of AI systems subject to data
governance obligations establish practices covering training, validation,
and testing data with respect to relevance, representativeness, freedom
from errors, and completeness.

VertGuard's alignment:

| Article 10 obligation           | VertGuard implementation                              |
|---------------------------------|-------------------------------------------------------|
| Data governance practices       | Training corpus managed under `ml-training-guide.md`; dataset SHA-256 anchored in model card |
| Relevance and representativeness| Corpus expansion plan (VG-007/VG-008): back-translation, adversarial red-team, Albanian-language coverage |
| Freedom from errors             | Reviewer sign-off required before any sample merges into corpus |
| Completeness / known biases     | Documented per model in `ml-models-reference.md`; bias assessment updated at each re-train |
| Data protection in training     | Community contribution pipeline: submitter-side hashing prevents raw text leaving the contributor's environment |
| Separation of training and inference data | Training corpus never joined with production request data; separate registry paths enforce this at the storage layer |

Inference-time data governance specifically: no input seen during
inference is routed back to the training corpus without explicit
operator opt-in, reviewer sign-off, and WORM-logged provenance linking
the production audit_event to the corpus entry.

## Audit trail for inference calls

Every scan request that reaches the ML stage produces an `audit_event`
written to the CITADEL WORM log. The event schema:

```json
{
  "event_type": "scan",
  "request_id": "uuid",
  "timestamp_utc": "ISO-8601",
  "tenant_id": "label",
  "input_hash": "sha256:...",
  "input_length_bytes": 512,
  "scan_module": "prompt",
  "regex_verdict": "SUSPICIOUS",
  "ml_verdict": "BLOCKED",
  "ml_confidence": 0.91,
  "ml_model_version": "distilbert-prompt-injection/v1.0.0",
  "ml_backend": "onnx",
  "ml_latency_ms": 34,
  "final_verdict": "BLOCKED",
  "ml_skipped": null
}
```

Fields that are explicitly absent from the audit_event:

- `text` — raw prompt. Never in the event.
- `media_bytes` — raw media. Never in the event.
- `caller_name`, `caller_email` — replaced by pseudonymous `tenant_id`.

When the ML stage is skipped (CLEAN or BLOCKED by regex, or breaker
open), `ml_verdict` and `ml_confidence` are null and `ml_skipped` is
set to `"not_reached"` or `"breaker_open"` respectively. This preserves
a complete audit record for every request regardless of path.

The WORM log is append-only. VertGuard operators cannot delete or modify
audit_events after they are committed. Auditors can cross-verify entries
against the CITADEL chain independently.

### Retention

Audit_events are retained according to the operator's CITADEL retention
policy. The recommended minimum for NIS2 Article 21/23 compliance is
**36 months**. Raw inputs are never retained alongside audit_events;
the `input_hash` is the only link between the audit record and the
original content, and the hash is one-way.

## Opt-out mechanisms

### Per-deployment opt-out of ML inference

Operators can disable the ML inference stage entirely by setting
`ml.enabled=false` in the Helm values. In this mode, all verdicts are
produced by the regex prefilter only. Audit_events continue to be written
with `ml_skipped="disabled"`. No data reaches the Python service.

### Per-caller opt-out

Callers can signal that a request should not be forwarded to the ML
service by including the header `X-VertGuard-ML-Opt-Out: true`. The Go
scanner honours this flag: the regex prefilter runs normally, and the
SUSPICIOUS band is promoted to BLOCKED (fail-closed) rather than being
routed to the ML service. The audit_event records `ml_skipped="caller_opt_out"`.

Operators can disable per-caller opt-out by setting
`config.ml.allow_caller_opt_out=false` (default: `true`). In high-security
deployments where the operator mandates ML enrichment for all SUSPICIOUS
verdicts, this prevents callers from bypassing the ML stage.

### Content retention opt-out

Even when `VERTGUARD_CONTENT_RETENTION=true` is set at the deployment
level, individual API callers can suppress content retention for a
specific request with `X-VertGuard-Retain-Content: false`. This provides
a request-level escape hatch for operators who retain most content but
need to suppress retention for privacy-sensitive scans.

## DPIA note

A Data Protection Impact Assessment template for VertGuard Phase 4.2 is
planned (VG-019). Until it is published, operators should conduct their
own DPIA referencing this document as the processing record. Key inputs
for the DPIA:

- Legitimate interest or contract as the lawful basis for processing
  scan inputs (Art. 6(1)(b) or (f) GDPR).
- No special-category data is sought; if it appears incidentally in
  scanned content, it is not extracted or retained.
- No automated decision-making with legal or similarly significant
  effects on natural persons (Art. 22 GDPR) — VertGuard classifies
  content, not people; enforcement decisions remain with the operator.
- Data subjects are typically the operators' own users; a DPIA for the
  operator's use of VertGuard should address this relationship.

## Related

- [`SECURITY.md`](../SECURITY.md) — threat model, data handling overview
- [`ml-architecture.md`](ml-architecture.md) — system design, security boundary
- [`ml-models-reference.md`](ml-models-reference.md) — model cards, bias assessment
- [`ml-training-guide.md`](ml-training-guide.md) — training data governance
- [`nis2-ai-act-mapping.md`](nis2-ai-act-mapping.md) — regulatory mapping
- [EU AI Act Art. 10 consolidated text](https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX:32024R1689)
- [GDPR Art. 25 (data protection by design)](https://gdpr-info.eu/art-25-gdpr/)
