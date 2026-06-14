## ADR-004 — All ML inference runs locally; no external API calls

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1 (hard requirement; applies to all phases)
- Owners: VertGuard core, Security, Compliance
- Related: [`docs/architecture.md`](../docs/architecture.md),
  ADR-003 (HuggingFace model selection),
  ADR-012 (Python ML service architecture)

## Context

VertGuard processes sensitive security data: raw phishing email
bodies, prompt injection attempts against customer LLMs, deepfake
media, and synthetic identity signals. This data is operationally
classified and may include PII. The system is deployed by ASNI (the
Albanian Armed Forces communications and IT agency) and must comply
with NIS2 Article 21 security measures for essential services.

The question is whether ML classification may be performed by calling
an external SaaS API (OpenAI, Anthropic, Cohere, Google Vertex AI,
etc.) or must run entirely within the customer's deployment boundary.

## Decision

**All ML inference in VertGuard must run locally.** No content
submitted to any VertGuard endpoint may be forwarded to an external
API for classification, enrichment, or any other processing. This is
a hard requirement — not a default — and applies to every module and
every phase.

The constraint is enforced architecturally: the Python ML service has
no outbound network access by default (Kubernetes NetworkPolicy;
`egress: []`). Any code path that would call an external API must be
blocked at the network layer, not just by convention.

## Reasons

- **NIS2 Article 21 data sovereignty.** Article 21(2)(e) requires
  that essential-service operators apply appropriate security measures
  to information assets. Sending raw phishing emails or prompt
  injection content to a third-party API transfers control of that
  data outside the operator's security boundary.
- **Operational secrecy.** Phishing emails targeting ASNI staff and
  prompt injection attempts against ASNI's LLM deployments are
  operationally sensitive. A compromised SaaS API (or a legal request
  to the SaaS provider) could expose threat intelligence about active
  attacks.
- **Air-gapped deployment requirement.** ASNI tactical networks
  operate without internet connectivity. External API calls would
  make VertGuard non-functional in the primary deployment environment.
- **Cost and availability.** Per-request API costs would dominate
  unit economics at scan volume; API availability SLAs (99.9%) are
  insufficient for a security-critical path that must operate during
  the incidents it detects.

## Consequences

- **Higher hardware requirements.** Local inference requires CPU/RAM
  for the Python ML pod (minimum 2 GiB; GPU optional). Operators
  must provision this capacity.
- **Model update discipline.** Without a SaaS provider managing
  model updates, VertGuard must maintain its own model lifecycle
  (versioned `models/models.yaml`, accuracy benchmarks in CI).
  See ADR-003.
- **No zero-shot generalisation.** Local DistilBERT models cannot
  be prompted ad-hoc. Novel attack categories require fine-tuning
  rather than a prompt change.

## Alternatives considered + rejected

- **SaaS API (OpenAI / Anthropic / Cohere).** Data leaves the
  deployment; NIS2 violation; air-gap incompatible; per-request
  cost; no fine-tuning with sovereign data. **Rejected.**
- **Opt-in SaaS with redaction.** Redacting PII before sending still
  exposes attack patterns and threat intelligence. Redaction
  correctness cannot be guaranteed for novel payloads.
  **Rejected.**
- **Hybrid: local for classified, SaaS for unclassified.** Adds
  a classification step before inference; misclassification leaks
  classified data. Complexity outweighs any benefit. **Rejected.**

## Validation

- The Python ML service NetworkPolicy in `deploy/helm/vertguard/`
  must specify `egress: []` (no outbound) by default.
- `grep -r "openai\|anthropic\|cohere\|vertex" python/ml_service/`
  must return zero matches in CI.
- Integration test: run VertGuard with network namespace isolation;
  all scan endpoints must return results (not errors) with no
  external packets emitted.

## Follow-ups

- SPIFFE/mTLS (Phase 4.3) will add workload identity verification
  on the intra-cluster gRPC path, replacing the NetworkPolicy-only
  isolation boundary.
