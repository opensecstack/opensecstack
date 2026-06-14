## ADR-005 — MITRE ATLAS as primary AI threat taxonomy

- Status: Accepted
- Date: 2026-05-10
- Phase: 4.1
- Owners: VertGuard core, Module 4
- Related: [`docs/module-4-ai-threat-feed.md`](../docs/module-4-ai-threat-feed.md),
  [`docs/architecture.md`](../docs/architecture.md),
  [`internal/threatfeed/atlas/`](../internal/threatfeed/atlas/),
  [`internal/db/`](../internal/db/) (`atlas_mappings` table)

## Context

Module 4 (AI Threat Intelligence Feed) collects, normalises, and
pushes AI-specific IOCs to ThreatFlow. Every IOC must be tagged with
a technique identifier so analysts can correlate incidents, filter
feeds, and map mitigations. A standard taxonomy is required.

Options evaluated: MITRE ATT&CK (general adversary tactics), OWASP
LLM Top 10 (LLM-application risks), MITRE ATLAS (AI-focused attack
taxonomy), and a VertGuard-proprietary taxonomy.

## Decision

VertGuard uses **MITRE ATLAS** as the primary taxonomy for AI attack
technique identification. ATLAS technique IDs (e.g. `AML.T0051`)
are the canonical tag on ThreatFlow IOCs and CITADEL WORM entries.
ATLAS data is synced periodically via `internal/threatfeed/atlas/`
and cached in the `atlas_mappings` table.

**OWASP LLM Top 10** is used additionally as a secondary tag on
prompt injection detections, where the OWASP category (e.g. `LLM01`)
provides a widely-understood shorthand for developers consuming the
feed. It does not replace ATLAS — both tags are emitted.

## Reasons

- **AI specificity.** MITRE ATT&CK covers general adversary tactics
  (phishing, lateral movement, exfiltration) but has no techniques
  for adversarial ML attacks (model poisoning, model inversion,
  membership inference). ATLAS was designed specifically for AI
  systems and is maintained by MITRE with input from industry.
- **Machine-readable and versioned.** ATLAS publishes a YAML
  manifest that can be consumed programmatically. The `atlas/sync.go`
  syncer polls `AtlasSourceURL` and updates the local cache, making
  technique definitions self-updating without a VertGuard release.
- **ThreatFlow compatibility.** ThreatFlow's IOC schema accepts
  `ai_attack_pattern` typed indicators with a `technique_id` field.
  ATLAS IDs map cleanly to this field. OWASP category strings are
  carried in the `tags` array as supplementary context.
- **Proprietary taxonomy rejected.** A VertGuard-specific taxonomy
  would not interoperate with other security tools, would require
  maintenance, and would provide no value to the broader ecosystem.

## Consequences

- **Sync dependency.** The ATLAS syncer (`RunPeriodic`) must be
  reachable at the configured `AtlasSourceURL`. Failures downgrade
  gracefully — the last successfully synced cache is used. The
  embedded `Initial()` set seeds the cache on first boot so the
  service starts even without network access.
- **ATLAS versioning.** When MITRE releases a new ATLAS version,
  existing `atlas_mappings` rows retain the old technique IDs.
  A migration script is required to remap renamed techniques.
- **OWASP LLM Top 10 is supplementary only.** It covers 10 LLM
  application risks, not the breadth of AI attack surface. Using
  it as primary would leave ATLAS-only techniques untagged.

## Alternatives considered + rejected

- **MITRE ATT&CK only.** No AI-specific techniques; does not cover
  model poisoning, adversarial examples, or model inversion.
  **Rejected as primary** (retained for mapping human-threat context
  in hybrid attacks).
- **OWASP LLM Top 10 only.** Narrowly scoped to LLM application
  risks; no coverage for non-LLM AI attacks (deepfake generation,
  audio spoofing). **Rejected as primary; accepted as secondary.**
- **Proprietary taxonomy.** No interoperability; maintenance burden;
  no community adoption. **Rejected.**

## Validation

- `go test ./internal/threatfeed/atlas/...` verifies sync, cache
  population, and technique lookup.
- `POST /api/v1/threatfeed/iocs` response must include `technique_id`
  matching an ATLAS AML.TXXXX pattern.
- `helm template` with `ioc.enabled=true` must render the ATLAS sync
  CronJob / goroutine wiring.

## Follow-ups

- ATLAS v2.x: review technique renames against `atlas_mappings`;
  add migration when breaking changes are released.
- Phase 4.3: expose technique-filtered feed endpoints so consumers
  can subscribe to specific ATLAS tactics (e.g. tactic `AML.TA0000`).
