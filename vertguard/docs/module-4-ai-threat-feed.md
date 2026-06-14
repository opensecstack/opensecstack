# Module 4 — AI Threat Intelligence Feed

**Status:** Phase 4.1 — Active development.

Module 4 is VertGuard's AI-specific threat intelligence layer. It
aggregates indicators of AI-attack behaviour — prompt injection
patterns, known malicious prompts, AI-generated phishing templates,
deepfake-hosting domains, model extraction techniques — and makes
them available to the rest of the ecosystem via the ThreatFlow IOC
contract.

This is the AI-era equivalent of a classical threat intel feed:
instead of IP addresses and file hashes, we track prompt patterns and
technique fingerprints.

For the ATLAS mapping reference, see [mitre-atlas-mapping.md](mitre-atlas-mapping.md).
For ThreatFlow integration specifics, see [threatflow-integration.md](threatflow-integration.md).

## Scope

Module 4 does three things:

1. **Collect** AI-attack indicators from multiple sources.
2. **Normalise** into ThreatFlow's IOC contract with `ai_attack_pattern`
   type.
3. **Distribute** via push to ThreatFlow + pull API for direct
   consumers.

What Module 4 does **not** do:

- Generate original threat intelligence (that's research).
- Make threat-actor attribution claims.
- Collect classical IOCs (IPs, domains, hashes) — those stay with
  ThreatFlow. We only handle AI-specific patterns.

## Sources

| Source | Type | Refresh | Notes |
|---|---|---|---|
| **MITRE ATLAS** | Techniques + procedures | Weekly | Authoritative framework; `atlas.mitre.org` |
| **OWASP LLM Top 10** | Attack categories + examples | Quarterly | Framework-derived, not per-IOC |
| **Public advisories** | Vendor advisories (OpenAI, Anthropic, Google) | As published | Manual curation initially |
| **Community feeds** | GitHub-hosted open repos (Ai-Exploits, Awesome-Jailbreaks, etc.) | Daily | SHA-checksummed source manifests |
| **Self-observed** | Novel patterns from VertGuard Module 3 runtime | Continuous | v0.3+ feature; flagged patterns marked `self-observed` |

Each source is configured in `VERTGUARD_THREATFEED_SOURCES` YAML.
Adding/disabling sources is a config-only change — no code deploy.

### Source-manifest schema

```yaml
sources:
  - id: mitre-atlas
    type: api
    endpoint: https://atlas.mitre.org/api/v1/techniques
    refresh_cron: "0 0 * * 0"   # Sunday 00:00 UTC
    license: Apache-2.0
    trust_level: authoritative

  - id: awesome-jailbreaks
    type: git
    repo: https://github.com/example/awesome-jailbreaks
    branch: main
    path: patterns/*.yaml
    sha_pin: 7a2f8c...
    refresh_cron: "0 6 * * *"   # daily 06:00 UTC
    license: CC-BY-4.0
    trust_level: community
```

**Trust levels** flow into the IOC `confidence` field.

## IOC contract

Module 4 emits IOCs that conform to ThreatFlow's existing schema plus
an `ai_attack_pattern` type:

```json
{
  "type":        "ai_attack_pattern",
  "value":       "jailbreak.persona_takeover.v3",
  "source":      "awesome-jailbreaks",
  "source_ref":  "https://github.com/example/awesome-jailbreaks/commit/...",
  "technique":   "AML.T0051.000",
  "mitre_atlas": {
    "technique_id": "AML.T0051",
    "sub_technique_id": "AML.T0051.000",
    "tactic":       "AML.TA0005"
  },
  "description": "LLM persona takeover via DAN-style role-play framing",
  "confidence":  0.91,
  "severity":    "high",
  "first_seen":  "2026-03-12T14:22:01Z",
  "last_seen":   "2026-04-19T10:15:00Z",
  "references": [
    "https://atlas.mitre.org/techniques/AML.T0051",
    "https://owasp.org/www-project-top-10-for-large-language-model-applications/"
  ],
  "tags": ["ai_attack_pattern", "prompt_injection", "jailbreak", "llm01"]
}
```

The pattern `value` is canonical across sources — if two sources
report the same technique (e.g. "DAN jailbreak"), they map to the
same pattern ID.

## MITRE ATLAS integration

ATLAS (Adversarial Threat Landscape for AI Systems) is the
authoritative MITRE framework for AI threats. Module 4 maintains a
full ATLAS mapping:

- All ATLAS techniques ingested weekly.
- Each VertGuard pattern tagged with the closest ATLAS technique.
- Reverse mapping: given an ATLAS technique, list VertGuard patterns
  that detect it.

API for this is:

```
POST /api/v1/threatfeed/atlas
Body: { "observed_behaviour": "..." }
Returns: { "matches": [{ "technique_id": "...", "confidence": ... }] }
```

Full mapping table: [mitre-atlas-mapping.md](mitre-atlas-mapping.md).

## Push to ThreatFlow

Every new or updated IOC is pushed to ThreatFlow via the SDK:

```go
// internal/threatfeed/threatflow.go (conceptual)
client := threatflow.NewClient(config.ThreatFlowURL, config.ThreatFlowKeySecret)
err := client.SubmitIOCBundle(ctx, bundle)
```

The bundle is HMAC-signed per the standard ThreatFlow webhook contract
(see [../../threatflow/docs/webhook-spec.md](../../threatflow/docs/webhook-spec.md)).

Push cadence:

- **Real-time** for patterns observed with `severity: critical` (e.g. a
  zero-day prompt that bypasses every known filter).
- **Batched every 15 minutes** for routine updates.
- **Reconciliation** daily: compare local state vs ThreatFlow's AI-tag
  bucket and push divergences.

## Pull API for direct consumers

Consumers not using ThreatFlow can query VertGuard directly:

```
GET /api/v1/threatfeed/iocs?since=2026-04-01&technique=AML.T0051&confidence_gte=0.8
```

Returns paginated JSON with the IOC envelopes defined above.

**Rate limits:** 100 req/min per API key by default. Configurable.

## Schedule

```
Hourly (on the :00):
  - Poll MITRE ATLAS for updates
  - Reload community feeds where SHA has changed

Every 15 minutes:
  - Batch push new/updated IOCs to ThreatFlow
  - Update local `last_seen` on observed patterns

Daily (04:00 UTC):
  - Full reconciliation with ThreatFlow AI-tag bucket
  - Clean stale IOCs (not seen in 90 days → mark deprecated)

Weekly (Sunday 00:00 UTC):
  - Full ATLAS sync
  - Source-manifest integrity check (all SHA pins still valid)
```

Schedules are viper-configurable (`VERTGUARD_THREATFEED_SCHEDULES_*`).

## Database schema

`migrations/005_threatfeed.sql` (conceptual):

```sql
CREATE TABLE threat_iocs (
    id              UUID PRIMARY KEY,
    pattern_value   TEXT NOT NULL,      -- canonical pattern ID
    type            TEXT NOT NULL,      -- always 'ai_attack_pattern' in v0.1
    source          TEXT NOT NULL,
    source_ref      TEXT,
    atlas_technique TEXT,               -- AML.T####
    confidence      NUMERIC(3,2),
    severity        TEXT,
    description     TEXT,
    references      JSONB,
    tags            TEXT[],
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    deprecated      BOOLEAN DEFAULT FALSE,
    UNIQUE (pattern_value, source)
);

CREATE INDEX idx_threat_iocs_atlas ON threat_iocs (atlas_technique);
CREATE INDEX idx_threat_iocs_last_seen ON threat_iocs (last_seen);
CREATE INDEX idx_threat_iocs_confidence ON threat_iocs (confidence);
```

## Confidence score derivation

```
confidence = source_trust_weight * pattern_intrinsic_confidence * recency_factor
```

| Factor | Range | Notes |
|---|---|---|
| `source_trust_weight` | 0.5-1.0 | `authoritative` (MITRE) = 1.0; `vendor-advisory` = 0.9; `community` = 0.7; `self-observed` = 0.6 |
| `pattern_intrinsic_confidence` | 0.5-1.0 | Source-declared confidence in the pattern itself |
| `recency_factor` | 0.5-1.0 | Decays linearly: last_seen within 30 days = 1.0; between 30-90 days = 0.8; beyond 90 days = 0.5 |

Final scores clamped to [0.5, 1.0] — we don't emit IOCs below 0.5
confidence.

## Integration with ecosystem

### ThreatFlow (primary consumer)

AI-tagged IOCs live in a dedicated bucket in ThreatFlow's IOC store.
Queries across both classical and AI IOCs work via ThreatFlow's
standard API — VertGuard doesn't need to be queried for
cross-correlation.

### IRFlow

When IRFlow creates an incident from an APIGuard finding, it queries
ThreatFlow (including AI IOCs). If the attack pattern maps to an
ATLAS technique, IRFlow enriches the incident with ATLAS context
(tactic, procedure, known-associated threat actors).

### SecureLab

SecureLab's attack-simulation scenarios reference ATLAS technique IDs.
When SecureLab runs an AI-attack scenario, VertGuard's IOC feed
supplies the scenario payload library.

### CITADEL (audit path)

Changes to the IOC corpus are WORM-logged: which pattern was added,
deprecated, or updated, by which source, at what time. This creates
an auditable threat-intelligence provenance chain.

## Metrics

| Metric | Description |
|---|---|
| `vertguard_threatfeed_iocs_total{source, atlas_technique}` | IOC volume |
| `vertguard_threatfeed_push_total{target, result}` | ThreatFlow push outcomes |
| `vertguard_threatfeed_latency_seconds{source}` | Per-source collection latency |
| `vertguard_threatfeed_staleness_seconds{source}` | Time since last successful collection |

Alert: sustained `vertguard_threatfeed_push_total{result="failure"}`
rate > 0 means ThreatFlow integration is broken.

## Open issues (Phase 4.1 scope)

- [ ] MITRE ATLAS full-framework ingestion (all techniques + tactics)
- [ ] Community-feed source catalogue (initial 5-10 sources)
- [ ] Vendor-advisory scraper (OpenAI, Anthropic, Google, Mistral)
- [ ] IOC canonicalisation across sources (prevent duplicates)
- [ ] ThreatFlow integration contract signed off by ThreatFlow team
- [ ] Pull API rate limiting + API-key model
- [ ] Reconciliation worker (daily cross-check vs ThreatFlow)
- [ ] Self-observed pattern capture (v0.3+ — requires Module 3 v0.2+)

## Related

- [mitre-atlas-mapping.md](mitre-atlas-mapping.md) — full ATLAS coverage
- [threatflow-integration.md](threatflow-integration.md) — wire format
- [api.md § Threat feed endpoints](api.md)
- [../../threatflow/docs/webhook-spec.md](../../threatflow/docs/webhook-spec.md)
- [module-3-prompt-injection.md](module-3-prompt-injection.md) — source of self-observed patterns
