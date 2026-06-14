# MITRE ATLAS Mapping

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence
Systems) is the authoritative framework for AI-system attacks,
published by MITRE Corporation. VertGuard aligns with ATLAS as its
primary taxonomy — every pattern, IOC, and detection is tagged with
the closest ATLAS technique where applicable.

ATLAS spec: https://atlas.mitre.org/

## Why ATLAS

Three reasons:

1. **Authoritative.** ATLAS is the MITRE-curated equivalent of
   ATT&CK for AI systems. Adopting it aligns with how threat
   intelligence will be shared across the EU / US / allied CSIRT
   ecosystem.
2. **Actionable.** Each ATLAS technique has documented mitigations,
   procedures, and known actors — VertGuard detections become
   plug-compatible with existing SOC tooling.
3. **Futureproof.** ATLAS evolves with the threat landscape; new
   techniques added quarterly. VertGuard's sync cadence (weekly for
   full framework, daily for updates) tracks this.

## Coverage approach

VertGuard covers ATLAS in three ways:

### 1. Detection-to-technique mapping

Every Module 3 pattern is tagged with its matching ATLAS technique:

```yaml
id:              LLM01.instruction_override.v1
atlas_technique: AML.T0051.000
atlas_tactic:    AML.TA0005
```

### 2. IOC-to-technique enrichment

Every AI-IOC in Module 4's feed carries ATLAS metadata:

```json
{
  "type":      "ai_attack_pattern",
  "value":     "...",
  "mitre_atlas": {
    "technique_id":     "AML.T0051",
    "sub_technique_id": "AML.T0051.000",
    "tactic":           "AML.TA0005"
  }
}
```

### 3. Behaviour-to-technique lookup API

Given an observed behaviour description, return matching ATLAS
techniques:

```
POST /api/v1/threatfeed/atlas
Body: { "observed_behaviour": "ML model exfiltration via inference API" }
```

## Tactics covered

ATLAS organises techniques under tactics. VertGuard's runtime scope
covers these tactics:

| Tactic ID | Name | VertGuard coverage |
|---|---|:-:|
| AML.TA0001 | Reconnaissance | ❌ |
| AML.TA0002 | Resource Development | ❌ |
| AML.TA0003 | Initial Access | 🔶 (via APIGuard + ThreatFlow) |
| AML.TA0004 | ML Model Access | 🔶 (Module 4 IOCs) |
| AML.TA0005 | Execution | ✅ (Module 3 primary) |
| AML.TA0006 | Persistence | ❌ (training-time concern) |
| AML.TA0007 | Privilege Escalation | 🔶 (via IRFlow incident response) |
| AML.TA0008 | Defense Evasion | 🔶 (Module 3 obfuscation patterns) |
| AML.TA0009 | Credential Access | ❌ (classical auth, not AI-specific) |
| AML.TA0010 | Discovery | 🔶 (Module 3 system-prompt-reveal patterns) |
| AML.TA0011 | Collection | ✅ (Module 3 LLM06 patterns) |
| AML.TA0012 | ML Attack Staging | 🔶 (Module 4 IOCs) |
| AML.TA0013 | Exfiltration | ✅ (Module 3 + Module 4) |
| AML.TA0014 | Impact | 🔶 (via IRFlow incident playbooks) |

**Legend:**
- ✅ Primary coverage — direct detection
- 🔶 Partial — enrichment/IOC coverage but not direct detection
- ❌ Out of scope — handled by other platforms or offline

## Key techniques covered by VertGuard

### AML.T0051 — LLM Prompt Injection

**Tactic:** AML.TA0005 (Execution).

**VertGuard coverage:** Module 3 primary target. All patterns in
`rust/prompt-patterns/src/owasp_llm.rs` and `jailbreak.rs` map to
this technique (many to sub-technique `AML.T0051.000`).

**Sub-techniques:**

- `AML.T0051.000` — Direct prompt injection (Module 3 primary)
- `AML.T0051.001` — Indirect prompt injection (Module 3 `indirect.rs`)

### AML.T0057 — LLM Data Leakage

**Tactic:** AML.TA0011 (Collection).

**VertGuard coverage:** Module 3 patterns targeting information-exfil
attempts (`LLM06.*` patterns).

### AML.T0024 — Exfiltration via ML Inference API

**Tactic:** AML.TA0013 (Exfiltration).

**VertGuard coverage:** Module 4 provides IOCs for known extraction
probes. Module 3 detects specific prompts known to trigger model
disclosure.

### AML.T0043 — Craft Adversarial Data

**Tactic:** AML.TA0005 (Execution).

**VertGuard coverage:** Module 1 (Phase 4.2+) detects adversarial
perturbations in images/video.

### AML.T0020 — Poisoning Training Data

**Tactic:** AML.TA0006 (Persistence).

**VertGuard coverage:** ❌ out of scope (training-time concern).
Mentioned here to clarify that VertGuard does **not** protect against
training-data poisoning — that's a development-pipeline concern
(dataset curation, provenance verification).

## Sync cadence

ATLAS is ingested automatically:

- **Weekly full sync** (Sunday 00:00 UTC): fetch entire ATLAS
  framework; update local mapping table.
- **Daily delta sync** (06:00 UTC): fetch updates since last full
  sync.
- **On-demand sync** via `vertguard atlas sync` CLI command.

Sync source: MITRE ATLAS JSON export at `atlas.mitre.org/api/v1/`.
Updates flow through `internal/threatfeed/atlas.go` into the
`atlas_mappings` DB table.

## Versioning

MITRE publishes ATLAS in versioned releases. VertGuard's mapping is
pinned to a specific ATLAS version at release time and updated as
ATLAS evolves:

```yaml
atlas_version: "2026.Q2"
atlas_synced:  "2026-04-15T00:00:00Z"
```

Historical detections remain tagged with the ATLAS version active at
detection time — audit queries can reconstruct "what did we know at
the time?"

## Integration with ThreatFlow

Every AI-IOC pushed to ThreatFlow from VertGuard carries ATLAS
metadata. This enables:

- Cross-correlation: "Show me all incidents involving AML.T0051.001"
- Tactic-level queries: "What's our exposure to Defense Evasion
  (AML.TA0008) across the stack?"
- Incident enrichment: ATLAS context added to IRFlow incidents
  automatically when correlated via Module 4

## Example queries

### Find all patterns for a specific technique

```sql
SELECT id, description, base_score
FROM patterns
WHERE atlas_technique = 'AML.T0051.000';
```

### Find IOCs for a specific tactic

```sql
SELECT pattern_value, confidence, first_seen, last_seen
FROM threat_iocs
WHERE atlas_technique IN (
  SELECT technique_id FROM atlas_mappings WHERE tactic_id = 'AML.TA0005'
)
ORDER BY last_seen DESC;
```

### Coverage report — techniques with no VertGuard detection

```sql
SELECT am.technique_id, am.name, am.tactic_id
FROM atlas_mappings am
LEFT JOIN patterns p ON p.atlas_technique = am.technique_id
WHERE p.id IS NULL
ORDER BY am.tactic_id, am.technique_id;
```

This query drives the coverage-gap analysis — helps prioritise new
pattern development.

## Open items (Phase 4.1 scope)

- [ ] Full ATLAS framework ingestion (all techniques + tactics)
- [ ] Per-pattern ATLAS tagging in `rust/prompt-patterns`
- [ ] Coverage-gap report endpoint: `GET /api/v1/threatfeed/atlas/coverage`
- [ ] ATLAS version migration procedure documented
- [ ] Public dashboard visualisation of coverage matrix

## Related

- [module-4-ai-threat-feed.md](module-4-ai-threat-feed.md)
- [owasp-llm-top10-coverage.md](owasp-llm-top10-coverage.md)
- [threatflow-integration.md](threatflow-integration.md)
- [MITRE ATLAS](https://atlas.mitre.org/)
