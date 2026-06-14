---
id: 02-ti-operations
order: 2
duration_minutes: 90
---

# Lesson 2: Intelligence Operations — STIX/TAXII, ThreatFlow, and Analytical Tradecraft

## STIX and TAXII: the sharing standards

STIX (Structured Threat Information eXpression) and TAXII (Trusted Automated eXchange of Intelligence Information) are the dominant standards for machine-readable threat intelligence sharing.

STIX 2.1 represents intelligence as a graph of typed JSON objects called STIX Domain Objects (SDOs) and STIX Relationship Objects (SROs). The primary SDO types you will work with are:

| SDO Type | Description |
|---|---|
| `indicator` | A pattern (in STIX Pattern Language) that, if matched in telemetry, indicates adversary activity |
| `malware` | A malware specimen description: name, family, capabilities |
| `threat-actor` | A named adversary group with motivation, sophistication, and target sector attributes |
| `attack-pattern` | A TTP, linked to a MITRE ATT&CK technique via `external_references` |
| `campaign` | A named set of adversary activity linked to threat actors and techniques |
| `course-of-action` | A defensive measure recommended in response to the threat |
| `relationship` | An SRO linking two SDOs — e.g., "indicator *indicates* malware" |

A STIX Bundle is the container format: a JSON object with `type: bundle` containing a list of STIX objects. Bundles are the unit of exchange over TAXII.

```json
{
  "type": "bundle",
  "id": "bundle--e9a4d8f0-3b1c-4a2e-9f72-d3c8b0e4a1f5",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--4a2d8f0e-1b3c-4e2a-9f72-d3c8b0e4a1f5",
      "name": "Cobalt Strike beacon C2 domain",
      "indicator_types": ["malicious-activity"],
      "pattern": "[domain-name:value = 'update.sys-analytics.net']",
      "pattern_type": "stix",
      "valid_from": "2026-04-01T00:00:00Z",
      "labels": ["TLP:AMBER"]
    }
  ]
}
```

TAXII 2.1 defines the API for serving and consuming STIX bundles. A TAXII server exposes Collections — named groups of STIX objects. Consumers poll collections via authenticated HTTP GET requests; producers push new objects via authenticated HTTP POST. ThreatFlow implements a full TAXII 2.1 server, enabling organisations to share intelligence directly with partners or subscribe to external TAXII feeds from government CSIRTs and commercial providers.

## Source quality and confidence assessment

Not all threat intelligence is equal. A critical analytical skill is assessing the reliability of a source and the credibility of its reporting. The Admiral's Format (originating from NATO intelligence doctrine) provides two dimensions:

**Source reliability** (A through F):
- A — Completely reliable: no doubt about authenticity, trustworthiness, and competence
- B — Usually reliable: minor doubt about past accuracy
- C — Fairly reliable: doubt, but has provided valid information before
- D — Not usually reliable: significant doubt about past accuracy
- E — Unreliable: lacks authenticity or trustworthiness
- F — Cannot be judged: insufficient basis to evaluate

**Information credibility** (1 through 6):
- 1 — Confirmed by other sources
- 2 — Probably true (corroborated by other information)
- 3 — Possibly true (unconfirmed but plausible)
- 4 — Doubtful (no corroboration; logical but plausible)
- 5 — Improbable (contradicts other information)
- 6 — Cannot be judged

In ThreatFlow, every intelligence item carries a confidence score (0–100) derived from source reliability and credibility assessments. The platform aggregates confidence across corroborating items: an IP address seen in two A1 intelligence reports scores much higher than the same IP appearing in a single D4 report.

## Analytical tradecraft: avoiding cognitive biases

Threat intelligence analysis is a cognitive process susceptible to systematic biases that degrade the quality of finished products. The three most consequential biases in threat intelligence work are:

**Confirmation bias** — The tendency to seek and accept information that confirms existing beliefs, and to discount contradicting evidence. Analysts attribute new campaigns to known threat groups prematurely. Counter-measure: apply the ACH (Analysis of Competing Hypotheses) method: explicitly enumerate all plausible hypotheses, list evidence for and against each, and score accordingly.

**Mirror imaging** — Assuming the adversary thinks and acts as we do: applies our own cultural, organisational, or technical framework to predict adversary behaviour. Counter-measure: study adversary-specific doctrine, published TTPs, and historical campaign reports rather than projecting defensive priorities onto offensive planning.

**Anchoring** — Excessive reliance on the first piece of information received. An initial attribution to Threat Actor X shapes all subsequent analysis, even when contradicting evidence accumulates. Counter-measure: delay attribution until a minimum evidence threshold is met; treat early indicators as hypotheses rather than conclusions.

## Working with ThreatFlow: enrichment and correlation

ThreatFlow is the opensecstack ecosystem's threat intelligence aggregation and enrichment platform. It ingests from multiple source types — TAXII feeds, MISP instances, OSINT RSS collectors, direct API integrations — and exposes a unified API for enrichment queries and intelligence search.

The core workflow in ThreatFlow for an IR analyst or threat hunter is the enrichment query: given an observable (an IP, domain, hash, or URL observed in telemetry), retrieve all associated intelligence:

```bash
# Enrich an IP observable observed in SIEM telemetry
threatflow enrich --type ipv4 --value 185.220.101.47

# Enrich a file hash
threatflow enrich --type sha256 --value a3f1d2e4b8c7f09e3a1d2b4c8f7e09a3

# Search for all STIX indicators matching a domain pattern
threatflow search --pattern "domain-name:value = 'update.sys-analytics.net'"

# Get all ATT&CK techniques associated with a threat actor
threatflow actor --name "APT29" --techniques
```

The enrichment response includes all associated intelligence items, their confidence scores, TLP classifications, source attributions, and STIX relationships — giving the analyst a structured picture of the observable's threat context within seconds, rather than requiring manual correlation across multiple external sources.

## Dissemination: right intelligence to the right audience

Finished intelligence products differ by audience and format. The three primary dissemination targets in a NIS2-scope organisation are:

1. **SOC detection engineers** — Receive STIX indicators and ATT&CK-mapped detection rules that can be directly imported into SIEM or EDR platforms. ThreatFlow exports in Sigma, YARA, and STIX Pattern formats.
2. **IR team / CSIRT** — Receive tactical reports describing current campaign TTPs, affected sectors, and recommended containment actions. ThreatFlow generates PDF and structured JSON tactical reports.
3. **Management / CISO** — Receive strategic briefings contextualising the threat landscape relevant to the organisation's sector and geography. ThreatFlow's strategic summary view aggregates threat actor activity by sector targeting.

NIS2 Article 26 encourages voluntary sharing of threat intelligence between entities and with CSIRTs. ThreatFlow's TAXII 2.1 server interface enables direct integration with the national CSIRT's intelligence sharing infrastructure, facilitating the structured sharing that NIS2 Article 21(2)(b) expects from incident handling teams.
