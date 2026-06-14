# ADR-003: MITRE ATT&CK as Primary Classification Framework

**Status**: Accepted  
**Date**: 2026-05-10  
**Deciders**: SecureLab core team

## Context

SecureLab needs a framework for classifying attack techniques. The framework serves three purposes:

1. **Coverage tracking**: which techniques has the organization tested, and which have confirmed detections?
2. **Gap reporting**: which techniques are in scope but have no test or no confirmed detection?
3. **Communication with stakeholders**: a shared vocabulary for security engineers, management, and regulators.

Several frameworks exist. We need to choose one as the primary classification and justify the choice.

## Decision

Use **MITRE ATT&CK** (Enterprise matrix, v14+) as the primary classification framework for all SecureLab scenarios and coverage reporting.

Every scenario YAML file must include at least one `mitre_technique_ids` value. Coverage reports reference ATT&CK technique IDs. The CITADEL `securelab.run_completed` event includes ATT&CK technique IDs.

## Alternatives considered

### OWASP Top 10 / OWASP API Security Top 10

- Pro: well-known, used by developers and AppSec teams
- Pro: directly relevant to the API attack scenarios SecureLab ships
- Con: limited to application security — does not cover network, lateral movement, exfil, or persistence
- Con: not a structured technique taxonomy — categories, not techniques
- Con: not updated frequently enough to cover new attack patterns

**Resolution**: OWASP categories are retained as optional tags (e.g. `owasp-a1`, `owasp-api-top10`) but are not the primary classification.

### Lockheed Martin Cyber Kill Chain

- Pro: simple, 7-stage model
- Con: high-level — does not map to specific techniques
- Con: less widely supported by detection platforms and SIEM systems
- Con: no community-maintained technique database

### Custom SecureLab taxonomy

- Pro: can be optimized for our specific attack library
- Con: requires maintenance
- Con: not recognized by stakeholders outside the platform
- Con: cannot produce reports that map to detection platform coverage

### MITRE ATT&CK (chosen)

- Pro: industry standard — accepted by detection platform vendors, SIEM vendors, and regulators (NIS2, NIST CSF)
- Pro: maintained by MITRE with regular updates covering new techniques
- Pro: sub-technique IDs allow precise classification (e.g. `T1078.001` vs `T1078`)
- Pro: ATT&CK Navigator layer export allows coverage visualization
- Pro: detection platforms (OpenScrub, APIGuard, ThreatFlow) already tag alerts with ATT&CK IDs
- Con: the full matrix is large — not all techniques are testable by SecureLab
- Con: sub-technique coverage requires careful mapping

## Rationale

MITRE ATT&CK is the de facto industry standard for attack classification. Using it as SecureLab's primary framework means:

- Coverage reports are immediately understandable to any security professional.
- Coverage gaps can be communicated to regulators (NIS2 Article 21) without translation.
- Detection platform alerts can be cross-referenced with scenario results using the same vocabulary.
- The community can contribute scenarios for specific ATT&CK techniques that are missing from the library.

## Consequences

- Every scenario YAML must include at least one `mitre_technique_ids` value. Scenarios without this field fail validation.
- The coverage API (`GET /api/v1/coverage`) is organized by ATT&CK technique ID.
- ATT&CK Navigator layer export is a first-class feature of the coverage report.
- CITADEL `securelab.run_completed` events include the technique IDs from the executed scenario.
- SecureLab tracks the ATT&CK matrix version. When MITRE publishes a new matrix version, a new technique coverage review issue is opened.
- OWASP Top 10 and OWASP API Top 10 categories are supported as optional tags but are secondary to ATT&CK classification.
