# ADR-004: Mapping NIS2 Article 21(2) Measures to NIST CSF Categories

Date: 2026-03-25
Status: Accepted
Deciders: OpenSecStack core team

---

## Context

NIS2 Directive Article 21(2) defines ten cybersecurity risk-management measures (labelled a through j) that entities in scope must implement. The directive describes what must be achieved but does not prescribe a specific control framework for operationalising the measures. Security teams within assessed organisations work with a variety of existing frameworks (NIST CSF, ISO/IEC 27001, CIS Controls) and need the NIS2 requirements to be expressed in terms they already use.

NIS2 Compass needs a framework to:

1. Organise the ten measures in a way that is actionable and recognisable to security practitioners.
2. Enable reporting and dashboards that aggregate compliance posture across a meaningful structural dimension.
3. Support cross-organisation comparison of compliance posture across a shared taxonomy.
4. Enforce the mapping at the database level so that controls are consistently categorised.

The NIST Cybersecurity Framework (CSF) is organised around five functions: Identify, Protect, Detect, Respond, Recover. These five functions describe the full lifecycle of cybersecurity risk management and are widely understood internationally, including in Europe. The mapping from Article 21(2) measures to NIST CSF functions is not defined by the directive, but a defensible and consistent mapping can be derived from the purpose of each measure.

---

## Decision

Map each NIS2 Article 21(2) measure to one of the five NIST CSF functions. Enforce this mapping through the `nist_category` ENUM column on the `controls` and `control_templates` tables.

The ENUM is defined as:

```sql
CREATE TYPE nist_category AS ENUM ('identify', 'protect', 'detect', 'respond', 'recover');
```

---

## Mapping

| Measure | Article Reference | NIST CSF Function | Rationale |
|---|---|---|---|
| a | Art.21(2)(a) | Identify | Risk analysis and information security policies are the foundation of the Identify function, which covers asset management, risk assessment, and governance. Understanding risk is the prerequisite for all other functions. |
| b | Art.21(2)(b) | Respond | Incident handling is the Respond function by definition. The Respond function covers response planning, communications, analysis, mitigation, and improvements following a detected event. |
| c | Art.21(2)(c) | Recover | Business continuity and disaster recovery are the Recover function. The Recover function covers recovery planning, improvements, and communications to restore capabilities after a disruption. |
| d | Art.21(2)(d) | Identify | Supply chain security is primarily an asset and dependency identification concern. Understanding and assessing third-party risk is part of the Identify function's coverage of the supply chain and external dependencies. |
| e | Art.21(2)(e) | Protect | Network and information systems security, including vulnerability management and technical hardening, are Protect function activities. The Protect function covers access control, awareness, data security, protective technology, and maintenance. |
| f | Art.21(2)(f) | Identify | Policies and procedures for assessing the effectiveness of cybersecurity risk-management measures feed back directly into risk understanding. Continuous assessment is part of the Identify function's risk assessment subprocess. |
| g | Art.21(2)(g) | Protect | Cyber hygiene practices and cybersecurity training reduce the attack surface and improve the human element of security. Training, awareness, and hygiene are Protect function activities under the Awareness and Training category. |
| h | Art.21(2)(h) | Protect | Cryptography and encryption are protective controls. Encryption of data at rest and in transit, key management, and certificate policies are Protect function activities under the Data Security category. |
| i | Art.21(2)(i) | Protect | Human resources security, access control policies, and asset management are Protect function activities. Identity management, authentication policy, and asset lifecycle management all fall under the Protect function. |
| j | Art.21(2)(j) | Protect | Multi-factor authentication (MFA) and continuous authentication are authentication controls. Authentication enforcement is a Protect function activity under the Identity Management and Access Control category. |

---

## Reasons

**NIST CSF is widely adopted and understood**: The NIST CSF is used as a reference framework by security teams globally, including in European organisations. Its five-function structure is simple enough to communicate to non-technical stakeholders while being detailed enough to guide technical implementation.

**The five-function structure maps cleanly to Article 21(2)**: The ten Article 21(2) measures distribute across the five NIST CSF functions without forced or ambiguous assignments. No measure spans two functions; each measure has a clear primary function. The concentration of measures in the Protect function (five of ten) reflects the directive's emphasis on preventive technical and organisational controls.

**DB-level enforcement prevents inconsistency**: By encoding the mapping as a PostgreSQL ENUM on the `nist_category` column, the database rejects any attempt to insert a control with an invalid category. This ensures that all reporting and aggregation queries can rely on the category values being from the defined set.

**Enables aggregate compliance posture by NIST function**: Dashboards and reports can group controls by `nist_category` to show compliance posture across the Identify / Protect / Detect / Respond / Recover lifecycle. An organisation with strong Protect scores but weak Identify scores has a different risk posture from one with the inverse pattern, and this distinction is meaningful to security leadership.

---

## Alternatives Considered

**ISO/IEC 27001 control mapping**: Considered as the primary mapping instead of NIST CSF. ISO 27001 Annex A provides a detailed control catalogue that maps well to NIS2 requirements. It was not chosen as the primary mapping because: (a) ISO 27001 Annex A contains 93 controls (2022 revision), which is significantly more granular than the five NIST CSF functions — a primary mapping at that level of granularity would require a more complex `nist_category` equivalent; (b) NIST CSF's five-function structure is a better fit for the high-level organisational reporting that NIS2 Compass dashboards provide. ISO 27001 mapping is under consideration as a secondary tag on controls in a future enhancement.

**ENISA's own NIS2 guidelines framework**: ENISA has published guidance on implementing Article 21 measures. A mapping to ENISA's own categories was considered but not chosen because ENISA's categorisation closely mirrors the Article 21(2) measures themselves (i.e., it does not add a structurally different organising dimension). Using NIST CSF adds more analytical value by translating the directive's language into a framework security teams actively work with.

**No mapping (store article reference only)**: Rejected. Storing only the `article_ref` (e.g., `Art.21(2)(a)`) provides traceability to the directive but no cross-framework analytical dimension. Organisations use different frameworks; a mapping enables NIS2 Compass findings to be contextualised within those frameworks. The absence of a mapping reduces the platform's utility as a reporting and decision-support tool.

---

## Consequences

- The `nist_category` ENUM is a permanent part of the schema. Changing a measure's assigned NIST function requires a data migration that updates all `controls` and `control_templates` rows for that measure.
- The `control_templates` seed data (`seeds/01_nis2_controls.py`) must assign the correct `nist_category` value to each of the ten control templates. The mapping in this ADR is the authoritative reference for those values.
- Dashboard queries that group by `nist_category` will reflect this mapping. If the mapping is revised in a future ADR, existing historical controls will retain their original category values unless explicitly migrated.
- Adding a new NIST CSF function (e.g., if NIST CSF v3 introduces a sixth function) requires an ENUM `ALTER TYPE ADD VALUE` migration and a corresponding update to this ADR.
- The `detect` and `respond` ENUM values are present in the schema but assigned to only one measure each (Art.21(2) does not have a strong detection-focused measure in the same way it has protection-focused ones). Queries and dashboards must handle the expected asymmetry in control counts across NIST functions.
