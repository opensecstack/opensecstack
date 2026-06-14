# NIS2 Compass — NIS2 Article 21(2) Controls Reference

This document is the canonical reference for the ten cybersecurity risk-management measures defined in Article 21(2) of the NIS2 Directive (Directive 2022/2555). It is intended for use by assessors conducting NIS2 Compass assessments, compliance managers reviewing assessment findings, and legal or regulatory teams preparing evidence for competent authorities.

---

## Introduction

Article 21(2) of the NIS2 Directive requires essential and important entities to take appropriate and proportionate technical, operational, and organisational measures to manage risks posed to the security of network and information systems. The article enumerates ten distinct measures, labelled (a) through (j), each addressing a specific domain of cybersecurity risk management.

NIS2 Compass maps each measure to a corresponding category from the NIST Cybersecurity Framework (CSF). This mapping allows organisations to align their EU regulatory obligations with a widely adopted security framework, facilitating integration with existing NIST-based programmes, gap analyses, and control libraries.

The ten measures are not presented in priority order — all are mandatory for entities within scope. National competent authorities may weight certain measures more heavily during supervisory examinations depending on sector-specific guidance, but all ten must be addressed in any complete NIS2 assessment.

---

## NIST CSF Mapping Overview

| Measure | Article Ref | Title | NIST CSF Category |
|---|---|---|---|
| a | Art.21(2)(a) | Risk Analysis & Information Security Policies | Identify |
| b | Art.21(2)(b) | Incident Handling | Respond |
| c | Art.21(2)(c) | Business Continuity & Disaster Recovery | Recover |
| d | Art.21(2)(d) | Supply Chain Security | Identify |
| e | Art.21(2)(e) | Network & Information Systems Security | Protect |
| f | Art.21(2)(f) | Effectiveness Assessment Policies | Identify |
| g | Art.21(2)(g) | Cyber Hygiene & Cybersecurity Training | Protect |
| h | Art.21(2)(h) | Cryptography & Encryption Policies | Protect |
| i | Art.21(2)(i) | HR Security, Access Control & Asset Management | Protect |
| j | Art.21(2)(j) | Multi-Factor Authentication & Continuous Authentication | Protect |

---

## Measure a — Risk Analysis & Information Security Policies

**Article reference:** Art.21(2)(a)
**NIST CSF category:** Identify

### Directive requirement

Organisations must establish and maintain documented policies for information security that are approved by management and communicated across the entity. A systematic risk analysis process must identify threats, vulnerabilities, and impacts relevant to network and information systems. Risk treatment decisions must be recorded and reviewed at planned intervals or following significant changes. Policies must define the scope, objectives, roles, and responsibilities for managing cybersecurity risk.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a current, management-approved information security policy exists alongside a documented risk register reviewed within the past 12 months. Set to `partially_compliant` if a policy or risk register exists but is outdated, unapproved, or incomplete in scope. Set to `non_compliant` if no formal policy or risk register is in place.
- **evidence**: Reference the policy document identifier, the date of the most recent management approval, and the risk register identifier. Include an artifact hash if the policy has been uploaded to the platform.
- **gap_description**: If gaps exist, document specifically whether the shortfall is in the policy document itself (missing content, unapproved), the risk analysis process (not performed, not documented, not current), or the review cadence (no scheduled review cycle).

### Common compliance evidence

- Information Security Policy document with management sign-off and version history.
- Risk register or risk treatment plan, dated and attributed to a named risk owner.
- Risk assessment methodology documentation (e.g., aligned to ISO/IEC 27001 clause 6.1 or NIST SP 800-30).
- Minutes of management review meetings at which cybersecurity risk was discussed.
- Documented risk appetite and tolerance thresholds approved by senior leadership or the board.
- Evidence of policy communication to staff (email distribution lists, intranet publication records, training acknowledgements).

### Key questions for assessors

- Is the information security policy a standalone, current document with an identified owner and a defined review cycle, or is it embedded in a larger generic document and rarely updated?
- Does the risk analysis process produce a documented output (risk register) and does that output include network and information system-specific risks relevant to the organisation's NIS2 sector?
- Has senior management formally approved the risk analysis outcomes, including acceptance of residual risks?
- Is there evidence that the risk register has been updated following significant architectural changes, major incidents, or changes in the threat landscape within the past 12 months?

### Typical findings

**Partial compliance:** A policy document exists but predates the NIS2 Directive by several years, has not been reviewed, or lacks explicit reference to the entity's NIS2 obligations. A risk register exists but lists generic IT risks without mapping to critical NIS2-in-scope systems or services.

**Non-compliance:** No documented information security policy. Risk analysis is performed informally without a written record. No ownership of cybersecurity risk at management level.

---

## Measure b — Incident Handling

**Article reference:** Art.21(2)(b)
**NIST CSF category:** Respond

### Directive requirement

Entities must implement procedures for detecting, reporting, analysing, and responding to cybersecurity incidents in a timely manner. An incident response plan must define roles, communication chains, and escalation paths including mandatory notification to the competent national authority or CSIRT within NIS2-mandated timeframes: early warning within 24 hours of becoming aware of a significant incident, full notification within 72 hours, and a final report within one month. Post-incident reviews must identify root causes and prevent recurrence. Records of all incidents and responses must be retained for audit purposes.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a tested incident response plan exists with documented NIS2 notification procedures, evidence of exercises, and incident records. Set to `partially_compliant` if a plan exists but has not been tested, lacks NIS2-specific notification thresholds, or has no records of exercises or incidents. Set to `non_compliant` if no incident response plan is in place.
- **evidence**: Reference the incident response plan identifier, the date of the most recent tabletop exercise or live incident, and any CSIRT or national authority notification records. Reference post-incident review reports if available.
- **gap_description**: Specify whether the gap is in plan existence, NIS2 notification mapping, testing cadence, or record retention.

### Common compliance evidence

- Incident Response Plan document, versioned and management-approved.
- Incident classification matrix mapping severity levels to NIS2 notification thresholds.
- Records of tabletop exercises or incident response drills (at least twice per year is recommended).
- Evidence of CSIRT or national competent authority notifications (redacted if necessary for sensitivity reasons).
- Post-incident review reports for significant incidents.
- Security incident register or ticketing system export covering the assessment period.

### Key questions for assessors

- Does the incident response plan explicitly reference NIS2 notification obligations (24-hour early warning, 72-hour full notification) and identify who is responsible for making those notifications?
- Has the incident response plan been exercised within the past 12 months, and are there records of the exercise outcomes and any resulting plan updates?
- Does the organisation have a current contact for the relevant national CSIRT or competent authority, and is the reporting mechanism understood and documented?
- Are post-incident reviews consistently conducted after significant events, and are lessons learned tracked to closure?

### Typical findings

**Partial compliance:** An incident response plan exists but was produced before NIS2 came into force and does not reflect mandatory notification timeframes. The plan has never been exercised, or exercises have not been conducted in over 12 months. Incident records exist but are informal and lack consistent classification.

**Non-compliance:** No documented incident response plan. Incident response is entirely ad hoc. No contact details or procedures for national authority or CSIRT notification. No records of past incidents or responses maintained.

---

## Measure c — Business Continuity & Disaster Recovery

**Article reference:** Art.21(2)(c)
**NIST CSF category:** Recover

### Directive requirement

Entities must implement business continuity management (BCM) and disaster recovery (DR) capabilities to ensure the resilience of critical services during and after a disruptive event. Business impact analyses must identify recovery time objectives (RTO) and recovery point objectives (RPO) for essential functions. Tested backup procedures must ensure data integrity and availability can be restored within defined timeframes. Crisis management plans must address communication strategies, fallback operations, and stakeholder engagement during prolonged outages.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a tested BCP and DR plan exist with documented and validated RTOs/RPOs, backup test evidence, and crisis communication procedures. Set to `partially_compliant` if plans exist but have gaps in testing, incomplete RTO/RPO definitions, or untested backups. Set to `non_compliant` if no BCM or DR plans exist, or backups are not tested.
- **evidence**: Reference the BCP and DR plan identifiers, the date of the most recent DR test, backup test logs, and business impact analysis documentation.
- **gap_description**: Note whether gaps are in plan completeness, test cadence, backup integrity, offline copy availability, or third-party dependency documentation.

### Common compliance evidence

- Business Continuity Plan (BCP) and Disaster Recovery Plan (DRP), both versioned and approved.
- Business Impact Analysis (BIA) with documented RTOs and RPOs for critical services.
- Backup test logs demonstrating successful restoration within defined RTOs/RPOs (tested at least annually for full DR; quarterly for partial tests).
- Evidence of offline or air-gapped backup copies not accessible from the production environment.
- Crisis communication plan and contact lists.
- Evidence that third-party provider dependencies are documented within the BCP.

### Key questions for assessors

- Has a business impact analysis been conducted that identifies RTOs and RPOs for all NIS2-in-scope services, and are these figures formally agreed with service owners?
- When was the DR plan last tested end-to-end, and were the results — including any failures — formally documented and remediated?
- Are backup copies stored in a location and manner that would survive a ransomware attack (i.e., offline or air-gapped from the production environment)?
- Does the BCP document dependencies on critical third-party providers, and has the entity verified that those providers have compatible recovery capabilities?

### Typical findings

**Partial compliance:** BCP and DR plans exist but RTOs/RPOs are aspirational rather than validated through testing. Backup procedures are documented but the most recent restoration test is more than 12 months old. Backup copies are accessible from the production network, creating ransomware exposure.

**Non-compliance:** No documented BCP or DR plan. Backups are taken but never tested. No documented crisis communication procedures. Recovery capabilities have never been evaluated against a disruption scenario.

---

## Measure d — Supply Chain Security

**Article reference:** Art.21(2)(d)
**NIST CSF category:** Identify

### Directive requirement

Entities must manage cybersecurity risks arising from relationships with direct suppliers and service providers who have access to their network and information systems. A supply chain risk management policy must cover vendor assessment, contractual security requirements, and ongoing monitoring. Security requirements must be flowed down to sub-processors where relevant. Entities must evaluate the overall security posture of the supply chain, including the development and maintenance practices of software components in use.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a supplier inventory exists, cybersecurity clauses are present in relevant contracts, vendor risk assessments are conducted, and ongoing monitoring is in place. Set to `partially_compliant` if some suppliers are assessed or have contractual clauses but the programme is incomplete or not consistently applied. Set to `non_compliant` if no supply chain security programme exists.
- **evidence**: Reference the supplier register identifier, example contractual clauses or standard supplier security questionnaire, and any recent third-party audit or assessment reports received from key suppliers.
- **gap_description**: Document which supplier categories lack assessment, where contractual clauses are absent, or where monitoring is inadequate.

### Common compliance evidence

- Supplier and third-party inventory listing all providers with access to NIS2-in-scope systems.
- Supply chain risk management policy, including vendor classification criteria.
- Contractual security clauses from representative supplier agreements (e.g., right-to-audit, incident notification obligations, SBOM provision).
- Completed vendor security questionnaires or assessment reports for critical suppliers.
- Evidence of periodic supplier risk reviews, including documentation of changes in supplier posture.
- Software Bill of Materials (SBOM) for critical software components where available.

### Key questions for assessors

- Does the organisation maintain an inventory of all third-party suppliers and service providers with access to NIS2-in-scope systems, classified by criticality?
- Do contracts with critical suppliers include explicit cybersecurity obligations — including incident notification, security audit rights, and data handling requirements — and are these clauses consistently applied to new and existing contracts?
- Has the organisation conducted or reviewed a security assessment of its most critical suppliers within the past 12 months?
- Is there a process for monitoring and responding to threat intelligence relating to supply chain compromise, such as tracking vulnerabilities in third-party software components?

### Typical findings

**Partial compliance:** A supplier list exists but has not been assessed for cybersecurity risk. Some contracts include security clauses but they were not consistently applied across the supplier base. No formal process for ongoing monitoring of supplier security posture.

**Non-compliance:** No supplier inventory. No contractual cybersecurity requirements imposed on third parties. Third-party access to critical systems is managed informally with no security evaluation of providers.

---

## Measure e — Network & Information Systems Security

**Article reference:** Art.21(2)(e)
**NIST CSF category:** Protect

### Directive requirement

Entities must implement technical and organisational measures to secure the acquisition, development, and maintenance of network and information systems, including vulnerability handling and disclosure. Secure-by-design principles must be applied to new system development, and hardening baselines must be defined for infrastructure components. Patch management processes must ensure timely remediation of known vulnerabilities based on criticality. Network segmentation and monitoring must limit the blast radius of potential compromises.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a documented vulnerability management programme is in place, hardening baselines are defined and applied, patching is tracked and timely, and network segmentation and monitoring are deployed. Set to `partially_compliant` if some elements are in place but gaps exist in coverage, cadence, or documentation. Set to `non_compliant` if no formal vulnerability management or patching programme exists.
- **evidence**: Reference the vulnerability management policy, patch compliance metrics or dashboards, hardening baseline documents, and network architecture diagrams showing segmentation.
- **gap_description**: Specify whether gaps relate to patch timeliness, hardening coverage, monitoring capability, secure development practices, or network segmentation.

### Common compliance evidence

- Vulnerability management policy and process documentation, including CVSS-based prioritisation criteria.
- Patch compliance reports or dashboard exports for the assessment period.
- Hardening baseline documents for key infrastructure components (servers, endpoints, network devices, cloud services).
- Network architecture diagram showing segmentation zones and monitoring points.
- Evidence of intrusion detection or prevention system (IDS/IPS) deployment.
- Secure software development lifecycle (SSDLC) documentation or secure coding standards.
- Firewall rule review records (recommended quarterly).

### Key questions for assessors

- Does the organisation have a defined vulnerability management programme with documented SLAs for patching critical vulnerabilities (e.g., CVSS 9.0+ within 7 days, 7.0-8.9 within 30 days)?
- Are hardening baselines defined for all major infrastructure component types, and is compliance with those baselines verified and tracked?
- Is the network segmented in a manner that limits lateral movement in the event of a compromise of a single zone, and are inter-zone communications controlled and monitored?
- Are intrusion detection and prevention capabilities deployed and are their alerts actively reviewed and actioned?

### Typical findings

**Partial compliance:** A patching process exists but is not consistently followed; critical vulnerability remediation frequently exceeds defined SLAs. Hardening baselines are defined for some infrastructure types but not consistently applied. Network segmentation exists at the perimeter but not between internal zones.

**Non-compliance:** No formal patch management programme. Vulnerabilities are remediated reactively only. No hardening baselines. Flat network with no internal segmentation. No intrusion detection capability.

---

## Measure f — Effectiveness Assessment Policies

**Article reference:** Art.21(2)(f)
**NIST CSF category:** Identify

### Directive requirement

Entities must establish policies and procedures to assess the effectiveness of cybersecurity risk management measures on a continuous or periodic basis. Assessments must include internal audits, penetration testing, and vulnerability scanning at intervals commensurate with the entity's risk profile. Results must be reported to management and used to drive improvement. Metrics and key performance indicators (KPIs) for cybersecurity effectiveness must be defined and tracked over time.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a formal effectiveness assessment programme exists with defined KPIs, regular penetration testing, internal audits, and documented management reporting. Set to `partially_compliant` if some testing or auditing occurs but is not systematic, results are not consistently reported to management, or KPIs are not defined. Set to `non_compliant` if no formal effectiveness assessment programme exists.
- **evidence**: Reference the effectiveness assessment policy, most recent penetration test report (executive summary), internal audit reports, and KPI dashboards or reports presented to management.
- **gap_description**: Note whether gaps are in the frequency of testing, the independence of testing, management reporting, or KPI definition and tracking.

### Common compliance evidence

- Effectiveness assessment policy defining types, frequency, and scope of assessments.
- Independent penetration test reports (at least annual) with remediation tracking.
- Internal audit reports covering cybersecurity controls.
- Vulnerability scan reports from continuous or periodic automated scanning.
- Security KPI report or dashboard presented to management (e.g., mean time to detect, patch compliance rate, phishing simulation click rates).
- Evidence of management review meetings at which cybersecurity KPIs and assessment results were discussed.

### Key questions for assessors

- Does the organisation commission independent penetration tests at least annually, covering both external attack surface and, where relevant, internal network penetration?
- Are the results of penetration tests and internal audits formally reported to senior management and tracked through to remediation?
- Has the organisation defined a set of measurable cybersecurity KPIs, and are these reported to the board or equivalent governing body at regular intervals?
- Is continuous automated scanning used to supplement point-in-time assessments, and are its outputs integrated with the vulnerability management programme?

### Typical findings

**Partial compliance:** Penetration tests are conducted but findings are not consistently remediated or tracked, and results are not reported to senior management. KPIs exist on paper but are not regularly computed or presented. Internal audits cover financial controls but rarely address cybersecurity.

**Non-compliance:** No penetration testing programme. Security assessments are entirely self-assessed without independent validation. No cybersecurity KPIs defined or tracked. No formal management reporting on cybersecurity effectiveness.

---

## Measure g — Cyber Hygiene & Cybersecurity Training

**Article reference:** Art.21(2)(g)
**NIST CSF category:** Protect

### Directive requirement

Entities must implement basic cyber hygiene practices across the organisation and ensure all staff receive role-appropriate cybersecurity awareness training. Training programmes must be regularly updated to reflect the current threat landscape and include practical components such as phishing simulations. Management and board members must receive targeted training on their cybersecurity governance responsibilities under NIS2. Records of completed training must be maintained and used to identify gaps.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a mandatory, role-differentiated training programme with documented completion records exists, phishing simulations are conducted, and management/board training on NIS2 governance has been delivered. Set to `partially_compliant` if training exists but is inconsistently delivered, not tracked, or does not cover management governance obligations. Set to `non_compliant` if no cybersecurity training programme is in place.
- **evidence**: Reference the training programme specification, completion rate reports for the current and prior year, phishing simulation results, and any management or board-level NIS2 briefing records.
- **gap_description**: Document specific gaps: low completion rates, absence of management training, outdated training content, or lack of phishing simulation.

### Common compliance evidence

- Cybersecurity awareness training programme curriculum and delivery plan.
- Training completion rate reports by department or role category.
- Phishing simulation campaign results and trend data over time.
- Records of management and board cybersecurity briefings or training sessions.
- Specialised technical training records for IT and security staff.
- Evidence of training content updates reflecting current threats (e.g., updated module dates, change log).

### Key questions for assessors

- Is mandatory cybersecurity awareness training delivered to all employees at least annually, and is there a documented process for following up with non-completers?
- Have board members and senior management received specific training on their cybersecurity governance responsibilities under NIS2, as distinct from general IT security awareness?
- Are phishing simulations conducted at regular intervals, and are the results used to identify individuals or teams requiring additional targeted training?
- Is the training curriculum reviewed and updated at least annually to incorporate emerging threats relevant to the organisation's sector?

### Typical findings

**Partial compliance:** Annual awareness training is delivered but completion is not tracked rigorously, resulting in significant portions of staff not completing it. Management have received general security briefings but not NIS2-specific governance training. Phishing simulations are conducted infrequently or their results are not used to drive follow-up actions.

**Non-compliance:** No formal cybersecurity awareness training programme. Security guidance is limited to an acceptable use policy that staff are required to sign on joining. No phishing simulation programme. No records of management cybersecurity training.

---

## Measure h — Cryptography & Encryption Policies

**Article reference:** Art.21(2)(h)
**NIST CSF category:** Protect

### Directive requirement

Entities must adopt and maintain policies on the use of cryptography and, where appropriate, encryption to protect the confidentiality, integrity, and authenticity of data in transit and at rest. Cryptographic standards must be reviewed periodically to ensure they remain fit for purpose against current and emerging threats, including post-quantum considerations. Key management procedures must govern the generation, storage, rotation, and destruction of cryptographic material. Deprecated algorithms and protocols (e.g., MD5, RC4, TLS 1.0/1.1) must be identified and phased out.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if a current cryptography policy exists with an approved algorithm registry, key management procedures, and documented elimination of deprecated protocols. Set to `partially_compliant` if a policy exists but does not cover all required areas, key management is informal, or deprecated algorithms remain in use in some systems. Set to `non_compliant` if no cryptography policy exists, data is transmitted or stored without encryption, or deprecated protocols are in widespread use.
- **evidence**: Reference the cryptography policy document, the approved algorithm registry, key management procedure documentation, and any configuration scanning or audit reports identifying cryptographic posture.
- **gap_description**: Note which specific areas are deficient: missing policy, informal key management, deprecated algorithm use, absence of post-quantum considerations, or weak TLS configurations.

### Common compliance evidence

- Cryptography policy document defining requirements for data in transit and at rest.
- Approved cryptographic algorithm registry specifying permitted cipher suites, hash functions, and key lengths.
- Key management policy and procedures covering generation, storage, rotation, expiry, and destruction.
- Evidence of a key management system (KMS) or hardware security module (HSM) for high-value keys.
- TLS configuration scan results demonstrating removal of TLS 1.0/1.1 and weak cipher suites.
- Documentation of post-quantum migration planning or roadmap.
- Records of periodic cryptographic standard reviews.

### Key questions for assessors

- Does the organisation have a current cryptography policy that explicitly defines requirements for encryption of sensitive data in transit and at rest, and has it been reviewed within the past 12 months?
- Are deprecated protocols (TLS 1.0, TLS 1.1, SSL, MD5, RC4, SHA-1 for signing) absent from all production systems, and is this verified through automated configuration scanning?
- Are key management procedures formal and documented, including defined key rotation schedules and secure key destruction processes?
- Has the organisation begun tracking post-quantum cryptography migration requirements in line with NIST PQC standards (FIPS 203, 204, 205)?

### Typical findings

**Partial compliance:** A cryptography policy exists but does not cover all data types or use cases. TLS 1.2 is enforced on public-facing services but legacy internal systems still support TLS 1.0. Key management is partially formalised but rotation schedules are not consistently followed. Post-quantum migration has not been considered.

**Non-compliance:** No cryptography policy. Sensitive data is transmitted over unencrypted channels in some contexts. Encryption at rest is not applied to critical data stores. No key management procedures; cryptographic keys are managed informally without rotation.

---

## Measure i — HR Security, Access Control & Asset Management

**Article reference:** Art.21(2)(i)
**NIST CSF category:** Protect

### Directive requirement

Entities must implement human resources security measures covering pre-employment screening, onboarding, role changes, and offboarding. Access control policies must enforce least-privilege and need-to-know principles, with privileged access subject to additional controls and regular review. A comprehensive asset inventory must be maintained covering hardware, software, data, and cloud services. Asset owners must be assigned, and asset classification must guide the application of appropriate security controls throughout the asset lifecycle.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if HR security procedures are documented and followed, access reviews are conducted at defined intervals, privileged access is controlled and audited, and an up-to-date asset inventory exists with assigned ownership. Set to `partially_compliant` if some elements are in place but processes are inconsistently applied, access reviews are overdue, or the asset inventory is incomplete. Set to `non_compliant` if HR security procedures are absent, access is not reviewed, or no asset inventory exists.
- **evidence**: Reference HR security policy documents, the most recent access rights review report, privileged access management (PAM) system records, and the asset inventory.
- **gap_description**: Document whether gaps relate to HR procedures (screening, offboarding), access review cadence, privileged access governance, or asset inventory completeness.

### Common compliance evidence

- HR security policy covering pre-employment screening, onboarding, and offboarding procedures.
- Documented offboarding checklist and evidence of timely account deactivation on departure.
- Access control policy enforcing least-privilege and need-to-know principles.
- Access rights review report, conducted at least every six months for standard access and more frequently for privileged access.
- Privileged Access Management (PAM) system records or privileged account inventory with justification for each account.
- Asset inventory covering hardware, software (including cloud SaaS), data classifications, and assigned owners.
- Evidence of asset inventory validation (automated discovery and manual review).

### Key questions for assessors

- Are pre-employment background checks consistently conducted for roles with access to NIS2-in-scope systems, and is the scope of checks appropriate to the level of access granted?
- Is there a documented and consistently followed offboarding process that includes timely deactivation or deletion of all system accounts within a defined timeframe after employment ends?
- Are access rights reviews conducted at least every six months for all users, with privileged accounts reviewed more frequently, and are findings tracked through to action?
- Is the asset inventory comprehensive, covering all hardware, software, cloud services, and data assets, with named owners assigned and a defined process for keeping it current?

### Typical findings

**Partial compliance:** Background checks are conducted for some roles but not consistently applied or proportionate to access levels. Offboarding processes are documented but accounts are not always deactivated promptly. Access rights reviews are conducted annually but not for privileged accounts specifically. Asset inventory exists but covers only hardware and does not include cloud services or data assets.

**Non-compliance:** No HR security policy. No background screening for sensitive roles. Accounts of former employees remain active months after departure. No access rights review process. No comprehensive asset inventory; asset ownership is not assigned.

---

## Measure j — Multi-Factor Authentication & Continuous Authentication

**Article reference:** Art.21(2)(j)
**NIST CSF category:** Protect

### Directive requirement

Entities must implement multi-factor authentication (MFA) for access to network and information systems, prioritising internet-facing services, privileged accounts, and remote access connections. Where technically feasible, continuous or adaptive authentication mechanisms must be employed to detect anomalous access patterns at runtime. Authentication policies must define accepted MFA methods, session lifetimes, and re-authentication requirements for sensitive operations. Phishing-resistant MFA methods (e.g., FIDO2/WebAuthn, hardware tokens) should be preferred over SMS-based OTP.

### NIS2 Compass control fields guidance

- **status**: Set to `compliant` if MFA is enforced for all remote access, privileged accounts, and internet-facing services, phishing-resistant methods are deployed or on a documented roadmap, and authentication events are integrated with SIEM for anomaly detection. Set to `partially_compliant` if MFA is deployed in some contexts but not all required areas, or if only weaker methods (e.g., SMS OTP) are used without a migration roadmap. Set to `non_compliant` if MFA is not deployed for internet-facing or privileged access.
- **evidence**: Reference the authentication policy document, MFA deployment scope documentation, authenticator type inventory, SIEM integration evidence, and any roadmap for phishing-resistant MFA migration.
- **gap_description**: Specify which systems or account types lack MFA, what authentication methods are in use, and whether legacy systems present technical blockers to MFA enforcement.

### Common compliance evidence

- Authentication policy defining MFA requirements, accepted methods, session lifetimes, and re-authentication triggers.
- MFA deployment scope documentation listing covered services, account types, and any documented exceptions.
- Evidence of FIDO2/WebAuthn or hardware token deployment for privileged accounts.
- Roadmap or migration plan for transitioning from SMS-based OTP to phishing-resistant authenticators.
- SIEM or identity platform reports showing authentication event monitoring and anomaly detection capability.
- Evidence of step-up authentication triggers for high-risk operations (e.g., privileged action confirmation, large data exports).

### Key questions for assessors

- Is MFA enforced for all remote access connections (VPN, RDP, cloud management portals) and all privileged account access, with no permitted exceptions based on convenience?
- What MFA methods are in use, and where SMS-based OTP is the primary method, is there a documented and time-bound roadmap to migrate to phishing-resistant alternatives?
- Are authentication events (successful logins, failed attempts, unusual access patterns) collected in a SIEM or similar platform and actively reviewed or alerted upon?
- Is step-up or re-authentication required for sensitive operations, and are session lifetimes configured in line with the sensitivity of the systems accessed?

### Typical findings

**Partial compliance:** MFA is enforced for VPN access but not for cloud management consoles, privileged workstations, or internal administrative interfaces. SMS-based OTP is the universal MFA method with no roadmap to migrate to stronger authenticators. Authentication events are logged but not monitored in real time.

**Non-compliance:** MFA is not deployed for remote access or privileged accounts. Single-factor authentication (username/password) is the only protection for internet-facing services. No authentication event monitoring or anomaly detection capability.

---

## Penalty Context

Non-compliance with Article 21 of the NIS2 Directive can result in significant financial penalties imposed by national competent authorities. Article 34 of the Directive provides for the following maximum penalties:

**Essential entities**
- Up to €10,000,000 or 2% of the total global annual turnover of the undertaking in the preceding financial year, whichever is higher.

**Important entities**
- Up to €7,000,000 or 1.4% of the total global annual turnover of the undertaking in the preceding financial year, whichever is higher.

In addition to financial penalties, national competent authorities may impose non-financial supervisory measures, including:
- Binding instructions to implement specific security measures within defined timeframes.
- Mandatory third-party security audits at the entity's expense.
- Temporary prohibition of a natural person responsible for management-level functions from exercising those functions (applicable to essential entities).
- Public disclosure of non-compliance findings.

Penalties are applied following a finding of negligence or intentional failure to comply. The proportionality of the measure to the nature, gravity, and duration of the breach is taken into account, as well as whether the entity has taken active steps to remediate the breach.

These penalty thresholds underscore the importance of maintaining accurate, evidence-backed assessment records and acting on identified gaps within reasonable timeframes.

---

## Assessment Scoring Guidance

Each NIS2 Compass control carries a `risk_score` field (0.0–10.0). The score reflects the residual risk posed by the identified compliance posture of the control — it is not a subjective rating of the control's difficulty to implement, but an assessment of the potential harm to the organisation and its stakeholders if the gap is not addressed.

The scale aligns with the CVSS scoring convention to allow integration with existing risk management programmes that use CVSS-based vulnerability ratings.

| Score | Band | Meaning |
|---|---|---|
| 0.0 | None | Fully compliant. No gaps identified. No residual risk attributable to this control. |
| 0.1 – 3.9 | Low | Minor gaps. Limited practical impact. Remediation can be integrated into normal operational planning. Typical timeline: within 6 months. |
| 4.0 – 6.9 | Medium | Moderate gaps. Some requirements of the measure are not met. There is a meaningful probability of impact if left unaddressed. Remediation should be formally planned with a target of 3–6 months. |
| 7.0 – 8.9 | High | Significant gaps. Multiple requirements are unmet or a single critical requirement is absent. The likelihood of regulatory scrutiny or incident impact is elevated. Requires immediate management attention and a defined short-term remediation programme with named ownership. |
| 9.0 – 10.0 | Critical | Severe or systemic non-compliance. The control is essentially absent or has failed. There is an immediate and material risk to the security of NIS2-in-scope services. Escalation to senior leadership is required. Depending on context, mandatory incident notification obligations under NIS2 may apply. |

### Assigning scores consistently

When assigning a `risk_score`, consider the following factors:

- **Scope of the gap**: Does the gap affect a single system or a category of systems? Does it affect internet-facing services or only internal ones?
- **Exploitability**: How easily could a threat actor exploit the absence of this control? Controls covering externally exploitable attack surfaces (e.g., Measure j — MFA on internet-facing services) warrant higher scores than equivalent gaps on isolated internal systems.
- **Existing compensating controls**: Are there other controls in place that partially mitigate the risk created by this gap? If so, the score may be adjusted downward, but the compensating control dependency should be documented in `notes`.
- **Time to remediate**: Controls where the remediation pathway is complex, expensive, or involves legacy system replacement carry inherently higher residual risk scores even with a remediation plan in place.
- **Sector context**: For essential entities in highly regulated sectors (energy, health, financial infrastructure), the consequences of control failure are typically more severe. Scores may be adjusted upward to reflect the higher impact context.

The `overall_risk_score` returned in the assessment summary is the arithmetic mean of all assigned control scores. This aggregate should be interpreted as a single indicator — it does not replace a per-control review, since a low overall score can mask a single critical control failure.
