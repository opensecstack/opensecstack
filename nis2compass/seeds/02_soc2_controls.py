"""
NIS2 Compass — Seed: SOC 2 Type II Trust Service Criteria Control Templates

Inserts the canonical set of SOC 2 Type II Trust Service Criteria (TSC) as
control templates with framework='soc2'.  These serve as a reference library
and are NOT tied to any specific assessment.

Usage:
    NIS2_DB_HOST=localhost NIS2_DB_PORT=5432 NIS2_DB_USER=nis2compass \
    NIS2_DB_PASSWORD=... NIS2_DB_NAME=nis2compass python seeds/02_soc2_controls.py
"""

import os
import sys
import psycopg2

# ---------------------------------------------------------------------------
# Database connection
# ---------------------------------------------------------------------------

def get_connection():
    return psycopg2.connect(
        host=os.environ.get("NIS2_DB_HOST", "localhost"),
        port=int(os.environ.get("NIS2_DB_PORT", 5432)),
        user=os.environ.get("NIS2_DB_USER", "nis2compass"),
        password=os.environ["NIS2_DB_PASSWORD"],
        dbname=os.environ.get("NIS2_DB_NAME", "nis2compass"),
    )

# ---------------------------------------------------------------------------
# Seed data — SOC 2 Type II Trust Service Criteria
# ---------------------------------------------------------------------------

CONTROLS = [
    # ── CC1 Control Environment ───────────────────────────────────────────
    {
        "measure_ref": "CC1.1",
        "article_ref": "CC1.1",
        "title": "Control Environment — COSO Principles",
        "description": (
            "The entity demonstrates a commitment to integrity and ethical values. Management "
            "establishes a tone at the top that reinforces the importance of a strong control "
            "environment. Policies and codes of conduct are documented, communicated to all "
            "personnel, and enforced consistently. Deviations from expected behaviour are "
            "identified, assessed, and remediated in a timely manner."
        ),
        "nist_category": "identify",
        "guidance": (
            "Publish an information security policy approved by the board or equivalent governing "
            "body. Ensure all employees acknowledge the code of conduct annually. Track and "
            "investigate reported ethical violations."
        ),
    },
    {
        "measure_ref": "CC1.2",
        "article_ref": "CC1.2",
        "title": "Board Independence and Oversight",
        "description": (
            "The board of directors or equivalent governing body demonstrates independence from "
            "management and exercises oversight of the development and performance of internal "
            "controls. The board includes members with relevant expertise to evaluate cybersecurity "
            "and operational risk. Regular reporting mechanisms ensure the board receives timely "
            "and accurate information about control effectiveness."
        ),
        "nist_category": "identify",
        "guidance": (
            "Establish a board-level security and risk committee with at least one member "
            "possessing cybersecurity expertise. Provide quarterly security briefings to the board "
            "and document meeting minutes."
        ),
    },
    {
        "measure_ref": "CC1.3",
        "article_ref": "CC1.3",
        "title": "Organisational Structure, Authority, and Responsibility",
        "description": (
            "Management establishes structures, reporting lines, and appropriate authorities and "
            "responsibilities in pursuit of objectives. Roles and responsibilities for information "
            "security are clearly defined, assigned, and communicated. Accountability for control "
            "activities is embedded in job descriptions and performance objectives."
        ),
        "nist_category": "identify",
        "guidance": (
            "Maintain an up-to-date RACI matrix for all security control areas. Ensure the CISO "
            "or equivalent role has direct reporting access to senior leadership. Review and "
            "update the organisational chart at least annually."
        ),
    },
    {
        "measure_ref": "CC1.4",
        "article_ref": "CC1.4",
        "title": "Commitment to Competence",
        "description": (
            "The entity demonstrates a commitment to attracting, developing, and retaining "
            "competent individuals in alignment with objectives. Hiring practices include "
            "background verification and skills assessments for security-sensitive roles. "
            "Ongoing training ensures staff maintain the competencies required for their "
            "responsibilities. Performance management processes address competency gaps."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define minimum qualification and certification requirements for security roles. "
            "Conduct annual competency assessments and provide targeted training to address "
            "identified gaps. Maintain training completion records."
        ),
    },
    {
        "measure_ref": "CC1.5",
        "article_ref": "CC1.5",
        "title": "Accountability for Internal Control",
        "description": (
            "The entity holds individuals accountable for their internal control responsibilities "
            "in pursuit of objectives. Performance incentives and disciplinary measures reinforce "
            "compliance with security policies. Management evaluates adherence to control "
            "requirements as part of regular performance reviews. Non-compliance consequences "
            "are clearly communicated and consistently enforced."
        ),
        "nist_category": "identify",
        "guidance": (
            "Include security control responsibilities in employee performance objectives. "
            "Establish a formal disciplinary process for policy violations. Document and "
            "communicate consequences for non-compliance at onboarding."
        ),
    },
    # ── CC2 Communication and Information ────────────────────────────────
    {
        "measure_ref": "CC2.1",
        "article_ref": "CC2.1",
        "title": "Information Quality and Communication",
        "description": (
            "The entity obtains or generates and uses relevant, quality information to support "
            "the functioning of internal controls. Data sources are identified and their quality "
            "assessed. Information used in control activities is accurate, timely, and complete. "
            "Processes are in place to identify and correct data quality issues."
        ),
        "nist_category": "identify",
        "guidance": (
            "Define data quality standards for security-relevant information (logs, alerts, "
            "asset inventories). Implement automated data quality checks and establish "
            "exception-handling procedures for quality failures."
        ),
    },
    {
        "measure_ref": "CC2.2",
        "article_ref": "CC2.2",
        "title": "Internal Communication of Control Information",
        "description": (
            "The entity internally communicates information, including objectives and "
            "responsibilities for internal control, necessary to support the functioning of "
            "internal controls. Security policies, procedures, and standards are communicated "
            "to all relevant personnel through appropriate channels. Changes to control "
            "requirements are communicated in a timely manner."
        ),
        "nist_category": "protect",
        "guidance": (
            "Maintain a centralised policy management system accessible to all employees. "
            "Notify affected teams of policy changes within 5 business days. Confirm receipt "
            "and acknowledgement for critical policy updates."
        ),
    },
    {
        "measure_ref": "CC2.3",
        "article_ref": "CC2.3",
        "title": "External Communication of Control Information",
        "description": (
            "The entity communicates with external parties regarding matters affecting the "
            "functioning of internal controls. Communication channels for reporting security "
            "concerns to external stakeholders (customers, regulators, partners) are established "
            "and maintained. Disclosure obligations are met in accordance with contractual and "
            "regulatory requirements."
        ),
        "nist_category": "respond",
        "guidance": (
            "Publish a responsible disclosure policy and security contact information. "
            "Establish SLAs for responding to customer security inquiries. Maintain a "
            "communications plan for notifying affected parties during a security incident."
        ),
    },
    # ── CC3 Risk Assessment ───────────────────────────────────────────────
    {
        "measure_ref": "CC3.1",
        "article_ref": "CC3.1",
        "title": "Risk Assessment Objectives",
        "description": (
            "The entity specifies objectives with sufficient clarity to enable the identification "
            "and assessment of risks relating to those objectives. Security objectives are aligned "
            "with the entity's overall business objectives and trust service commitments. Risks "
            "are assessed against defined criteria including likelihood and impact."
        ),
        "nist_category": "identify",
        "guidance": (
            "Define measurable security objectives tied to each Trust Service Criterion. "
            "Conduct a formal risk assessment at least annually and after significant changes "
            "to the environment. Document risk acceptance decisions with management approval."
        ),
    },
    {
        "measure_ref": "CC3.2",
        "article_ref": "CC3.2",
        "title": "Risk Identification and Analysis",
        "description": (
            "The entity identifies risks to the achievement of its objectives across the entity "
            "and analyses risks as a basis for determining how the risks should be managed. "
            "Threat modelling, vulnerability assessments, and threat intelligence are used to "
            "identify new and emerging risks. Risk owners are assigned for identified risks."
        ),
        "nist_category": "identify",
        "guidance": (
            "Maintain a risk register with clearly defined risk owners, likelihood and impact "
            "ratings, and treatment decisions. Integrate threat intelligence feeds into the "
            "risk identification process. Review the risk register quarterly."
        ),
    },
    {
        "measure_ref": "CC3.3",
        "article_ref": "CC3.3",
        "title": "Fraud Risk Assessment",
        "description": (
            "The entity considers the potential for fraud in assessing risks to the achievement "
            "of objectives. Fraud risk scenarios relevant to financial reporting, unauthorised "
            "access, and data misuse are identified and assessed. Anti-fraud controls are "
            "implemented commensurate with the assessed risk level."
        ),
        "nist_category": "identify",
        "guidance": (
            "Include fraud scenarios (insider threat, social engineering, financial manipulation) "
            "in the annual risk assessment. Implement detective controls such as user behaviour "
            "analytics and anomaly detection. Conduct periodic access reviews to limit "
            "opportunities for fraudulent activity."
        ),
    },
    {
        "measure_ref": "CC3.4",
        "article_ref": "CC3.4",
        "title": "Identification and Assessment of Significant Changes",
        "description": (
            "The entity identifies and assesses changes that could significantly impact the "
            "system of internal controls. Change management processes ensure that security "
            "implications of significant changes (new systems, acquisitions, regulatory changes) "
            "are evaluated before implementation. Risk assessments are updated to reflect "
            "identified changes."
        ),
        "nist_category": "identify",
        "guidance": (
            "Integrate a security impact assessment into the change management process for all "
            "significant changes. Define thresholds for what constitutes a 'significant change' "
            "requiring a full risk assessment update. Document and track risk assessment updates "
            "triggered by changes."
        ),
    },
    # ── CC4 Monitoring Activities ─────────────────────────────────────────
    {
        "measure_ref": "CC4.1",
        "article_ref": "CC4.1",
        "title": "Ongoing and Separate Evaluations",
        "description": (
            "The entity selects, develops, and performs ongoing and/or separate evaluations to "
            "ascertain whether the components of internal control are present and functioning. "
            "Continuous monitoring controls supplement periodic independent assessments. "
            "Evaluation methodologies are appropriate to the size and complexity of the entity."
        ),
        "nist_category": "detect",
        "guidance": (
            "Implement continuous control monitoring tools for key controls (e.g., configuration "
            "drift detection, access anomaly alerting). Schedule independent internal audits "
            "at least annually. Document evaluation scope, methodology, and findings."
        ),
    },
    {
        "measure_ref": "CC4.2",
        "article_ref": "CC4.2",
        "title": "Evaluation and Communication of Control Deficiencies",
        "description": (
            "The entity evaluates and communicates internal control deficiencies in a timely "
            "manner to those parties responsible for taking corrective action, including senior "
            "management and the board of directors, as appropriate. A deficiency remediation "
            "tracking process ensures identified gaps are addressed within defined timeframes."
        ),
        "nist_category": "respond",
        "guidance": (
            "Establish a formal finding management process with severity classifications, "
            "assigned owners, and remediation deadlines. Report open deficiencies to senior "
            "management monthly and to the board quarterly. Track remediation progress and "
            "verify closure through evidence review."
        ),
    },
    # ── CC5 Control Activities ────────────────────────────────────────────
    {
        "measure_ref": "CC5.1",
        "article_ref": "CC5.1",
        "title": "Selection and Development of Control Activities",
        "description": (
            "The entity selects and develops control activities that contribute to the mitigation "
            "of risks to the achievement of objectives to acceptable levels. Controls are selected "
            "based on a cost-benefit analysis and are commensurate with the assessed risk level. "
            "A mix of preventive, detective, and corrective controls is implemented."
        ),
        "nist_category": "protect",
        "guidance": (
            "Document the rationale for each selected control and map it to the risk it mitigates. "
            "Review the control portfolio at least annually to ensure it remains appropriate for "
            "the current risk environment. Consider automation to improve control reliability."
        ),
    },
    {
        "measure_ref": "CC5.2",
        "article_ref": "CC5.2",
        "title": "Technology General Controls",
        "description": (
            "The entity selects and develops general control activities over technology to support "
            "the achievement of objectives. Controls address the acquisition, implementation, "
            "maintenance, and disposal of technology. Change management, access controls, and "
            "IT operations controls are defined and operating effectively."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement a formal IT general controls (ITGC) framework covering logical access, "
            "change management, computer operations, and data management. Test ITGCs at least "
            "annually. Address deficiencies before relying on automated application controls."
        ),
    },
    {
        "measure_ref": "CC5.3",
        "article_ref": "CC5.3",
        "title": "Deployment of Controls Through Policies and Procedures",
        "description": (
            "The entity deploys control activities through policies that establish what is expected "
            "and procedures that put policies into action. Policies are approved by appropriate "
            "management and reviewed at defined intervals. Procedures provide sufficient detail "
            "to enable consistent execution and are updated to reflect changes in the control "
            "environment."
        ),
        "nist_category": "protect",
        "guidance": (
            "Maintain a policy lifecycle management process with defined review cycles (at least "
            "annually). Ensure procedures are tested for completeness and clarity before publication. "
            "Track policy acknowledgement by all affected personnel."
        ),
    },
    # ── CC6 Logical and Physical Access Controls ──────────────────────────
    {
        "measure_ref": "CC6.1",
        "article_ref": "CC6.1",
        "title": "Logical Access Security Controls",
        "description": (
            "The entity implements logical access security software, infrastructure, and "
            "architectures over protected information assets to protect them from security "
            "events to meet the entity's objectives. Access control mechanisms enforce the "
            "principle of least privilege, and privileged access is subject to additional "
            "controls including multi-factor authentication."
        ),
        "nist_category": "protect",
        "guidance": (
            "Enforce role-based access control (RBAC) across all systems. Require MFA for all "
            "privileged and remote access. Conduct quarterly access reviews and revoke "
            "unnecessary permissions promptly. Log and monitor all privileged access activities."
        ),
    },
    {
        "measure_ref": "CC6.2",
        "article_ref": "CC6.2",
        "title": "User Registration and De-registration",
        "description": (
            "Prior to issuing system credentials and granting system access, the entity registers "
            "and authorises new internal and external users whose access is administered by the "
            "entity. User registration follows a formal onboarding process with management approval. "
            "De-registration ensures access is promptly revoked upon termination or role change."
        ),
        "nist_category": "protect",
        "guidance": (
            "Automate provisioning and de-provisioning through integration with the HR system. "
            "Ensure all access requests are formally approved. Revoke access within 24 hours of "
            "employment termination. Conduct regular reviews of dormant accounts."
        ),
    },
    {
        "measure_ref": "CC6.3",
        "article_ref": "CC6.3",
        "title": "Role-based Access and Least Privilege",
        "description": (
            "The entity authorises, modifies, or removes access to data, software, functions, "
            "and other protected information assets based on roles, responsibilities, or the "
            "system design and changes, giving consideration to the concepts of least privilege "
            "and segregation of duties. Access rights are reviewed periodically and adjusted "
            "to reflect current job responsibilities."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define access roles aligned to job functions and enforce them through an identity "
            "management system. Perform semi-annual access certification campaigns. Identify and "
            "remediate access that violates segregation of duties principles within 30 days."
        ),
    },
    {
        "measure_ref": "CC6.4",
        "article_ref": "CC6.4",
        "title": "Physical Access Restrictions",
        "description": (
            "The entity restricts physical access to facilities and protected information assets "
            "to authorised personnel to meet the entity's objectives. Physical access controls "
            "include key cards, biometrics, security cameras, and visitor management procedures. "
            "Access to sensitive areas (data centres, server rooms) is limited to those with a "
            "demonstrable business need."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement layered physical access controls with distinct zones (perimeter, office, "
            "data centre). Maintain a visitor log and escort policy for all non-employees. "
            "Review physical access rights quarterly and revoke access upon personnel departure."
        ),
    },
    {
        "measure_ref": "CC6.5",
        "article_ref": "CC6.5",
        "title": "Disposal of Assets",
        "description": (
            "The entity discontinues logical and physical protections over physical assets only "
            "after the ability to read or recover data and software from those assets has been "
            "diminished and is no longer required to meet the entity's objectives. Data "
            "sanitisation procedures are applied before disposal or repurposing of hardware "
            "and storage media."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement NIST SP 800-88 compliant media sanitisation procedures. Maintain records "
            "of all disposed assets including sanitisation method and destruction certificates. "
            "Apply secure wipe or physical destruction for all storage media containing "
            "sensitive data."
        ),
    },
    {
        "measure_ref": "CC6.6",
        "article_ref": "CC6.6",
        "title": "Security Against Threats Outside System Boundaries",
        "description": (
            "The entity implements logical access security measures to protect against threats "
            "from sources outside its system boundaries. Perimeter security controls include "
            "firewalls, intrusion detection systems, DDoS mitigation, and secure remote access "
            "solutions. Network traffic is monitored for anomalies and indicators of compromise."
        ),
        "nist_category": "protect",
        "guidance": (
            "Deploy next-generation firewalls and IDS/IPS at all network perimeters. Enable "
            "DDoS mitigation services for internet-facing systems. Review firewall rules "
            "quarterly. Integrate perimeter alerts with the SIEM for centralised monitoring."
        ),
    },
    {
        "measure_ref": "CC6.7",
        "article_ref": "CC6.7",
        "title": "Transmission and Movement of Information",
        "description": (
            "The entity restricts the transmission, movement, and removal of information to "
            "authorised internal and external users and processes, and protects it during "
            "transmission. Data in transit is encrypted using strong, current cryptographic "
            "standards. Data loss prevention (DLP) controls monitor and restrict unauthorised "
            "data movement."
        ),
        "nist_category": "protect",
        "guidance": (
            "Enforce TLS 1.2 or higher for all data in transit. Implement DLP solutions to "
            "detect and block unauthorised data exfiltration. Audit and approve all mechanisms "
            "for transferring data outside the organisation's boundary."
        ),
    },
    {
        "measure_ref": "CC6.8",
        "article_ref": "CC6.8",
        "title": "Prevention and Detection of Malicious Software",
        "description": (
            "The entity implements controls to prevent or detect and act upon the introduction "
            "of unauthorised or malicious software to meet the entity's objectives. Endpoint "
            "protection platforms (EPP) and endpoint detection and response (EDR) solutions "
            "are deployed across the environment. Software allowlisting and application control "
            "policies reduce the attack surface."
        ),
        "nist_category": "detect",
        "guidance": (
            "Deploy EDR solutions on all endpoints and servers. Enforce application allowlisting "
            "on high-risk systems. Maintain antimalware signature currency with automated updates. "
            "Test incident response procedures for malware scenarios at least annually."
        ),
    },
    # ── CC7 System Operations ─────────────────────────────────────────────
    {
        "measure_ref": "CC7.1",
        "article_ref": "CC7.1",
        "title": "Detection and Monitoring of New Vulnerabilities",
        "description": (
            "To meet its objectives, the entity uses detection and monitoring procedures to "
            "identify changes to configurations or new vulnerabilities that could adversely "
            "affect the entity. Vulnerability scanning is performed on a regular schedule "
            "across all in-scope systems. Threat intelligence is used to identify newly "
            "disclosed vulnerabilities relevant to the environment."
        ),
        "nist_category": "detect",
        "guidance": (
            "Perform authenticated vulnerability scans on all systems at least monthly. "
            "Subscribe to relevant vulnerability intelligence feeds (NVD, vendor advisories). "
            "Prioritise remediation using CVSS scores and asset criticality. Track open "
            "vulnerabilities in a centralised remediation register."
        ),
    },
    {
        "measure_ref": "CC7.2",
        "article_ref": "CC7.2",
        "title": "Monitoring for Security Events",
        "description": (
            "The entity monitors system components and the operation of those components for "
            "anomalies that are indicative of malicious acts, natural disasters, and errors "
            "affecting the entity's ability to meet its objectives. Security information and "
            "event management (SIEM) solutions aggregate and correlate log data to detect "
            "security events. Alerting thresholds and escalation paths are defined and tested."
        ),
        "nist_category": "detect",
        "guidance": (
            "Centralise log collection from all critical systems into a SIEM. Define and tune "
            "detection rules to reduce false positives. Establish response SLAs for different "
            "alert severity levels. Conduct purple team exercises to validate detection coverage."
        ),
    },
    {
        "measure_ref": "CC7.3",
        "article_ref": "CC7.3",
        "title": "Evaluation and Response to Security Events",
        "description": (
            "The entity evaluates security events to determine whether they could or have "
            "resulted in a failure of the entity to meet its objectives (security incidents) "
            "and, if so, takes actions to prevent or address such failures. Triage processes "
            "distinguish genuine incidents from false positives. Incident severity criteria "
            "guide the escalation and response process."
        ),
        "nist_category": "respond",
        "guidance": (
            "Define incident classification criteria and escalation thresholds. Maintain an "
            "on-call security analyst schedule for 24/7 coverage of high-severity alerts. "
            "Document triage decisions and actions taken in a ticketing system. Review "
            "false-positive rates monthly to improve detection quality."
        ),
    },
    {
        "measure_ref": "CC7.4",
        "article_ref": "CC7.4",
        "title": "Incident Response and Recovery",
        "description": (
            "The entity responds to identified security incidents by executing a defined "
            "incident management process to understand, contain, remediate, and communicate "
            "about security incidents, as appropriate. Post-incident reviews identify root "
            "causes and drive process improvements. Communication obligations to affected "
            "parties are met within required timeframes."
        ),
        "nist_category": "respond",
        "guidance": (
            "Maintain and test an incident response plan at least annually through tabletop "
            "exercises. Define roles and responsibilities for incident response team members. "
            "Establish communication templates for notifying affected customers and regulators. "
            "Conduct post-incident reviews within 5 business days of incident closure."
        ),
    },
    {
        "measure_ref": "CC7.5",
        "article_ref": "CC7.5",
        "title": "Identification and Remediation of Infrastructure and Software Issues",
        "description": (
            "The entity identifies, develops, and implements activities to recover from "
            "identified security incidents. Recovery procedures are documented and tested. "
            "Lessons learned from incidents are incorporated into security control improvements "
            "and the risk management process. Residual risk after remediation is assessed "
            "and accepted or further treated."
        ),
        "nist_category": "recover",
        "guidance": (
            "Document recovery procedures for all critical system components. Test recovery "
            "capabilities quarterly. Track remediation activities to closure in the incident "
            "management system. Update the risk register and control framework based on "
            "post-incident findings."
        ),
    },
    # ── CC8 Change Management ─────────────────────────────────────────────
    {
        "measure_ref": "CC8.1",
        "article_ref": "CC8.1",
        "title": "Change Management Process",
        "description": (
            "The entity authorises, designs, develops or acquires, configures, documents, "
            "tests, approves, and implements changes to infrastructure, data, software, and "
            "procedures to meet its change management objectives. All changes are tracked in "
            "a change management system with appropriate approval workflows. Emergency changes "
            "follow an expedited but controlled process with post-implementation review."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement a formal change advisory board (CAB) process for significant changes. "
            "Require security review for all changes to security-relevant systems. Maintain "
            "change records with approval history, test results, and rollback procedures. "
            "Conduct post-implementation reviews for all major changes."
        ),
    },
    # ── CC9 Risk Mitigation ───────────────────────────────────────────────
    {
        "measure_ref": "CC9.1",
        "article_ref": "CC9.1",
        "title": "Risk Mitigation Activities",
        "description": (
            "The entity identifies, selects, and develops risk mitigation activities for risks "
            "arising from potential business disruptions. Business continuity and disaster "
            "recovery plans address the availability of critical systems and data. "
            "Risk mitigation strategies are evaluated for their effectiveness and updated "
            "as the risk landscape evolves."
        ),
        "nist_category": "recover",
        "guidance": (
            "Develop and maintain business continuity plans (BCPs) for all critical business "
            "processes. Test BCPs at least annually through full or partial exercises. "
            "Document RTOs and RPOs for critical systems and validate them through testing. "
            "Review and update BCPs following significant organisational or technology changes."
        ),
    },
    {
        "measure_ref": "CC9.2",
        "article_ref": "CC9.2",
        "title": "Vendor and Business Partner Risk Management",
        "description": (
            "The entity assesses and manages risks associated with vendors and business partners. "
            "Due diligence is performed on third parties with access to the entity's systems or "
            "data prior to engagement. Contractual security requirements are established and "
            "vendor compliance is monitored on an ongoing basis. Material vendor incidents are "
            "reported and assessed for their impact on the entity."
        ),
        "nist_category": "identify",
        "guidance": (
            "Establish a vendor risk management programme with tiered assessment requirements "
            "based on data access and criticality. Include security clauses (right-to-audit, "
            "incident notification obligations, data handling requirements) in all vendor "
            "contracts. Conduct annual vendor security reviews for critical suppliers."
        ),
    },
]

# ---------------------------------------------------------------------------
# Upsert SQL
# ---------------------------------------------------------------------------

UPSERT_SQL = """
INSERT INTO control_templates
    (measure_ref, article_ref, title, description, nist_category, guidance, framework)
VALUES
    (%(measure_ref)s, %(article_ref)s, %(title)s, %(description)s, %(nist_category)s, %(guidance)s, 'soc2')
ON CONFLICT (measure_ref, framework) DO NOTHING;
"""

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    try:
        conn = get_connection()
    except KeyError as exc:
        print(f"ERROR: missing required environment variable: {exc}", file=sys.stderr)
        sys.exit(1)
    except psycopg2.OperationalError as exc:
        print(f"ERROR: could not connect to database: {exc}", file=sys.stderr)
        sys.exit(1)

    try:
        with conn:
            with conn.cursor() as cur:
                count = 0
                for control in CONTROLS:
                    cur.execute(UPSERT_SQL, control)
                    count += 1
    finally:
        conn.close()

    print(f"Seeded {count} SOC 2 control templates.")


if __name__ == "__main__":
    main()
