"""
NIS2 Compass — Seed: ISO 27001:2022 Control Templates

Inserts a representative set of ISO/IEC 27001:2022 Annex A controls as
control templates with framework='iso27001'.  These serve as a reference
library and are NOT tied to any specific assessment.

Usage:
    NIS2_DB_HOST=localhost NIS2_DB_PORT=5432 NIS2_DB_USER=nis2compass \
    NIS2_DB_PASSWORD=... NIS2_DB_NAME=nis2compass python seeds/03_iso27001_controls.py
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
# Seed data — ISO/IEC 27001:2022 Annex A controls
# ---------------------------------------------------------------------------

CONTROLS = [
    # ── Clause 5 — Organisational Controls ───────────────────────────────
    {
        "measure_ref": "A.5.1",
        "article_ref": "A.5.1",
        "title": "Policies for Information Security",
        "description": (
            "Information security policy and topic-specific policies shall be defined, approved "
            "by management, published, communicated to and acknowledged by relevant personnel "
            "and relevant interested parties, and reviewed at planned intervals or if significant "
            "changes occur. Policies shall be reviewed for continuing suitability, adequacy, and "
            "effectiveness. Topic-specific policies shall address access control, asset management, "
            "cryptography, physical security, and other areas as appropriate."
        ),
        "nist_category": "identify",
        "guidance": (
            "Establish a policy hierarchy with an overarching information security policy "
            "supported by topic-specific policies. Policies must be approved by top management "
            "and reviewed at least annually or after significant changes. Maintain evidence of "
            "policy acknowledgement by all relevant personnel."
        ),
    },
    {
        "measure_ref": "A.5.2",
        "article_ref": "A.5.2",
        "title": "Information Security Roles and Responsibilities",
        "description": (
            "Information security roles and responsibilities shall be defined and allocated "
            "according to the organisation's needs. Responsibilities for the protection of "
            "individual assets and for carrying out specific information security processes "
            "shall be identified. Responsibilities for information security risk management "
            "activities shall be assigned. Individuals with assigned responsibilities shall be "
            "competent in the areas required and be provided with appropriate resources."
        ),
        "nist_category": "identify",
        "guidance": (
            "Document an information security responsibility matrix (RACI) covering all key "
            "security domains. Ensure a designated senior role (e.g., CISO) holds overall "
            "accountability for information security. Review and update role assignments "
            "at least annually and when personnel changes occur."
        ),
    },
    {
        "measure_ref": "A.5.3",
        "article_ref": "A.5.3",
        "title": "Segregation of Duties",
        "description": (
            "Conflicting duties and conflicting areas of responsibility shall be segregated. "
            "No single individual shall have the ability to commit fraud or error and then "
            "conceal it without detection. Where segregation of duties is not possible due to "
            "resource constraints, compensating controls such as activity monitoring, audit "
            "trails, and supervisory review shall be implemented and documented."
        ),
        "nist_category": "protect",
        "guidance": (
            "Identify critical processes where segregation of duties is required (e.g., access "
            "provisioning, change approval, financial transactions). Document compensating controls "
            "where full segregation is not achievable. Review segregation of duties conflicts "
            "during access certification campaigns."
        ),
    },
    {
        "measure_ref": "A.5.4",
        "article_ref": "A.5.4",
        "title": "Management Responsibilities",
        "description": (
            "Management shall require all personnel to apply information security in accordance "
            "with the established information security policy and topic-specific policies. "
            "Management shall demonstrate commitment by establishing security objectives, "
            "allocating adequate resources, directing and supporting persons to contribute to "
            "the effectiveness of the ISMS, and promoting continual improvement."
        ),
        "nist_category": "identify",
        "guidance": (
            "Include information security responsibilities in all relevant job descriptions. "
            "Ensure managers communicate and enforce security policies within their teams. "
            "Incorporate security performance into management objectives and annual reviews."
        ),
    },
    {
        "measure_ref": "A.5.10",
        "article_ref": "A.5.10",
        "title": "Acceptable Use of Information and Other Associated Assets",
        "description": (
            "Rules for the acceptable use and procedures for handling information and other "
            "associated assets shall be identified, documented, and implemented. Personnel and "
            "external parties using or having access to the organisation's assets shall be "
            "made aware of the information security requirements relevant to the assets they "
            "use. Consequences of non-compliance shall be clearly defined."
        ),
        "nist_category": "protect",
        "guidance": (
            "Publish an acceptable use policy covering all information assets including devices, "
            "email, internet access, and cloud services. Require acknowledgement at onboarding "
            "and annually thereafter. Address personal use, data handling, and prohibited "
            "activities clearly."
        ),
    },
    {
        "measure_ref": "A.5.15",
        "article_ref": "A.5.15",
        "title": "Access Control",
        "description": (
            "Rules to control physical and logical access to information and other associated "
            "assets shall be established and implemented based on business and information "
            "security requirements. Access shall be granted on a need-to-know and least-privilege "
            "basis. Access rights shall be reviewed at regular intervals and adjusted or "
            "revoked upon changes in roles or employment status."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define an access control policy specifying criteria for granting, modifying, and "
            "revoking access. Implement role-based access control (RBAC). Conduct access "
            "reviews at least every six months for all user accounts, with higher frequency "
            "for privileged accounts."
        ),
    },
    {
        "measure_ref": "A.5.23",
        "article_ref": "A.5.23",
        "title": "Information Security for Use of Cloud Services",
        "description": (
            "Processes for acquisition, use, management, and exit from cloud services shall be "
            "established in accordance with the organisation's information security requirements. "
            "Security responsibilities shared between the organisation and cloud service providers "
            "shall be defined. Controls shall be implemented to address data residency, "
            "portability, and the ability to audit cloud environments."
        ),
        "nist_category": "protect",
        "guidance": (
            "Maintain an inventory of all cloud services in use. Assess cloud service providers "
            "against the organisation's security requirements before adoption. Define shared "
            "responsibility boundaries in contracts. Establish exit strategies and data "
            "portability requirements for all critical cloud services."
        ),
    },
    {
        "measure_ref": "A.5.30",
        "article_ref": "A.5.30",
        "title": "ICT Readiness for Business Continuity",
        "description": (
            "ICT readiness shall be planned, implemented, maintained, and tested based on "
            "business continuity objectives and ICT continuity requirements. Recovery time "
            "objectives (RTO) and recovery point objectives (RPO) shall be defined for critical "
            "ICT systems. Redundancy and failover capabilities shall be implemented and "
            "validated through regular testing."
        ),
        "nist_category": "recover",
        "guidance": (
            "Define RTOs and RPOs for all critical systems and validate them through testing. "
            "Implement redundant infrastructure for critical services. Conduct DR tests at "
            "least annually and document results. Update ICT continuity plans following "
            "significant changes to the environment."
        ),
    },
    # ── Clause 6 — People Controls ────────────────────────────────────────
    {
        "measure_ref": "A.6.1",
        "article_ref": "A.6.1",
        "title": "Screening",
        "description": (
            "Background verification checks on all candidates for employment shall be carried "
            "out prior to joining the organisation and on an ongoing basis taking into "
            "consideration applicable laws, regulations, and ethics, and be proportional to "
            "the business requirements, the classification of the information to be accessed, "
            "and the perceived risks. Enhanced screening shall be conducted for roles with "
            "significant access to sensitive data or critical systems."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define screening requirements by role sensitivity, including criminal record checks, "
            "employment history verification, and reference checks. Conduct enhanced screening "
            "for privileged roles. Repeat screening for existing employees when they move to "
            "higher-trust roles. Document screening outcomes and store securely."
        ),
    },
    {
        "measure_ref": "A.6.3",
        "article_ref": "A.6.3",
        "title": "Information Security Awareness, Education, and Training",
        "description": (
            "Personnel of the organisation and, where relevant, interested parties shall receive "
            "appropriate information security awareness, education and training, and regular "
            "updates of the organisation's information security policies and procedures, as "
            "relevant for their job function. Training programmes shall be regularly reviewed "
            "and updated to reflect the current threat landscape."
        ),
        "nist_category": "protect",
        "guidance": (
            "Deliver mandatory security awareness training at onboarding and at least annually "
            "thereafter. Provide role-specific training for developers, system administrators, "
            "and management. Include phishing simulations in the awareness programme. "
            "Track completion rates and follow up with non-completers."
        ),
    },
    {
        "measure_ref": "A.6.5",
        "article_ref": "A.6.5",
        "title": "Responsibilities After Termination or Change of Employment",
        "description": (
            "Information security responsibilities and duties that remain valid after termination "
            "or change of employment shall be defined, communicated to the individual, and "
            "enforced. Personnel shall be required to return all organisational assets upon "
            "termination. All access rights shall be revoked promptly and in accordance with "
            "documented offboarding procedures."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement a formal offboarding checklist covering asset return, access revocation, "
            "and confidentiality obligations. Revoke all logical access within one business day "
            "of termination. Include post-employment confidentiality obligations in employment "
            "contracts. Conduct exit interviews for personnel leaving security-sensitive roles."
        ),
    },
    # ── Clause 7 — Physical Controls ─────────────────────────────────────
    {
        "measure_ref": "A.7.1",
        "article_ref": "A.7.1",
        "title": "Physical Security Perimeters",
        "description": (
            "Security perimeters shall be defined and used to protect areas that contain "
            "information and other associated assets. Physical security perimeters shall be "
            "physically sound, with no gaps that could allow unauthorised entry. The strength "
            "of perimeter controls shall be commensurate with the sensitivity of the assets "
            "protected. Multiple perimeter layers shall be used for critical areas."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define and document physical security zones with appropriate access controls for "
            "each zone. Inspect physical perimeters at least quarterly for integrity. "
            "Implement intruder detection systems for critical facilities. Review and update "
            "physical security plans annually."
        ),
    },
    {
        "measure_ref": "A.7.4",
        "article_ref": "A.7.4",
        "title": "Physical Security Monitoring",
        "description": (
            "Premises shall be continuously monitored for unauthorised physical access. "
            "CCTV surveillance, security guards, or equivalent monitoring mechanisms shall "
            "be deployed based on risk assessment. Monitoring footage and access logs shall "
            "be retained for a sufficient period to support investigation of security incidents. "
            "Alerts for anomalous physical access events shall be defined and tested."
        ),
        "nist_category": "detect",
        "guidance": (
            "Deploy CCTV coverage across all entry/exit points and sensitive areas. Retain "
            "CCTV footage for at least 90 days. Integrate physical access logs with the "
            "security operations function. Define alerts for out-of-hours access to "
            "sensitive areas."
        ),
    },
    # ── Clause 8 — Technological Controls ────────────────────────────────
    {
        "measure_ref": "A.8.1",
        "article_ref": "A.8.1",
        "title": "User Endpoint Devices",
        "description": (
            "Information stored on, processed by or accessible via user endpoint devices shall "
            "be protected. Endpoint security policies shall address configuration management, "
            "disk encryption, screen lock, software update management, and the use of "
            "removable media. Remote wipe capabilities shall be available for devices with "
            "access to sensitive data."
        ),
        "nist_category": "protect",
        "guidance": (
            "Deploy a mobile device management (MDM) or unified endpoint management (UEM) "
            "solution across all corporate endpoints. Enforce full-disk encryption, automatic "
            "screen lock, and automatic OS update policies. Enable remote wipe for all "
            "devices with access to sensitive data. Conduct quarterly compliance checks."
        ),
    },
    {
        "measure_ref": "A.8.2",
        "article_ref": "A.8.2",
        "title": "Privileged Access Rights",
        "description": (
            "The allocation and use of privileged access rights shall be restricted and managed. "
            "Privileged accounts shall be used only for tasks requiring elevated access; standard "
            "accounts shall be used for routine activities. All privileged access activities "
            "shall be logged and monitored. Privileged access shall be reviewed at regular "
            "intervals and removed when no longer required."
        ),
        "nist_category": "protect",
        "guidance": (
            "Implement a privileged access management (PAM) solution to control and audit "
            "privileged account usage. Require MFA for all privileged access. Review privileged "
            "access rights quarterly. Apply just-in-time (JIT) access principles to minimise "
            "standing privileged access."
        ),
    },
    {
        "measure_ref": "A.8.5",
        "article_ref": "A.8.5",
        "title": "Secure Authentication",
        "description": (
            "Secure authentication technologies and procedures shall be implemented based on "
            "information access restrictions and the topic-specific policy on access control. "
            "Multi-factor authentication shall be required for all remote access, privileged "
            "accounts, and access to sensitive systems. Phishing-resistant authentication "
            "methods shall be preferred. Password policies shall enforce complexity, length, "
            "and rotation requirements."
        ),
        "nist_category": "protect",
        "guidance": (
            "Enforce MFA for all remote access and administrative interfaces. Prefer FIDO2 or "
            "certificate-based authentication over SMS OTP. Implement password managers and "
            "enforce minimum password length of 12 characters. Detect and respond to "
            "authentication anomalies through SIEM integration."
        ),
    },
    {
        "measure_ref": "A.8.7",
        "article_ref": "A.8.7",
        "title": "Protection Against Malware",
        "description": (
            "Protection against malware shall be implemented and supported by appropriate user "
            "awareness. Endpoint protection solutions shall detect, prevent, and respond to "
            "malware threats. Controls shall address the risks from software obtained from "
            "external sources, including web downloads and removable media. User awareness "
            "training shall include guidance on recognising and reporting malware."
        ),
        "nist_category": "protect",
        "guidance": (
            "Deploy endpoint detection and response (EDR) on all endpoints and servers. "
            "Configure automatic signature updates with a maximum 4-hour update interval. "
            "Implement email and web gateway scanning for malicious content. Test malware "
            "response procedures at least annually."
        ),
    },
    {
        "measure_ref": "A.8.8",
        "article_ref": "A.8.8",
        "title": "Management of Technical Vulnerabilities",
        "description": (
            "Information about technical vulnerabilities of information systems in use shall "
            "be obtained in a timely manner. The organisation's exposure to such vulnerabilities "
            "shall be evaluated, and appropriate measures shall be taken to address the "
            "associated risk. Vulnerability management processes shall define timelines for "
            "remediation based on severity and asset criticality."
        ),
        "nist_category": "identify",
        "guidance": (
            "Conduct authenticated vulnerability scans at least monthly across all in-scope "
            "systems. Define remediation SLAs by severity: critical within 7 days, high within "
            "30 days, medium within 90 days. Track remediation progress and report metrics to "
            "management monthly. Validate remediation through rescan."
        ),
    },
    {
        "measure_ref": "A.8.15",
        "article_ref": "A.8.15",
        "title": "Logging",
        "description": (
            "Logs that record activities, exceptions, faults, and other relevant events shall "
            "be produced, stored, protected, and analysed. Log coverage shall include security "
            "events, privileged account activity, authentication events, and system changes. "
            "Log retention periods shall be defined and meet regulatory and investigative "
            "requirements. Logs shall be protected from unauthorised access and tampering."
        ),
        "nist_category": "detect",
        "guidance": (
            "Centralise log collection into a SIEM with a minimum retention period of 12 months "
            "(with at least 3 months hot/searchable). Define the minimum log sources required "
            "for coverage. Protect log integrity through write-once storage or cryptographic "
            "hashing. Review logging coverage quarterly."
        ),
    },
    {
        "measure_ref": "A.8.16",
        "article_ref": "A.8.16",
        "title": "Monitoring Activities",
        "description": (
            "Networks, systems, and applications shall be monitored for anomalous behaviour and "
            "potential information security incidents. Monitoring procedures shall define what "
            "is monitored, monitoring intervals, and actions to be taken when anomalies are "
            "detected. Monitoring results shall be reviewed regularly and acted upon. "
            "The monitoring strategy shall be reviewed and updated periodically."
        ),
        "nist_category": "detect",
        "guidance": (
            "Define a monitoring strategy covering network traffic, endpoint behaviour, identity "
            "events, and cloud activity. Implement user and entity behaviour analytics (UEBA) "
            "to detect anomalous patterns. Review and tune detection rules quarterly. "
            "Ensure monitoring coverage includes cloud-hosted workloads."
        ),
    },
    {
        "measure_ref": "A.8.24",
        "article_ref": "A.8.24",
        "title": "Use of Cryptography",
        "description": (
            "Rules for the effective use of cryptography, including cryptographic key management, "
            "shall be defined and implemented. The organisation shall define its approved "
            "cryptographic algorithms, key lengths, and protocols. Data at rest and in transit "
            "shall be protected using cryptographic controls commensurate with the sensitivity "
            "of the information. Deprecated algorithms and protocols shall be identified and "
            "phased out on a defined timeline."
        ),
        "nist_category": "protect",
        "guidance": (
            "Maintain an approved cryptographic standards registry and enforce it through "
            "configuration management. Implement a key management system (KMS) or HSM for "
            "high-value keys. Define and enforce key rotation schedules. Monitor for use of "
            "deprecated algorithms (e.g., MD5, SHA-1, TLS 1.0/1.1) and plan migration to "
            "post-quantum-safe algorithms."
        ),
    },
    {
        "measure_ref": "A.8.28",
        "article_ref": "A.8.28",
        "title": "Secure Coding",
        "description": (
            "Secure coding principles shall be applied to software development. Developers "
            "shall be trained on secure coding practices relevant to their technology stack. "
            "Security requirements shall be defined at the start of development projects and "
            "security testing (SAST, DAST, SCA) shall be integrated into the software "
            "development lifecycle. Identified vulnerabilities shall be remediated before "
            "software is deployed to production."
        ),
        "nist_category": "protect",
        "guidance": (
            "Integrate static analysis (SAST) and software composition analysis (SCA) into "
            "CI/CD pipelines. Conduct dynamic application security testing (DAST) before each "
            "major release. Train all developers on OWASP Top 10 and secure coding standards. "
            "Establish a security champion programme within development teams."
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
    (%(measure_ref)s, %(article_ref)s, %(title)s, %(description)s, %(nist_category)s, %(guidance)s, 'iso27001')
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

    print(f"Seeded {count} ISO 27001:2022 control templates.")


if __name__ == "__main__":
    main()
