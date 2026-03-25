"""
NIS2 Compass — Seed: NIS2 Article 21(2) Control Templates

Inserts the canonical set of NIS2 Article 21(2) measures as control templates.
These serve as a reference library and are NOT tied to any specific assessment.

Usage:
    NIS2_DB_HOST=localhost NIS2_DB_PORT=5432 NIS2_DB_USER=nis2compass \
    NIS2_DB_PASSWORD=... NIS2_DB_NAME=nis2compass python seeds/01_nis2_controls.py
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
# DDL
# ---------------------------------------------------------------------------

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS control_templates (
    id            SERIAL       PRIMARY KEY,
    measure_ref   CHAR(1)      NOT NULL UNIQUE,
    article_ref   VARCHAR(20)  NOT NULL,
    title         VARCHAR(255) NOT NULL,
    description   TEXT         NOT NULL,
    nist_category VARCHAR(20)  NOT NULL,
    guidance      TEXT
);
"""

# ---------------------------------------------------------------------------
# Seed data — all 10 NIS2 Article 21(2) measures
# ---------------------------------------------------------------------------

CONTROLS = [
    {
        "measure_ref": "a",
        "article_ref": "Art.21(2)(a)",
        "title": "Risk Analysis & Information Security Policies",
        "description": (
            "Organisations must establish and maintain documented policies for information security "
            "that are approved by management and communicated across the entity. A systematic risk "
            "analysis process must be conducted to identify threats, vulnerabilities, and impacts "
            "relevant to network and information systems. Risk treatment decisions must be recorded "
            "and reviewed at planned intervals or following significant changes. The policies must "
            "cover the scope, objectives, roles, and responsibilities for managing cybersecurity risk."
        ),
        "nist_category": "identify",
        "guidance": (
            "Align with ISO/IEC 27001 clause 6.1 for risk assessment methodology. Ensure the risk "
            "register is reviewed at least annually and after any major incident or architectural "
            "change. Document the risk appetite and tolerance thresholds approved by senior leadership."
        ),
    },
    {
        "measure_ref": "b",
        "article_ref": "Art.21(2)(b)",
        "title": "Incident Handling",
        "description": (
            "Entities must implement procedures for detecting, reporting, analysing, and responding "
            "to cybersecurity incidents in a timely manner. An incident response plan must define "
            "roles, communication chains, and escalation paths including mandatory notification to "
            "the competent national authority or CSIRT within NIS2-mandated timeframes (early warning "
            "within 24 hours, full notification within 72 hours). Post-incident reviews must be "
            "conducted to identify root causes and prevent recurrence. Records of all incidents and "
            "responses must be retained for audit purposes."
        ),
        "nist_category": "respond",
        "guidance": (
            "Map incident severity levels to NIS2 notification obligations. Integrate with national "
            "CSIRT reporting portals where available. Conduct tabletop exercises at least twice a year "
            "to validate the incident response plan."
        ),
    },
    {
        "measure_ref": "c",
        "article_ref": "Art.21(2)(c)",
        "title": "Business Continuity & Disaster Recovery",
        "description": (
            "Entities must implement business continuity management (BCM) and disaster recovery (DR) "
            "capabilities to ensure the resilience of critical services during and after a disruptive "
            "event. Business impact analyses must identify recovery time objectives (RTO) and recovery "
            "point objectives (RPO) for essential functions. Tested backup procedures must ensure "
            "data integrity and availability can be restored within defined timeframes. Crisis "
            "management plans must address communication strategies, fallback operations, and "
            "stakeholder engagement during prolonged outages."
        ),
        "nist_category": "recover",
        "guidance": (
            "Perform full DR tests at least annually and partial tests quarterly. Backup media must "
            "be stored offline or in an air-gapped environment to guard against ransomware. Document "
            "dependencies on third-party providers within the BCP."
        ),
    },
    {
        "measure_ref": "d",
        "article_ref": "Art.21(2)(d)",
        "title": "Supply Chain Security",
        "description": (
            "Entities must manage cybersecurity risks arising from relationships with direct suppliers "
            "and service providers who have access to their network and information systems. A supply "
            "chain risk management policy must cover vendor assessment, contractual security "
            "requirements, and ongoing monitoring. Security requirements must be flowed down to "
            "sub-processors where relevant. Entities must evaluate the overall security posture of "
            "the supply chain, including the development and maintenance practices of software "
            "components in use."
        ),
        "nist_category": "identify",
        "guidance": (
            "Maintain an inventory of all third-party suppliers with access to critical systems. "
            "Include cybersecurity clauses (right-to-audit, incident notification, SBOM provision) "
            "in supplier contracts. Use threat intelligence feeds to monitor for supply chain "
            "compromise indicators."
        ),
    },
    {
        "measure_ref": "e",
        "article_ref": "Art.21(2)(e)",
        "title": "Network & Information Systems Security",
        "description": (
            "Entities must implement technical and organisational measures to secure the acquisition, "
            "development, and maintenance of network and information systems, including vulnerability "
            "handling and disclosure. Secure-by-design principles must be applied to new system "
            "development, and hardening baselines must be defined for infrastructure components. "
            "Patch management processes must ensure timely remediation of known vulnerabilities "
            "based on criticality. Network segmentation and monitoring must limit the blast radius "
            "of potential compromises."
        ),
        "nist_category": "protect",
        "guidance": (
            "Adopt a vulnerability management programme aligned with CVSS scoring for prioritisation. "
            "Implement intrusion detection and prevention systems on perimeter and internal segments. "
            "Review firewall rules and access control lists at least quarterly."
        ),
    },
    {
        "measure_ref": "f",
        "article_ref": "Art.21(2)(f)",
        "title": "Effectiveness Assessment Policies",
        "description": (
            "Entities must establish policies and procedures to assess the effectiveness of "
            "cybersecurity risk management measures on a continuous or periodic basis. Assessments "
            "must include internal audits, penetration testing, and vulnerability scanning at "
            "intervals commensurate with the entity's risk profile. Results must be reported to "
            "management and used to drive improvement. Metrics and key performance indicators (KPIs) "
            "for cybersecurity effectiveness must be defined and tracked over time."
        ),
        "nist_category": "identify",
        "guidance": (
            "Commission independent penetration tests at least annually. Define a set of measurable "
            "cybersecurity KPIs (e.g., mean time to detect, patch compliance rate) and report them "
            "to the board or equivalent governing body. Use continuous automated scanning to "
            "complement point-in-time assessments."
        ),
    },
    {
        "measure_ref": "g",
        "article_ref": "Art.21(2)(g)",
        "title": "Cyber Hygiene & Cybersecurity Training",
        "description": (
            "Entities must implement basic cyber hygiene practices across the organisation and ensure "
            "all staff receive role-appropriate cybersecurity awareness training. Training programmes "
            "must be regularly updated to reflect the current threat landscape and include practical "
            "components such as phishing simulations. Management and board members must receive "
            "targeted training on their cybersecurity governance responsibilities under NIS2. "
            "Records of completed training must be maintained and used to identify gaps."
        ),
        "nist_category": "protect",
        "guidance": (
            "Deliver mandatory annual awareness training for all employees, with additional "
            "specialised training for IT and security staff. Track completion rates and follow up "
            "with non-completers. Include social engineering recognition, password hygiene, and "
            "secure remote working in the baseline curriculum."
        ),
    },
    {
        "measure_ref": "h",
        "article_ref": "Art.21(2)(h)",
        "title": "Cryptography & Encryption Policies",
        "description": (
            "Entities must adopt and maintain policies on the use of cryptography and, where "
            "appropriate, encryption to protect the confidentiality, integrity, and authenticity "
            "of data in transit and at rest. Cryptographic standards must be reviewed periodically "
            "to ensure they remain fit for purpose against current and emerging threats, including "
            "post-quantum considerations. Key management procedures must govern the generation, "
            "storage, rotation, and destruction of cryptographic material. Deprecated algorithms "
            "and protocols (e.g., MD5, RC4, TLS 1.0/1.1) must be identified and phased out."
        ),
        "nist_category": "protect",
        "guidance": (
            "Define an approved cryptographic algorithm registry and enforce it through automated "
            "configuration scanning. Implement a key management system (KMS) or hardware security "
            "module (HSM) for high-value keys. Begin tracking post-quantum migration requirements "
            "in alignment with NIST PQC standards."
        ),
    },
    {
        "measure_ref": "i",
        "article_ref": "Art.21(2)(i)",
        "title": "HR Security, Access Control & Asset Management",
        "description": (
            "Entities must implement human resources security measures covering pre-employment "
            "screening, onboarding, role changes, and offboarding. Access control policies must "
            "enforce least-privilege and need-to-know principles, with privileged access subject "
            "to additional controls and regular review. A comprehensive asset inventory must be "
            "maintained covering hardware, software, data, and cloud services. Asset owners must "
            "be assigned, and asset classification must guide the application of appropriate "
            "security controls throughout the asset lifecycle."
        ),
        "nist_category": "protect",
        "guidance": (
            "Automate identity lifecycle management through integration with HR systems. Conduct "
            "access rights reviews at least every six months, prioritising privileged accounts. "
            "Ensure the asset inventory is updated automatically through discovery tooling and "
            "validated manually on a quarterly basis."
        ),
    },
    {
        "measure_ref": "j",
        "article_ref": "Art.21(2)(j)",
        "title": "Multi-Factor Authentication & Continuous Authentication",
        "description": (
            "Entities must implement multi-factor authentication (MFA) for access to network and "
            "information systems, prioritising internet-facing services, privileged accounts, and "
            "remote access connections. Where technically feasible, continuous or adaptive "
            "authentication mechanisms must be employed to detect anomalous access patterns at "
            "runtime. Authentication policies must define accepted MFA methods, session lifetimes, "
            "and re-authentication requirements for sensitive operations. Phishing-resistant MFA "
            "methods (e.g., FIDO2/WebAuthn, hardware tokens) should be preferred over SMS-based OTP."
        ),
        "nist_category": "protect",
        "guidance": (
            "Enforce MFA for all remote access and administrative interfaces as an immediate "
            "priority. Migrate from SMS-based OTP to phishing-resistant authenticators on a "
            "defined roadmap. Integrate authentication events with SIEM for anomaly detection "
            "and trigger step-up authentication for high-risk actions."
        ),
    },
]

# ---------------------------------------------------------------------------
# Upsert SQL
# ---------------------------------------------------------------------------

UPSERT_SQL = """
INSERT INTO control_templates
    (measure_ref, article_ref, title, description, nist_category, guidance)
VALUES
    (%(measure_ref)s, %(article_ref)s, %(title)s, %(description)s, %(nist_category)s, %(guidance)s)
ON CONFLICT (measure_ref) DO UPDATE SET
    article_ref   = EXCLUDED.article_ref,
    title         = EXCLUDED.title,
    description   = EXCLUDED.description,
    nist_category = EXCLUDED.nist_category,
    guidance      = EXCLUDED.guidance;
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
                cur.execute(CREATE_TABLE_SQL)
                count = 0
                for control in CONTROLS:
                    cur.execute(UPSERT_SQL, control)
                    count += 1
    finally:
        conn.close()

    print(f"Seeded {count} control templates.")


if __name__ == "__main__":
    main()
