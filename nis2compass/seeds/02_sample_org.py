"""
NIS2 Compass — Seed: Sample Organisation & Assessment

Inserts one sample organisation (Acme Energy GmbH), one initial NIS2 assessment,
and 10 control entries (one per Article 21(2) measure) with status 'not_assessed'.

Requires Alembic migrations to have been applied first (alembic upgrade head).

Usage:
    NIS2_DB_HOST=localhost NIS2_DB_PORT=5432 NIS2_DB_USER=nis2compass \
    NIS2_DB_PASSWORD=... NIS2_DB_NAME=nis2compass python seeds/02_sample_org.py
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
# NIS2 Article 21(2) measures: (measure_ref, nist_category, title)
# ---------------------------------------------------------------------------

MEASURES = [
    ("a", "identify", "Risk Analysis & Information Security Policies"),
    ("b", "respond",  "Incident Handling"),
    ("c", "recover",  "Business Continuity & Disaster Recovery"),
    ("d", "identify", "Supply Chain Security"),
    ("e", "protect",  "Network & Information Systems Security"),
    ("f", "identify", "Effectiveness Assessment Policies"),
    ("g", "protect",  "Cyber Hygiene & Cybersecurity Training"),
    ("h", "protect",  "Cryptography & Encryption Policies"),
    ("i", "protect",  "HR Security, Access Control & Asset Management"),
    ("j", "protect",  "Multi-Factor Authentication & Continuous Authentication"),
]

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
                # --- Insert organisation (idempotent by name) --------------------
                cur.execute(
                    """
                    INSERT INTO organisations
                        (name, industry, country, size, entity_type,
                         registration_number, contact_email)
                    VALUES
                        (%(name)s, %(industry)s, %(country)s, %(size)s, %(entity_type)s,
                         %(registration_number)s, %(contact_email)s)
                    ON CONFLICT DO NOTHING
                    RETURNING id;
                    """,
                    {
                        "name": "Acme Energy GmbH",
                        "industry": "energy",
                        "country": "DE",
                        "size": "large",
                        "entity_type": "essential",
                        "registration_number": "HRB-654321-B",
                        "contact_email": "compliance@acme-energy.example.com",
                    },
                )
                row = cur.fetchone()
                if row:
                    org_id = row[0]
                else:
                    cur.execute(
                        "SELECT id FROM organisations WHERE name = %s;",
                        ("Acme Energy GmbH",),
                    )
                    org_id = cur.fetchone()[0]
                print(f"Organisation id: {org_id}")

                # --- Insert assessment (idempotent by org_id + title) -----------
                cur.execute(
                    """
                    INSERT INTO assessments
                        (org_id, title, status, framework_version, assessor)
                    VALUES
                        (%(org_id)s, %(title)s, %(status)s,
                         %(framework_version)s, %(assessor)s)
                    ON CONFLICT DO NOTHING
                    RETURNING id;
                    """,
                    {
                        "org_id": org_id,
                        "title": "NIS2 Article 21 Initial Assessment 2026",
                        "status": "draft",
                        "framework_version": "NIS2-2022/0383",
                        "assessor": "system",
                    },
                )
                row = cur.fetchone()
                if row:
                    assessment_id = row[0]
                else:
                    cur.execute(
                        """
                        SELECT id FROM assessments
                        WHERE org_id = %s AND title = %s;
                        """,
                        (org_id, "NIS2 Article 21 Initial Assessment 2026"),
                    )
                    assessment_id = cur.fetchone()[0]
                print(f"Assessment id: {assessment_id}")

                # --- Insert controls for measures a–j (idempotent) ---------------
                controls_inserted = 0
                for measure_ref, nist_category, title in MEASURES:
                    cur.execute(
                        """
                        INSERT INTO controls
                            (assessment_id, article_ref, measure_ref,
                             nist_category, title, status)
                        VALUES
                            (%(assessment_id)s, %(article_ref)s, %(measure_ref)s,
                             %(nist_category)s, %(title)s, %(status)s)
                        ON CONFLICT DO NOTHING;
                        """,
                        {
                            "assessment_id": assessment_id,
                            "article_ref": f"Art.21(2)({measure_ref})",
                            "measure_ref": measure_ref,
                            "nist_category": nist_category,
                            "title": title,
                            "status": "not_assessed",
                        },
                    )
                    controls_inserted += cur.rowcount

    finally:
        conn.close()

    print(f"Seeded organisation, assessment, and {controls_inserted} controls.")


if __name__ == "__main__":
    main()
