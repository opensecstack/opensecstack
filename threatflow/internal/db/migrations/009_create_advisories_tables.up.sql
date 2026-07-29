-- CSAF 2.0 advisories pushed by OpenCSIRT (POST /api/v1/advisories). Each
-- CSAF vulnerabilities[] entry is mapped to a STIX 2.1 "vulnerability"
-- object (stored in the existing stix_objects table, referenced here via
-- stix_object_ref) so CVE data is queryable/correlatable through the same
-- canonical STIX path as every other ingestion source (ADR-001). CSAF-only
-- structure that has no clean STIX 2.1 equivalent — product_tree and
-- remediations — is kept in these dedicated tables instead of being forced
-- into a STIX object. See threatflow/adrs/004-opencsirt-advisory-ingestion-gap.md.

-- advisories: one row per CSAF document.tracking.id, holding the *current*
-- (latest-known) revision. Dedup/revision key is (tracking_id, revision) —
-- see advisory_revisions for the append-only history of every revision
-- received.
CREATE TABLE IF NOT EXISTS advisories (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tracking_id           VARCHAR(128) NOT NULL UNIQUE,
    csaf_version          VARCHAR(10) NOT NULL DEFAULT '2.0',
    revision              VARCHAR(32) NOT NULL DEFAULT '1',
    category              VARCHAR(64) NOT NULL,
    title                 TEXT NOT NULL,
    lang                  VARCHAR(16) NOT NULL DEFAULT 'en',
    status                VARCHAR(10) NOT NULL DEFAULT 'final' CHECK (status IN ('draft', 'final', 'interim')),
    tlp_label             VARCHAR(16) NOT NULL CHECK (tlp_label IN ('CLEAR', 'GREEN', 'AMBER', 'RED')),
    publisher_name        VARCHAR(255) NOT NULL,
    publisher_category    VARCHAR(32) NOT NULL,
    publisher_namespace   TEXT,
    initial_release_date  TIMESTAMPTZ NOT NULL,
    current_release_date  TIMESTAMPTZ NOT NULL,
    source                VARCHAR(255) NOT NULL DEFAULT 'opencsirt',
    stix_bundle_id        UUID REFERENCES stix_bundles(id) ON DELETE SET NULL,
    raw_document          JSONB NOT NULL,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_advisories_tracking_id ON advisories(tracking_id);
CREATE INDEX idx_advisories_source ON advisories(source);
CREATE INDEX idx_advisories_tlp ON advisories(tlp_label);
CREATE INDEX idx_advisories_current_release ON advisories(current_release_date DESC);
CREATE INDEX idx_advisories_search ON advisories USING GIN (to_tsvector('english', title));

-- advisory_revisions: append-only audit trail. One row per distinct
-- (advisory_id, revision) actually received — a re-POST of an
-- already-seen revision hits the unique constraint and is treated as a
-- no-op duplicate by the ingestion handler (idempotent re-delivery), never
-- silently dropped from the audit trail.
CREATE TABLE IF NOT EXISTS advisory_revisions (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id   UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    revision      VARCHAR(32) NOT NULL,
    document_hash CHAR(64) NOT NULL,
    raw_document  JSONB NOT NULL,
    received_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT advisory_revisions_dedup UNIQUE (advisory_id, revision)
);

CREATE INDEX idx_advisory_revisions_advisory ON advisory_revisions(advisory_id);

-- advisory_vulnerabilities: one row per CSAF vulnerabilities[] entry of the
-- *current* revision. stix_object_ref points at the STIX 2.1 "vulnerability"
-- object (stix_objects.stix_id) this entry was mapped to.
CREATE TABLE IF NOT EXISTS advisory_vulnerabilities (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id       UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    cve               VARCHAR(50),
    title             TEXT NOT NULL,
    notes             JSONB NOT NULL DEFAULT '[]',
    product_status    JSONB NOT NULL DEFAULT '{}',
    scores            JSONB NOT NULL DEFAULT '[]',
    references_json   JSONB NOT NULL DEFAULT '[]',
    stix_object_ref   VARCHAR(128) REFERENCES stix_objects(stix_id) ON DELETE SET NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_advisory_vulns_advisory ON advisory_vulnerabilities(advisory_id);
CREATE INDEX idx_advisory_vulns_cve ON advisory_vulnerabilities(cve) WHERE cve IS NOT NULL;

-- advisory_remediations: CSAF vulnerabilities[].remediations[] — no STIX 2.1
-- equivalent exists (STIX has no first-class "remediation" SDO), kept here
-- verbatim and cross-referenced to its parent vulnerability row.
CREATE TABLE IF NOT EXISTS advisory_remediations (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vulnerability_id  UUID NOT NULL REFERENCES advisory_vulnerabilities(id) ON DELETE CASCADE,
    category          VARCHAR(32) NOT NULL CHECK (category IN (
        'mitigation', 'no_fix_planned', 'none_available', 'vendor_fix', 'workaround'
    )),
    details           TEXT NOT NULL,
    product_ids       TEXT[] NOT NULL DEFAULT '{}',
    url               TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_advisory_remediations_vuln ON advisory_remediations(vulnerability_id);

-- advisory_products: CSAF product_tree.full_product_names[] — likewise no
-- STIX 2.1 equivalent (STIX's "software" SCO is a poor fit for CPE/PURL
-- product identity plus advisory-scoped product_id references used by
-- remediations/product_status), kept here verbatim.
CREATE TABLE IF NOT EXISTS advisory_products (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id  UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
    product_id   VARCHAR(255) NOT NULL,
    name         TEXT NOT NULL,
    cpe          TEXT,
    purl         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT advisory_products_dedup UNIQUE (advisory_id, product_id)
);

CREATE INDEX idx_advisory_products_advisory ON advisory_products(advisory_id);
