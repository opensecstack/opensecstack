-- CITADEL — Compliance Evidence ingestion (NIS2 Compass -> CITADEL push
-- pipeline). See docs/v1.0.0-readiness-roadmap.md Phase 5 and root
-- CLAUDE.md's SDK-contract table ("Compliance Evidence | JSON v1").
--
-- Design: compliance evidence is not a MARSHAL-governed action (no
-- authorization verdict is needed — the caller isn't asking permission to
-- do something, it's depositing a record for later audit), so it does not
-- go through marshal_decisions. It IS an audit-relevant event, so per root
-- CLAUDE.md's Governance & Audit section it MUST still flow through the
-- WORM chain (worm_entries, TripleHash-protected) rather than existing as a
-- parallel shadow log — hence worm_entry_id below is NOT NULL and
-- references worm_entries(id), the same FK pattern marshal_decisions
-- already uses for its own worm_entry_id column in 000001_initial.
--
-- The full report body is stored here (not just a hash reference) so
-- GET /api/v1/evidence/{id} can actually return the submitted evidence to
-- an auditor without a second round-trip to NIS2 Compass, which may have
-- since mutated or deleted the underlying assessment. report_hash is kept
-- alongside as a fast, storage-independent integrity check (SHA-256 of the
-- exact bytes NIS2 Compass sent), separate from the WORM entry's own
-- TripleHash of the full envelope.

BEGIN;

CREATE TABLE IF NOT EXISTS compliance_evidence (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    organisation_id  TEXT        NOT NULL,
    assessment_id    TEXT        NOT NULL,
    schema_version   TEXT        NOT NULL,
    report_hash      TEXT        NOT NULL,  -- hex SHA-256 of the raw report bytes
    report           JSONB       NOT NULL,  -- full evidence report body, verbatim
    submitted_by     TEXT        NOT NULL,  -- sinauth subject verified from actor_token
    worm_entry_id    UUID        NOT NULL REFERENCES worm_entries(id),
    submitted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_compliance_evidence_org_assessment
    ON compliance_evidence (organisation_id, assessment_id);
CREATE INDEX IF NOT EXISTS idx_compliance_evidence_submitted_at
    ON compliance_evidence (submitted_at);

COMMIT;
