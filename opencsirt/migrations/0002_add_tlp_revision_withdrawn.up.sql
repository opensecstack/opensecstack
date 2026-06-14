-- OpenCSIRT v1.0.0 — add constituency tlp_default, advisory revision + withdrawn_at,
-- and normalise advisory TLP values to lowercase for JSON/TS alignment.

-- constituencies: add tlp_default column (lowercase TLP values).
ALTER TABLE constituencies
    ADD COLUMN tlp_default text NOT NULL DEFAULT 'green'
        CHECK (tlp_default IN ('clear', 'green', 'amber', 'red'));

-- advisories: add revision counter and withdrawn_at timestamp.
ALTER TABLE advisories ADD COLUMN revision int NOT NULL DEFAULT 1;
ALTER TABLE advisories ADD COLUMN withdrawn_at timestamptz;

-- advisories: migrate TLP to lowercase and tighten constraint.
UPDATE advisories SET tlp = lower(tlp);
ALTER TABLE advisories DROP CONSTRAINT advisories_tlp_check;
ALTER TABLE advisories ALTER COLUMN tlp SET DEFAULT 'green';
ALTER TABLE advisories ADD CONSTRAINT advisories_tlp_check
    CHECK (tlp IN ('clear', 'green', 'amber', 'red'));
