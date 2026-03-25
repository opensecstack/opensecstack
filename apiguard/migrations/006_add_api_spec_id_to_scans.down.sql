ALTER TABLE findings DROP COLUMN IF EXISTS owasp_category;
ALTER TABLE scans    DROP COLUMN IF EXISTS api_spec_id;
DROP INDEX IF EXISTS idx_scans_api_spec_id;
