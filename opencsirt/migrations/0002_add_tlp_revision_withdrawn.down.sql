ALTER TABLE constituencies DROP COLUMN IF EXISTS tlp_default;
ALTER TABLE advisories DROP COLUMN IF EXISTS revision;
ALTER TABLE advisories DROP COLUMN IF EXISTS withdrawn_at;
ALTER TABLE advisories DROP CONSTRAINT IF EXISTS advisories_tlp_check;
ALTER TABLE advisories ALTER COLUMN tlp SET DEFAULT 'GREEN';
ALTER TABLE advisories ADD CONSTRAINT advisories_tlp_check
    CHECK (tlp IN ('CLEAR', 'GREEN', 'AMBER', 'RED'));
