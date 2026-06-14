-- Module 6 (Identity Verification) — scan persistence.
CREATE TABLE IF NOT EXISTS identity_scans (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id           TEXT NOT NULL UNIQUE,
  classification    TEXT NOT NULL,
  confidence        DOUBLE PRECISION NOT NULL,
  claim_hash        TEXT NOT NULL,
  claim_type        TEXT NOT NULL,
  context           TEXT NOT NULL,
  indicator_count   INTEGER NOT NULL DEFAULT 0,
  indicators        JSONB NOT NULL DEFAULT '[]'::jsonb,
  worm_entry_id     TEXT,
  duration_ms       DOUBLE PRECISION NOT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_identity_scans_created_at
  ON identity_scans (created_at DESC);

-- Enables future DB-layer replay detection without a table scan.
CREATE INDEX IF NOT EXISTS idx_identity_scans_claim_hash
  ON identity_scans (claim_hash);

CREATE INDEX IF NOT EXISTS idx_identity_scans_classification_created_at
  ON identity_scans (classification, created_at DESC);
