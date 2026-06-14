-- VG-006: ThreatFlow webhook subscribers.
CREATE TABLE IF NOT EXISTS webhook_subscribers (
  id UUID PRIMARY KEY,
  url TEXT NOT NULL,
  hmac_secret TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  filters JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_subscribers_active
  ON webhook_subscribers (active) WHERE active = TRUE;
