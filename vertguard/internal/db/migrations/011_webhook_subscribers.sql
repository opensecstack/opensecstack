-- VG-015: persistent outbound webhook subscribers with 3-slot HMAC
-- rotation + outbox-pattern delivery. Coexists with the legacy
-- in-memory webhook_subscribers table from 002 — distinct purpose:
-- 002 was per-process ThreatFlow re-fanout, 011 is the durable
-- per-tenant subscriber registry that survives restart.
CREATE TABLE IF NOT EXISTS webhook_subscribers_v2 (
  id UUID PRIMARY KEY,
  tenant TEXT NOT NULL DEFAULT '',
  url TEXT NOT NULL,
  event_types TEXT[] NOT NULL DEFAULT '{}',
  -- 3-slot rotation: index 0 primary, 1 next, 2 previous. Aligned
  -- positionally with key_ids. Empty slots are stored as ''.
  hmac_secrets TEXT[] NOT NULL DEFAULT '{}',
  key_ids TEXT[] NOT NULL DEFAULT '{}',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_subscribers_v2_enabled
  ON webhook_subscribers_v2 (enabled) WHERE enabled = TRUE;

CREATE INDEX IF NOT EXISTS idx_webhook_subscribers_v2_event_types
  ON webhook_subscribers_v2 USING GIN (event_types);

-- Outbox pattern: the dispatcher writes here synchronously inside the
-- handler request and a background worker delivers + marks delivered.
-- Survives crash between event emit and HTTP POST to subscriber.
CREATE TABLE IF NOT EXISTS webhook_outbox (
  id UUID PRIMARY KEY,
  subscriber_id UUID NOT NULL,
  event_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  payload JSONB NOT NULL,
  attempts INT NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_webhook_outbox_pending
  ON webhook_outbox (next_attempt_at) WHERE delivered_at IS NULL;
