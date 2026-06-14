-- API keys authenticate ecosystem clients + human operators. Plaintext keys
-- are shown once at creation; only SHA-256 hashes are stored.
CREATE TABLE api_keys (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name          VARCHAR(255) NOT NULL,
    key_hash      CHAR(64) NOT NULL UNIQUE,
    role          VARCHAR(20) NOT NULL CHECK (role IN ('viewer', 'analyst', 'operator', 'admin')),
    enabled       BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at    TIMESTAMPTZ,
    last_used_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_api_keys_enabled ON api_keys(enabled) WHERE enabled = TRUE;
CREATE INDEX idx_api_keys_role ON api_keys(role);
