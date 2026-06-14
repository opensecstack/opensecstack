CREATE TABLE api_specs (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    spec_hash      VARCHAR(64) NOT NULL UNIQUE,          -- SHA-256 of raw spec content
    spec_url       TEXT,                                  -- origin URL if fetched remotely
    spec_format    VARCHAR(20) NOT NULL DEFAULT 'openapi3', -- openapi3 | swagger2 | graphql
    title          TEXT,
    version        TEXT,
    base_url       TEXT,
    endpoint_count INT NOT NULL DEFAULT 0,
    auth_schemes   JSONB NOT NULL DEFAULT '[]',           -- parsed auth scheme names
    raw_spec       TEXT,                                  -- raw spec content (nullable — large)
    parsed_ir      JSONB NOT NULL DEFAULT '{}',           -- parsed APIGuard IR
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_specs_spec_hash  ON api_specs(spec_hash);
CREATE INDEX idx_api_specs_created_at ON api_specs(created_at DESC);
