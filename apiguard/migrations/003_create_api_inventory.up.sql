CREATE TABLE api_inventory (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_url TEXT NOT NULL UNIQUE,
    spec_hash VARCHAR(64), -- latest known spec hash
    api_version VARCHAR(50),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_scanned_at TIMESTAMPTZ,
    scan_count INT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_inventory_target_url ON api_inventory(target_url);
