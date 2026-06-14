-- SPDX-License-Identifier: Apache-2.0
-- Migration 001: scenarios table

CREATE TABLE IF NOT EXISTS scenarios (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name                text        NOT NULL UNIQUE,
    description         text,
    mitre_technique_ids text[]      NOT NULL DEFAULT '{}',
    tags                text[]      NOT NULL DEFAULT '{}',
    severity            text        NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    timeout_seconds     int         NOT NULL DEFAULT 300,
    yaml_content        text        NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scenarios_severity_idx ON scenarios (severity);
CREATE INDEX IF NOT EXISTS scenarios_tags_idx     ON scenarios USING gin (tags);
