-- SPDX-License-Identifier: Apache-2.0
-- Migration 002: environments table

CREATE TABLE IF NOT EXISTS environments (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    name        text        NOT NULL UNIQUE,
    kind        text        NOT NULL CHECK (kind IN ('docker', 'wasm')),
    target_url  text        NOT NULL,
    network_id  text,
    status      text        NOT NULL DEFAULT 'ready' CHECK (status IN ('ready', 'running', 'teardown', 'error')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS environments_status_idx ON environments (status);
