-- SPDX-License-Identifier: Apache-2.0
-- Migration 003: scenario_runs table

CREATE TABLE IF NOT EXISTS scenario_runs (
    id                    uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario_id           uuid        NOT NULL REFERENCES scenarios (id) ON DELETE RESTRICT,
    environment_id        uuid        NOT NULL REFERENCES environments (id) ON DELETE RESTRICT,
    status                text        NOT NULL DEFAULT 'pending'
                                      CHECK (status IN ('pending', 'running', 'passed', 'failed', 'error')),
    started_at            timestamptz,
    finished_at           timestamptz,
    attack_events         jsonb       NOT NULL DEFAULT '[]',
    detection_events      jsonb       NOT NULL DEFAULT '[]',
    detection_latency_ms  int,
    detected              bool,
    notes                 text
);

CREATE INDEX IF NOT EXISTS scenario_runs_scenario_id_idx     ON scenario_runs (scenario_id);
CREATE INDEX IF NOT EXISTS scenario_runs_environment_id_idx  ON scenario_runs (environment_id);
CREATE INDEX IF NOT EXISTS scenario_runs_status_idx          ON scenario_runs (status);
CREATE INDEX IF NOT EXISTS scenario_runs_started_at_idx      ON scenario_runs (started_at DESC);
