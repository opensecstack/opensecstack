-- SPDX-License-Identifier: Apache-2.0
-- Migration 004: mitre_coverage table

CREATE TABLE IF NOT EXISTS mitre_coverage (
    technique_id      text           PRIMARY KEY,
    technique_name    text,
    tactic            text,
    scenario_count    int            NOT NULL DEFAULT 0,
    last_detected_at  timestamptz,
    detection_rate    numeric(5, 2)  NOT NULL DEFAULT 0.00
);

CREATE INDEX IF NOT EXISTS mitre_coverage_tactic_idx ON mitre_coverage (tactic);
