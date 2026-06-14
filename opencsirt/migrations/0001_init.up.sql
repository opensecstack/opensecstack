-- OpenCSIRT v1.0.0 initial schema.
-- AGPL-3.0-or-later.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ── constituencies ────────────────────────────────────────────────────
CREATE TABLE constituencies (
    id                       uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                     text NOT NULL,
    sector                   text NOT NULL,
    country                  text NOT NULL,
    nis2_status              text NOT NULL CHECK (nis2_status IN ('essential', 'important', 'out_of_scope')),
    primary_contact_email    text NOT NULL,
    secondary_contact_email  text,
    created_at               timestamptz NOT NULL DEFAULT now(),
    updated_at               timestamptz NOT NULL DEFAULT now(),
    UNIQUE (name, country)
);

CREATE INDEX idx_constituencies_sector ON constituencies(sector);
CREATE INDEX idx_constituencies_nis2_status ON constituencies(nis2_status);

-- ── incidents ─────────────────────────────────────────────────────────
CREATE TABLE incidents (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    constituency_id   uuid REFERENCES constituencies(id) ON DELETE SET NULL,
    source            text NOT NULL CHECK (source IN ('irflow', 'manual', 'abuse_mailbox', 'peer_csirt')),
    severity          text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status            text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'triaged', 'contained', 'closed')),
    title             text NOT NULL,
    description       text NOT NULL DEFAULT '',
    opened_at         timestamptz NOT NULL DEFAULT now(),
    closed_at         timestamptz,
    citadel_emitted   boolean NOT NULL DEFAULT false,
    metadata          jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_incidents_constituency_id ON incidents(constituency_id);
CREATE INDEX idx_incidents_status_opened ON incidents(status, opened_at DESC);
CREATE INDEX idx_incidents_severity ON incidents(severity);

-- ── peer_csirts ──────────────────────────────────────────────────────
CREATE TABLE peer_csirts (
    id                  uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                text NOT NULL UNIQUE,
    jurisdiction        text NOT NULL,
    contact_endpoint    text NOT NULL,
    pgp_key             text,
    last_handshake_at   timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now()
);

-- ── advisories ───────────────────────────────────────────────────────
CREATE TABLE advisories (
    id                uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id       uuid REFERENCES incidents(id) ON DELETE SET NULL,
    csaf_id           text NOT NULL UNIQUE,
    csaf_version      text NOT NULL DEFAULT '2.0',
    csaf_doc          jsonb NOT NULL,
    state             text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'withdrawn')),
    tlp               text NOT NULL DEFAULT 'green' CHECK (tlp IN ('clear', 'green', 'amber', 'red')),
    title             text NOT NULL,
    summary           text NOT NULL DEFAULT '',
    published_at      timestamptz,
    published_by      uuid,
    citadel_emitted   boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_advisories_state ON advisories(state);
CREATE INDEX idx_advisories_published_at ON advisories(published_at DESC NULLS LAST);

-- ── escalations ──────────────────────────────────────────────────────
CREATE TABLE escalations (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    incident_id   uuid NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    peer_id       uuid NOT NULL REFERENCES peer_csirts(id) ON DELETE RESTRICT,
    sent_at       timestamptz NOT NULL DEFAULT now(),
    ack_at        timestamptz,
    response      jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (incident_id, peer_id)
);

CREATE INDEX idx_escalations_incident ON escalations(incident_id);

-- ── citadel_outbox ───────────────────────────────────────────────────
-- Pattern from OpenScrub mitigations state machine: every CITADEL event
-- lands here with state pending|sent|failed; the watcher emits and only
-- transitions to sent on durable confirmation.
CREATE TABLE citadel_outbox (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_id      text NOT NULL UNIQUE,
    event_type    text NOT NULL,
    payload       jsonb NOT NULL,
    state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'sending', 'sent', 'failed')),
    attempts      int NOT NULL DEFAULT 0,
    last_error    text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    sent_at       timestamptz,
    target_type   text NOT NULL,
    target_id     uuid
);

CREATE INDEX idx_citadel_outbox_state_created ON citadel_outbox(state, created_at);

-- ── audit_log ────────────────────────────────────────────────────────
-- Read-side and non-CITADEL audit trail (CITADEL handles privileged
-- write actions; this table captures listing, viewing, login, etc.
-- so a forensic timeline is reconstructable).
CREATE TABLE audit_log (
    id            uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    actor_id      uuid,
    actor_role    text,
    action        text NOT NULL,
    target_type   text,
    target_id     uuid,
    metadata      jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_log_actor ON audit_log(actor_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at DESC);

-- ── ioc_ingest_log (ThreatFlow puller) ───────────────────────────────
CREATE TABLE ioc_ingest_log (
    id              uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    source          text NOT NULL,
    bundle_sha256   text NOT NULL,
    count           int NOT NULL,
    ingested_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_ioc_ingest_log_source_ingested ON ioc_ingest_log(source, ingested_at DESC);
