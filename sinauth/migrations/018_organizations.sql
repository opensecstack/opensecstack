-- Organizations: second identity subject alongside individual users
-- (ADR 005 v1.1 — organizations + membership, no client_credentials yet)
CREATE TABLE IF NOT EXISTS organizations (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name           TEXT NOT NULL,
    slug                 TEXT UNIQUE NOT NULL,
    org_type             TEXT NOT NULL CHECK (org_type IN ('government','private','ecommerce','ngo')),
    registration_number  TEXT,
    verified_at          TIMESTAMPTZ,
    verified_by          TEXT,
    status               TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','active','suspended')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS organization_members (
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_role        TEXT NOT NULL DEFAULT 'member' CHECK (org_role IN ('owner','admin','member')),
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Schema for workstream 2 (authorize/token flow); column lives here to avoid
-- two migrations touching authorization_codes.
ALTER TABLE authorization_codes ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES organizations(id);
