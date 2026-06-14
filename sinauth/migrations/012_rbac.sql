-- Groups: collections of users that can be assigned roles en masse
CREATE TABLE IF NOT EXISTS groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_group_members_user_id ON group_members(user_id);

-- Roles defined per OAuth client (platform)
-- e.g. client "community" has roles: author, moderator, admin
CREATE TABLE IF NOT EXISTS client_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id   TEXT NOT NULL,   -- references oauth_clients.client_id
    name        TEXT NOT NULL,   -- e.g. "analyst", "admin", "viewer"
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (client_id, name)
);

-- User-level role assignments per client
CREATE TABLE IF NOT EXISTS user_client_roles (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    role_name  TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, client_id, role_name)
);
CREATE INDEX IF NOT EXISTS idx_user_client_roles_user ON user_client_roles(user_id);

-- Group-level role assignments per client (all group members inherit these roles)
CREATE TABLE IF NOT EXISTS group_client_roles (
    group_id   UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    client_id  TEXT NOT NULL,
    role_name  TEXT NOT NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, client_id, role_name)
);

-- Policies: rules evaluated at token issuance
-- Examples:
--   type=require_mfa: enforce MFA for users with role X in client Y
--   type=deny_role:   deny a specific role to users without email verified
CREATE TABLE IF NOT EXISTS policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    type        TEXT NOT NULL CHECK (type IN ('require_mfa','require_email_verified','deny_role','allow_client')),
    client_id   TEXT,        -- NULL = applies to all clients
    role_name   TEXT,        -- NULL = applies to all roles
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
