-- Identity providers configured by admins (SAML, OIDC upstream, LDAP)
CREATE TABLE IF NOT EXISTS identity_providers (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL UNIQUE,        -- display name e.g. "AKSHI Azure AD"
    slug         TEXT NOT NULL UNIQUE,        -- URL-safe e.g. "akshi-azure-ad"
    type         TEXT NOT NULL CHECK (type IN ('saml', 'oidc', 'ldap')),
    enabled      BOOLEAN NOT NULL DEFAULT true,
    -- SAML fields
    saml_metadata_url     TEXT,
    saml_metadata_xml     TEXT,
    saml_entity_id        TEXT,
    saml_sso_url          TEXT,
    saml_certificate      TEXT,
    -- OIDC upstream fields
    oidc_issuer           TEXT,
    oidc_client_id        TEXT,
    oidc_client_secret    TEXT,
    oidc_scopes           TEXT[] NOT NULL DEFAULT '{"openid","profile","email"}',
    -- LDAP fields
    ldap_url              TEXT,              -- e.g. ldap://dc.example.com:389
    ldap_bind_dn          TEXT,
    ldap_bind_password    TEXT,
    ldap_base_dn          TEXT,
    ldap_user_filter      TEXT DEFAULT '(sAMAccountName={username})',
    ldap_attr_username    TEXT DEFAULT 'sAMAccountName',
    ldap_attr_email       TEXT DEFAULT 'mail',
    ldap_attr_display     TEXT DEFAULT 'displayName',
    ldap_tls              BOOLEAN NOT NULL DEFAULT true,
    -- Attribute mapping
    attr_map_username     TEXT DEFAULT 'sub',
    attr_map_email        TEXT DEFAULT 'email',
    attr_map_display_name TEXT DEFAULT 'name',
    attr_map_role         TEXT DEFAULT '',   -- claim/attr to map to sinauth role; empty = default_role
    default_role          TEXT NOT NULL DEFAULT 'viewer',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Links sinauth users to their external identity
CREATE TABLE IF NOT EXISTS federated_identities (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    external_id TEXT NOT NULL,   -- subject/NameID from external IDP
    email       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider_id, external_id)
);
CREATE INDEX IF NOT EXISTS idx_federated_identities_user_id ON federated_identities(user_id);

-- SAML relay state for in-progress flows
CREATE TABLE IF NOT EXISTS saml_relay_states (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    relay_state TEXT NOT NULL UNIQUE,
    redirect_uri TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes'
);

-- OIDC upstream state/nonce for in-progress flows
CREATE TABLE IF NOT EXISTS oidc_upstream_states (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id UUID NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    state       TEXT NOT NULL UNIQUE,
    nonce       TEXT NOT NULL,
    redirect_uri TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL DEFAULT now() + interval '10 minutes'
);
