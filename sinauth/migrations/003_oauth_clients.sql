-- sinauth: registered OAuth2 client applications
CREATE TABLE IF NOT EXISTS oauth_clients (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id          TEXT UNIQUE NOT NULL,
    client_secret_hash TEXT,
    name               TEXT NOT NULL,
    logo_url           TEXT,
    redirect_uris      TEXT[]  NOT NULL DEFAULT '{}',
    allowed_scopes     TEXT[]  NOT NULL DEFAULT '{openid,profile,email}',
    grant_types        TEXT[]  NOT NULL DEFAULT '{authorization_code,refresh_token}',
    require_pkce       BOOLEAN NOT NULL DEFAULT true,
    is_confidential    BOOLEAN NOT NULL DEFAULT true,
    created_by         TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
