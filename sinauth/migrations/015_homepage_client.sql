-- Public OAuth client for the opensecstack.org homepage "Try it live" demo.
-- No client_secret (public PKCE-only client).
INSERT INTO oauth_clients (
    client_id,
    client_secret_hash,
    name,
    redirect_uris,
    allowed_scopes,
    grant_types,
    require_pkce,
    is_confidential,
    created_by
) VALUES (
    'homepage',
    NULL,
    'OpenSecStack Homepage',
    ARRAY[
        'http://localhost:5173/auth/callback',
        'http://localhost:4173/auth/callback',
        'https://opensecstack.org/auth/callback'
    ],
    ARRAY['openid', 'profile', 'email'],
    ARRAY['authorization_code'],
    true,
    false,
    'system'
) ON CONFLICT (client_id) DO NOTHING;
