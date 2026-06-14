-- Add missing redirect URIs for sinauth/website (port 5174) and main website dev ports.
UPDATE oauth_clients
SET redirect_uris = ARRAY[
    'http://localhost:5173/auth/callback',
    'http://localhost:5174/auth/callback',
    'http://localhost:4173/auth/callback',
    'http://localhost:4174/auth/callback',
    'https://opensecstack.org/auth/callback'
]
WHERE client_id = 'homepage';
