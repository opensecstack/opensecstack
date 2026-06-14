-- Public PKCE-only OAuth clients for the OpenSecStack platform ecosystem.
-- Each platform's web app initiates a popup PKCE flow against sinauth and
-- receives the authorization code at <origin>/auth/callback.
-- redirect_uris cover both the Vite dev port and the docker-compose web port.

INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, allowed_scopes, grant_types, require_pkce, is_confidential, created_by)
VALUES
  ('openscrub', NULL, 'OpenScrub',
   ARRAY['http://localhost:3087/auth/callback','http://localhost:3002/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('opencsirt', NULL, 'OpenCSIRT',
   ARRAY['http://localhost:3088/auth/callback','http://localhost:3003/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('cyberpath', NULL, 'CyberPath',
   ARRAY['http://localhost:3006/auth/callback','http://localhost:3004/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('securelab', NULL, 'SecureLab',
   ARRAY['http://localhost:3085/auth/callback','http://localhost:3005/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('vertguard', NULL, 'VertGuard',
   ARRAY['http://localhost:3009/auth/callback','http://localhost:3007/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('apiguard', NULL, 'APIGuard',
   ARRAY['http://localhost:3000/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  ('nis2compass', NULL, 'NIS2 Compass',
   ARRAY['http://localhost:3001/auth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system'),

  -- SIN Community uses a server-side OAuth flow; its callback is on the API origin.
  ('community', NULL, 'SIN Community',
   ARRAY['http://localhost:8089/api/v1/auth/sinauth/callback'],
   ARRAY['openid','profile','email'], ARRAY['authorization_code'], true, false, 'system')
ON CONFLICT (client_id) DO NOTHING;
