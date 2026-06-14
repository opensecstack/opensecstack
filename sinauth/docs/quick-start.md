# Quick Start

Get sinauth running locally in under five minutes.

## Prerequisites

- Go 1.25 or later
- Docker and Docker Compose
- `make`

A local PostgreSQL instance is not required — Docker Compose provides one.

## 1. Clone the repository

```bash
git clone https://github.com/opensecstack/sinauth.git
cd sinauth
```

## 2. Copy the environment file

```bash
cp .env.example .env
```

The defaults in `.env.example` work as-is for local development with Docker Compose. You do not need to edit anything for the first run.

## 3. Generate the RSA signing key

sinauth signs all tokens with an RSA-2048 private key. Generate it once:

```bash
make keys-generate
```

This runs `go run ./cmd/sinauth keys generate` and writes the key to the path configured in `SINAUTH_SIGNING_KEY_PATH` (default: `./dev-keys/sinauth.pem`). The file is created with mode `0600`. Never commit this file to git — it is already in `.gitignore`.

## 4. Start sinauth with Docker Compose

```bash
docker compose -f docker-compose.dev.yml up
```

This starts:
- **sinauth** on `http://localhost:8100`
- **PostgreSQL 16** on `localhost:5433` (database: `sinauth`, user: `sinauth`, password: `sinauth`)

On first startup sinauth runs in dev mode (`SINAUTH_DEV_MODE=true`), which relaxes config validation so you can start without all env vars set.

## 5. Run database migrations

In a second terminal:

```bash
make migrate DB_URL=postgres://sinauth:sinauth@localhost:5433/sinauth?sslmode=disable
```

This applies all SQL files under `migrations/` in order. Migrations are idempotent (`CREATE TABLE IF NOT EXISTS`).

## 6. Verify sinauth is live

```bash
curl -s http://localhost:8100/api/v1/health | jq .
# { "status": "ok" }

curl -s http://localhost:8100/.well-known/openid-configuration | jq .issuer
# "http://localhost:8100"
```

## 7. Inspect the OIDC discovery document

```bash
curl -s http://localhost:8100/.well-known/openid-configuration | jq .
```

You should see the full discovery document with all endpoints pointing to `http://localhost:8100`.

## 8. Register your first OAuth client (platform)

sinauth's admin API requires a bearer token. For local development, use the admin bootstrap flow or insert a client directly:

```bash
# Register a client via the admin API
# (replace <ADMIN_TOKEN> with a valid admin access token)
curl -s -X POST http://localhost:8100/api/v1/admin/clients \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "myclient",
    "name": "My Platform",
    "redirect_uris": ["http://localhost:3000/auth/callback"],
    "allowed_scopes": ["openid", "profile", "email"],
    "require_pkce": true,
    "is_confidential": false
  }' | jq .
```

For a quick local test without a token, you can insert directly into PostgreSQL:

```sql
INSERT INTO oauth_clients (client_id, name, redirect_uris, allowed_scopes, require_pkce, is_confidential)
VALUES ('myclient', 'My Platform', '{"http://localhost:3000/auth/callback"}', '{openid,profile,email}', true, false);
```

## 9. Test the login flow with curl

PKCE flow requires a `code_verifier` and `code_challenge`. Here is a minimal shell script:

```bash
# Generate PKCE values
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '+/' '-_')

echo "Verifier:  $VERIFIER"
echo "Challenge: $CHALLENGE"

# Step 1: Open the authorization URL in your browser
echo ""
echo "Open this URL in your browser:"
echo "http://localhost:8100/oauth/authorize?response_type=code&client_id=myclient&redirect_uri=http://localhost:3000/auth/callback&scope=openid%20profile%20email&state=test123&code_challenge=${CHALLENGE}&code_challenge_method=S256"
```

After logging in (or registering) you will be redirected to `http://localhost:3000/auth/callback?code=<CODE>&state=test123`.

```bash
# Step 2: Exchange the code for tokens
CODE=<paste code from redirect here>

curl -s -X POST http://localhost:8100/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=${CODE}" \
  -d "redirect_uri=http://localhost:3000/auth/callback" \
  -d "client_id=myclient" \
  -d "code_verifier=${VERIFIER}" | jq .
```

You will receive an `access_token`, `id_token`, and `refresh_token`.

## Next steps

- [Configuration](configuration.md) — all environment variables explained
- [Architecture](architecture.md) — how sinauth works internally
- [Integration guides](integration/) — platform-specific setup
