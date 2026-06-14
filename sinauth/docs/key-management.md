# Key Management

sinauth uses RSA-2048 asymmetric keys to sign all tokens. This page explains why, how to generate keys, how to store them safely, and how to rotate them without downtime.

## Why asymmetric signing (RS256)

sinauth signs tokens with a **private key** that only sinauth holds. Any platform can **verify** tokens using the corresponding **public key**, which sinauth publishes at `/.well-known/jwks.json`.

This is the critical advantage of RS256 (RSA) over HS256 (HMAC):

- **HS256**: both sinauth and every platform must share the same secret key. If any platform is compromised, the signing secret is exposed and all tokens across all platforms are at risk.
- **RS256**: platforms only ever see the public key. A compromised platform cannot forge tokens. The private key never leaves sinauth.

RSA-2048 provides approximately 112 bits of security, which is the NIST-recommended minimum through 2030.

## Generating a key

```bash
make keys-generate
```

This runs:

```bash
go run ./cmd/sinauth keys generate
```

The command generates a new RSA-2048 private key and writes it as a PKCS#1 PEM file to the path configured in `SINAUTH_SIGNING_KEY_PATH`. The file is created with permissions `0600` (read/write for owner only).

If the file already exists, the command exits without overwriting it.

To generate to a custom path:

```bash
go run ./cmd/sinauth keys generate --path /etc/sinauth/keys/sinauth.pem
```

## Key storage

### Development

The key lives at `./dev-keys/sinauth.pem` (relative to the project root). This directory is in `.gitignore`. The Docker Compose dev stack mounts it as a volume into the container.

### Production

The key file must be:
- Readable by the sinauth process user only (`chmod 0600`)
- Located on persistent storage that survives container restarts
- **Never committed to git** — add `*.pem` and your key directory to `.gitignore`

Recommended storage options:

| Option | How |
|---|---|
| Kubernetes Secret | Mount as a volume; set `SINAUTH_SIGNING_KEY_PATH` to the mount path |
| HashiCorp Vault | Use the Vault agent to write the PEM to a tmpfs mount at startup |
| AWS Secrets Manager | Retrieve at startup and write to a tmpfs file |
| Docker secret | `docker secret create sinauth_key sinauth.pem`, mount in compose |

### PEM format

The file must be a PKCS#1 RSA private key PEM:

```
-----BEGIN RSA PRIVATE KEY-----
<base64-encoded DER>
-----END RSA PRIVATE KEY-----
```

sinauth will refuse to start if the PEM block type is not `RSA PRIVATE KEY`.

## Key rotation strategy

Rotating the signing key without downtime requires a brief overlap period where both the old and new keys are valid for verification.

### Step 1: Generate the new key

Generate the new key file on the sinauth host:

```bash
go run ./cmd/sinauth keys generate --path /etc/sinauth/keys/sinauth-2.pem
```

### Step 2: Add the new key to JWKS (planned v1.1 feature)

In v1.0, sinauth serves a single key. For zero-downtime rotation before multi-key JWKS is available:

1. Update `SINAUTH_SIGNING_KEY_PATH` to point to the new key file.
2. Update `SINAUTH_SIGNING_KEY_ID` to a new value (e.g., `sinauth-2`).
3. Restart sinauth. New tokens are now signed with the new key.

Platforms that cache the JWKS will see a `kid` mismatch on existing tokens. Their JWKS cache TTL is 1 hour (`Cache-Control: max-age=3600`). During this window, platforms will re-fetch the JWKS automatically on `kid` mismatch.

Access tokens expire after 1 hour — after one hour all tokens signed with the old key will have expired naturally.

### Step 3: Remove the old key

After the access token TTL has elapsed (1 hour), all outstanding tokens signed with the old key are expired. You can safely delete the old key file.

Refresh tokens (30-day TTL) are opaque — they are verified by database lookup, not by JWT signature. They are not affected by key rotation.

### Future: multi-key JWKS (v1.1)

v1.1 will support publishing multiple public keys in the JWKS response simultaneously, enabling seamless zero-downtime rotation without a cache-expiry window.

## What not to do

- Never commit `.pem` files to git. Add a pre-commit hook if needed: `git secrets --add --literal '-----BEGIN RSA PRIVATE KEY-----'`
- Never copy the private key to platform servers. Platforms only need the JWKS URL.
- Never log the private key or include it in error messages.
- Never use the same key across environments (dev, staging, production use separate keys).
