# PKCE

## Why PKCE?

PKCE (Proof Key for Code Exchange, RFC 7636) solves a specific attack: **authorization code interception**.

In the Authorization Code flow, after the user authenticates at sinauth, sinauth redirects the browser back to the platform with an authorization `code` in the URL:

```
https://platform.sin.to/callback?code=abc123&state=...
```

Without PKCE, any application that can observe this URL (a malicious app registered for the same URL scheme on mobile, a browser extension, or a compromised redirect handler) can steal the `code` and exchange it for tokens before the legitimate platform can.

PKCE prevents this by cryptographically binding the authorization code to the specific instance of the flow that started it. Even if an attacker gets the code, they cannot use it — they don't have the proof key.

## The S256 method

sinauth requires `code_challenge_method=S256` (SHA-256). The plain method is not supported.

### Step 1: Generate a code_verifier

The `code_verifier` is a cryptographically random string, 43–128 characters long, using the URL-safe base64 alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, `~`).

```go
// Go
verifierBytes := make([]byte, 48)
rand.Read(verifierBytes)
codeVerifier := base64.RawURLEncoding.EncodeToString(verifierBytes)
```

```typescript
// TypeScript / Node.js
const verifierBytes = crypto.randomBytes(48);
const codeVerifier = verifierBytes.toString('base64url');
```

```bash
# Shell
VERIFIER=$(openssl rand -base64 48 | tr -d '=+/' | cut -c1-64)
```

### Step 2: Compute the code_challenge

```
code_challenge = BASE64URL(SHA-256(ASCII(code_verifier)))
```

```go
// Go
h := sha256.Sum256([]byte(codeVerifier))
codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])
```

```typescript
// TypeScript / Node.js
const hash = crypto.createHash('sha256').update(codeVerifier).digest();
const codeChallenge = hash.toString('base64url');
```

```bash
# Shell
CHALLENGE=$(echo -n "$VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '+/' '-_')
```

### Step 3: Send code_challenge in the authorization request

```
GET /oauth/authorize
  ?response_type=code
  &client_id=myclient
  &redirect_uri=https://myplatform.sin.to/callback
  &scope=openid profile email
  &state=<random>
  &code_challenge=<code_challenge>
  &code_challenge_method=S256
```

sinauth stores `code_challenge` with the authorization code in the database.

### Step 4: Send code_verifier in the token request

```
POST /oauth/token
  grant_type=authorization_code
  &code=<authorization_code>
  &redirect_uri=https://myplatform.sin.to/callback
  &client_id=myclient
  &code_verifier=<code_verifier>
```

### Step 5: sinauth verifies

sinauth computes `SHA-256(code_verifier)` and compares it to the stored `code_challenge`. If they match, the exchange proceeds. If not, `invalid_grant` is returned.

This is implemented in `internal/oidc/pkce.go`:

```go
func VerifyS256(verifier, challenge string) error {
    h := sha256.Sum256([]byte(verifier))
    computed := base64.RawURLEncoding.EncodeToString(h[:])
    if computed != challenge {
        return ErrPKCEMismatch
    }
    return nil
}
```

## Security properties

- The `code_verifier` is never sent to sinauth during the authorization request — only its hash is. An attacker who can read the authorization request URL cannot reconstruct the verifier.
- The `code_verifier` is only sent once, over TLS, to the token endpoint. It cannot be reused because the authorization code is marked used after the first exchange.
- The one-time-use nature of authorization codes (enforced atomically in the database) means that even a replayed code+verifier pair fails on second use.
