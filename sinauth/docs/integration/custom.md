# Integrating a Custom Platform with sinauth

This guide covers integrating any OIDC-compatible platform with sinauth using the Authorization Code + PKCE flow. Code examples are provided in Go and TypeScript.

## Prerequisites

1. sinauth is running and reachable at your issuer URL.
2. Your platform has been registered as an OAuth client in sinauth. See the [Admin Guide](../admin-guide.md#registering-a-new-oauth-client-platform).

## Client configuration

When registering your platform, you will need:

```
Issuer:               https://auth.sin.to
Authorization URL:    https://auth.sin.to/oauth/authorize
Token URL:            https://auth.sin.to/oauth/token
UserInfo URL:         https://auth.sin.to/oauth/userinfo
JWKS URL:             https://auth.sin.to/.well-known/jwks.json
Scopes:               openid profile email offline_access
Grant type:           authorization_code
PKCE method:          S256
Redirect URI:         https://yourplatform.sin.to/auth/callback
```

## Step 1: Redirect to sinauth

When the user clicks "Login", redirect them to the sinauth authorization endpoint.

### Go

```go
package auth

import (
    "crypto/rand"
    "crypto/sha256"
    "encoding/base64"
    "fmt"
    "net/http"
    "net/url"
)

const (
    issuer      = "https://auth.sin.to"
    clientID    = "myplatform"
    redirectURI = "https://myplatform.sin.to/auth/callback"
)

func generatePKCE() (verifier, challenge string, err error) {
    b := make([]byte, 48)
    if _, err = rand.Read(b); err != nil {
        return
    }
    verifier = base64.RawURLEncoding.EncodeToString(b)
    h := sha256.Sum256([]byte(verifier))
    challenge = base64.RawURLEncoding.EncodeToString(h[:])
    return
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
    verifier, challenge, err := generatePKCE()
    if err != nil {
        http.Error(w, "internal error", http.StatusInternalServerError)
        return
    }

    // Generate a random state value for CSRF protection
    stateBytes := make([]byte, 16)
    rand.Read(stateBytes)
    state := base64.RawURLEncoding.EncodeToString(stateBytes)

    // Store verifier and state in the user's session (use your session library)
    session := getSession(r)
    session.Set("pkce_verifier", verifier)
    session.Set("oauth_state", state)
    session.Save(w)

    params := url.Values{
        "response_type":         {"code"},
        "client_id":             {clientID},
        "redirect_uri":          {redirectURI},
        "scope":                 {"openid profile email offline_access"},
        "state":                 {state},
        "code_challenge":        {challenge},
        "code_challenge_method": {"S256"},
    }

    authURL := fmt.Sprintf("%s/oauth/authorize?%s", issuer, params.Encode())
    http.Redirect(w, r, authURL, http.StatusFound)
}
```

### TypeScript (Express)

```typescript
import crypto from 'crypto';
import express from 'express';

const ISSUER = 'https://auth.sin.to';
const CLIENT_ID = 'myplatform';
const REDIRECT_URI = 'https://myplatform.sin.to/auth/callback';

function generatePKCE(): { verifier: string; challenge: string } {
    const verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto
        .createHash('sha256')
        .update(verifier)
        .digest('base64url');
    return { verifier, challenge };
}

const router = express.Router();

router.get('/auth/login', (req, res) => {
    const { verifier, challenge } = generatePKCE();
    const state = crypto.randomBytes(16).toString('base64url');

    // Store in session (use express-session or similar)
    req.session.pkceVerifier = verifier;
    req.session.oauthState = state;

    const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: 'openid profile email offline_access',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
    });

    res.redirect(`${ISSUER}/oauth/authorize?${params.toString()}`);
});
```

## Step 2: Handle the callback and exchange the code

After the user authenticates and consents, sinauth redirects back to your `redirect_uri` with a `code` and `state` parameter.

### Go

```go
type TokenResponse struct {
    AccessToken  string `json:"access_token"`
    IDToken      string `json:"id_token"`
    RefreshToken string `json:"refresh_token"`
    TokenType    string `json:"token_type"`
    ExpiresIn    int    `json:"expires_in"`
}

func CallbackHandler(w http.ResponseWriter, r *http.Request) {
    // Validate state
    session := getSession(r)
    expectedState := session.Get("oauth_state")
    if r.URL.Query().Get("state") != expectedState {
        http.Error(w, "state mismatch", http.StatusBadRequest)
        return
    }

    code := r.URL.Query().Get("code")
    verifier := session.Get("pkce_verifier")

    // Exchange code for tokens
    resp, err := http.PostForm(issuer+"/oauth/token", url.Values{
        "grant_type":    {"authorization_code"},
        "code":          {code},
        "redirect_uri":  {redirectURI},
        "client_id":     {clientID},
        "code_verifier": {verifier},
    })
    if err != nil || resp.StatusCode != http.StatusOK {
        http.Error(w, "token exchange failed", http.StatusInternalServerError)
        return
    }
    defer resp.Body.Close()

    var tokens TokenResponse
    if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
        http.Error(w, "decode error", http.StatusInternalServerError)
        return
    }

    // Verify and parse the ID token (see Step 3)
    claims, err := verifyIDToken(tokens.IDToken)
    if err != nil {
        http.Error(w, "invalid id_token", http.StatusUnauthorized)
        return
    }

    // Establish a local session for the user
    session.Set("user_id", claims.Sub)
    session.Set("user_email", claims.Email)
    session.Set("access_token", tokens.AccessToken)
    session.Set("refresh_token", tokens.RefreshToken)
    session.Save(w)

    http.Redirect(w, r, "/dashboard", http.StatusFound)
}
```

### TypeScript (Express)

```typescript
import axios from 'axios';

router.get('/auth/callback', async (req, res) => {
    const { code, state, error } = req.query as Record<string, string>;

    if (error) {
        return res.status(400).send(`Auth error: ${error}`);
    }

    // Validate state
    if (state !== req.session.oauthState) {
        return res.status(400).send('State mismatch');
    }

    const verifier = req.session.pkceVerifier!;

    // Exchange code for tokens
    const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
        client_id: CLIENT_ID,
        code_verifier: verifier,
    });

    const { data: tokens } = await axios.post(
        `${ISSUER}/oauth/token`,
        params.toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    // Decode and verify the ID token (see Step 3)
    const claims = await verifyIDToken(tokens.id_token);

    // Store in session
    req.session.userId = claims.sub;
    req.session.email = claims.email;
    req.session.accessToken = tokens.access_token;
    req.session.refreshToken = tokens.refresh_token;

    res.redirect('/dashboard');
});
```

## Step 3: Verify the ID token

Verify the RS256 signature using sinauth's JWKS endpoint. Never skip this step — an unverified ID token is untrusted input.

### Go (using golang-jwt/jwt)

```go
import (
    "context"
    "crypto/rsa"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "math/big"
    "net/http"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5"
)

type IDTokenClaims struct {
    Sub           string `json:"sub"`
    Email         string `json:"email"`
    EmailVerified bool   `json:"email_verified"`
    Name          string `json:"name"`
    Picture       string `json:"picture"`
    Nonce         string `json:"nonce"`
    jwt.RegisteredClaims
}

var (
    jwksCache    map[string]*rsa.PublicKey
    jwksCacheMu  sync.RWMutex
    jwksCachedAt time.Time
)

func getPublicKey(kid string) (*rsa.PublicKey, error) {
    jwksCacheMu.RLock()
    if time.Since(jwksCachedAt) < time.Hour {
        key := jwksCache[kid]
        jwksCacheMu.RUnlock()
        if key != nil {
            return key, nil
        }
    }
    jwksCacheMu.RUnlock()

    // Fetch JWKS
    resp, err := http.Get(ISSUER + "/.well-known/jwks.json")
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    var jwks struct {
        Keys []struct {
            Kid string `json:"kid"`
            N   string `json:"n"`
            E   string `json:"e"`
        } `json:"keys"`
    }
    json.NewDecoder(resp.Body).Decode(&jwks)

    jwksCacheMu.Lock()
    jwksCache = make(map[string]*rsa.PublicKey)
    for _, k := range jwks.Keys {
        nb, _ := base64.RawURLEncoding.DecodeString(k.N)
        eb, _ := base64.RawURLEncoding.DecodeString(k.E)
        e := int(new(big.Int).SetBytes(eb).Int64())
        jwksCache[k.Kid] = &rsa.PublicKey{
            N: new(big.Int).SetBytes(nb),
            E: e,
        }
    }
    jwksCachedAt = time.Now()
    jwksCacheMu.Unlock()

    return jwksCache[kid], nil
}

func verifyIDToken(tokenString string) (*IDTokenClaims, error) {
    claims := &IDTokenClaims{}
    _, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
        if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
        }
        kid, _ := t.Header["kid"].(string)
        return getPublicKey(kid)
    }, jwt.WithIssuer(ISSUER), jwt.WithAudience(CLIENT_ID))
    if err != nil {
        return nil, err
    }
    return claims, nil
}
```

### TypeScript (using jose)

```typescript
import * as jose from 'jose';

const JWKS = jose.createRemoteJWKSet(
    new URL(`${ISSUER}/.well-known/jwks.json`)
);

async function verifyIDToken(token: string): Promise<jose.JWTPayload> {
    const { payload } = await jose.jwtVerify(token, JWKS, {
        issuer: ISSUER,
        audience: CLIENT_ID,
        algorithms: ['RS256'],
    });
    return payload;
}
```

## Step 4: Making authenticated API calls

Include the access token in requests to sinauth's UserInfo endpoint or any protected SIN platform API:

```go
req, _ := http.NewRequest("GET", ISSUER+"/oauth/userinfo", nil)
req.Header.Set("Authorization", "Bearer "+accessToken)
resp, _ := http.DefaultClient.Do(req)
```

```typescript
const { data: user } = await axios.get(`${ISSUER}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
});
```

## Step 5: Token refresh

When the access token expires (after 1 hour), use the refresh token to get a new one silently:

```go
resp, err := http.PostForm(issuer+"/oauth/token", url.Values{
    "grant_type":    {"refresh_token"},
    "refresh_token": {refreshToken},
    "client_id":     {clientID},
})
```

```typescript
const params = new URLSearchParams({
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    client_id: CLIENT_ID,
});

const { data: newTokens } = await axios.post(
    `${ISSUER}/oauth/token`,
    params.toString(),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
);
```

## Logout

Redirect the user to sinauth's end-session endpoint:

```
https://auth.sin.to/oauth/endsession
  ?post_logout_redirect_uri=https://myplatform.sin.to/
  &id_token_hint=<id_token>
```

Then clear the local session on your platform.
