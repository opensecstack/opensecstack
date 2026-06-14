# @opensecstack/sinauth

TypeScript SDK for the **sinauth** identity provider. Provides RS256 JWT verification and OAuth2 PKCE helpers for frontend apps and Node.js services in the OpenSecStack suite.

## Installation

```bash
npm install @opensecstack/sinauth
```

## Quick Start

### Server-side token verification

```typescript
import { SinauthClient } from '@opensecstack/sinauth'

const sinauth = new SinauthClient('https://sinauth.example.com')

// Verify any token (checks RS256 signature + expiry + issuer)
const claims = await sinauth.verifyToken(accessToken)
console.log(claims.sub, claims.role, claims.client_roles)

// Verify token AND assert it was issued for a specific OAuth client
const claims = await sinauth.verifyTokenForClient(accessToken, 'community')

// Fetch user profile from sinauth userinfo endpoint
const userInfo = await sinauth.fetchUserInfo(accessToken)
console.log(userInfo.email, userInfo.name)

// Exchange an authorization code for tokens (PKCE or confidential client)
const tokens = await sinauth.exchangeCode({
  code: req.query.code,
  redirectUri: 'https://app.example.com/callback',
  clientID: 'community',
  codeVerifier: session.codeVerifier, // for PKCE flows
})
```

### Frontend PKCE flow

```typescript
import { generatePKCE, buildAuthURL, SinauthClient } from '@opensecstack/sinauth'

const sinauth = new SinauthClient('https://sinauth.example.com')

// Step 1 — Generate PKCE params and redirect the user
const { codeVerifier, codeChallenge, state } = await generatePKCE()
sessionStorage.setItem('pkce_verifier', codeVerifier)
sessionStorage.setItem('pkce_state', state)

const discovery = await sinauth.getDiscovery()
const authURL = buildAuthURL({
  authorizationEndpoint: discovery.authorization_endpoint,
  clientID: 'community',
  redirectURI: 'https://app.example.com/callback',
  scopes: ['openid', 'profile', 'email'],
  state,
  codeChallenge,
})
window.location.href = authURL

// Step 2 — Handle the callback (in your /callback route)
const params = new URLSearchParams(window.location.search)
if (params.get('state') !== sessionStorage.getItem('pkce_state')) throw new Error('state mismatch')

const tokens = await sinauth.exchangeCode({
  code: params.get('code')!,
  redirectUri: 'https://app.example.com/callback',
  clientID: 'community',
  codeVerifier: sessionStorage.getItem('pkce_verifier')!,
})
```

## API Reference

### `new SinauthClient(issuerURL: string)`

Creates a client pointed at the sinauth issuer. OIDC discovery and JWKS are fetched and cached on first use.

### `client.getDiscovery(): Promise<DiscoveryDocument>`

Fetches and caches the OIDC discovery document from `/.well-known/openid-configuration`.

### `client.verifyToken(token: string): Promise<SinauthClaims>`

Verifies an RS256-signed JWT: signature, expiry, and issuer. Returns typed claims.

### `client.verifyTokenForClient(token: string, clientID: string): Promise<SinauthClaims>`

Same as `verifyToken`, but additionally asserts the token belongs to the given OAuth client (by `client_id` claim or `aud`).

### `client.fetchUserInfo(accessToken: string): Promise<UserInfo>`

Calls the sinauth `/oauth/userinfo` endpoint with the given Bearer token.

### `client.exchangeCode(params): Promise<TokenResponse>`

Exchanges an authorization code for tokens. Supports PKCE (`codeVerifier`) and confidential clients (`clientSecret`).

### `generatePKCE(): Promise<{ codeVerifier, codeChallenge, state }>`

Generates a PKCE code verifier, its S256 challenge, and a random `state` value using the Web Crypto API (browser-compatible).

### `buildAuthURL(params): string`

Constructs an OAuth2 authorization URL with PKCE (`code_challenge_method=S256`).

## License

Apache-2.0
