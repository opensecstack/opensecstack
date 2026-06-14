# OpenID Connect (OIDC)

## What is OpenID Connect?

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0. OAuth 2.0 solves the problem of *authorization* — granting one application access to resources owned by a user on another service. OIDC extends OAuth 2.0 to solve *authentication* — letting an application verify who the user is.

Before OIDC, applications would use OAuth 2.0 to get an access token and then call a user-info API to figure out who the user was. Every OAuth provider did this differently. OIDC standardizes it.

## How OIDC extends OAuth 2.0

OIDC adds three things to OAuth 2.0:

1. **The `openid` scope**: When a client requests this scope, the authorization server knows that the client wants to authenticate the user, not just authorize resource access.

2. **The ID token**: A signed JWT returned alongside the access token. It contains claims about the authenticated user (who they are, when they authenticated, and for which client). The client application reads and verifies the ID token to establish identity without making an additional network call.

3. **The discovery document** (`/.well-known/openid-configuration`): A JSON document that describes all of the authorization server's endpoints, supported algorithms, and capabilities. Clients can discover sinauth's configuration automatically instead of being manually configured.

## ID token vs access token

Both are signed JWTs in sinauth, but they serve different purposes:

| | ID token | Access token |
|---|---|---|
| Audience | The client application | Resource servers (APIs) |
| Purpose | Prove who the user is | Authorize API calls |
| TTL | 5 minutes | 1 hour |
| Use | Read at login, verify claims, discard | Send as `Bearer` on every API request |
| Key claims | `sub`, `email`, `name`, `nonce`, `azp` | `sub`, `client_id`, `scope` |

**The ID token is for the client.** The client reads it, verifies the signature, and trusts the identity claims inside.

**The access token is for resource servers (APIs).** The client sends it to APIs as a `Bearer` token. The API verifies the signature and trusts the claims.

Never use the ID token as an API access credential. Never read user identity from the access token claims on the server side (use the ID token or the UserInfo endpoint instead).

## The discovery document

```
GET https://auth.sin.to/.well-known/openid-configuration
```

Returns a JSON document describing sinauth's configuration: all endpoint URLs, supported scopes, supported algorithms, and supported grant types. OIDC client libraries use this document to configure themselves automatically — you only need to provide the issuer URL.

## sinauth's OIDC support

sinauth implements:

- OpenID Connect Core 1.0 (authorization code flow with PKCE)
- OpenID Connect Discovery 1.0
- RFC 7517 (JSON Web Key Sets — JWKS)
- RFC 7519 (JSON Web Tokens)
- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE)
- RFC 7009 (Token Revocation)
- RFC 7662 (Token Introspection)
