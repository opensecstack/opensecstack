# ADR 002: RS256 (RSA Asymmetric Signing) over HS256 (HMAC Symmetric)

**Status**: Accepted
**Date**: 2024-01-15
**Deciders**: sinauth core team

## Context

sinauth issues JWTs that platforms need to verify on every authenticated request. Two common JWT signing algorithms exist: HS256 (HMAC-SHA256, symmetric) and RS256 (RSASSA-PKCS1-v1_5 with SHA-256, asymmetric). The choice of algorithm has significant security and operational implications for a multi-platform identity system.

## Decision

We chose RS256 (RSA-2048 asymmetric signing) over HS256 (HMAC symmetric signing).

## Reasons

### Platforms can verify tokens without knowing the private key

With HS256, the same secret key is used to both sign and verify tokens. This means every SIN platform would need a copy of sinauth's signing secret. If any platform is compromised, the attacker has the signing secret and can forge tokens for any user on any platform.

With RS256, sinauth holds the RSA private key and uses it to sign tokens. Platforms verify tokens using the RSA public key, which sinauth publishes at `/.well-known/jwks.json`. The private key never leaves sinauth. A compromised platform cannot forge tokens.

In a 10-platform ecosystem, this is a critical security property: the blast radius of a single platform compromise is contained to that platform.

### JWKS endpoint enables key rotation without reconfiguring clients

With HS256, rotating the signing secret requires updating the secret in sinauth and in every platform simultaneously — a coordinated deployment across 10 services.

With RS256, sinauth publishes its current public key(s) at the JWKS endpoint. Platforms fetch this endpoint at startup and cache it for 1 hour. When sinauth rotates its key pair, it publishes the new public key in JWKS. Platforms automatically pick up the new key on cache expiry or on `kid` mismatch — no reconfiguration needed.

### Local verification without network calls

Platforms can verify RS256 tokens entirely locally using the cached public key. There is no need to call sinauth on every request. This means:
- Zero latency overhead for token verification
- No sinauth downtime impact on platform availability (platforms can verify existing tokens even if sinauth is temporarily unreachable)
- Linear scalability — verification throughput scales with platform CPU, not sinauth capacity

HS256 can also be verified locally, but it requires distributing the shared secret, which negates the locality benefit.

### Standard choice for authorization servers

RS256 is the algorithm specified in OpenID Connect Core 1.0 as the required algorithm for ID tokens (`id_token_signing_alg_values_supported`). It is the default in Auth0, Okta, Keycloak, and every other major OIDC provider. Using RS256 ensures sinauth's tokens work with standard OIDC client libraries without configuration.

## Trade-offs

### Key size and performance

RSA-2048 signing is slower than HMAC-SHA256. Benchmarks on modern hardware:
- RS256 sign: ~0.3ms
- HS256 sign: ~0.01ms

At sinauth's expected token issuance rate (tokens are issued once per login, not per request), this difference is negligible. Token verification is fast in both cases (~0.1ms for RS256 with cached key).

### Key storage complexity

An RSA key pair (private key as a PEM file) requires more careful storage than a shared secret. We address this with: file permissions (`0600`), gitignore, and production recommendations for secrets managers (Vault, K8s Secrets). See [docs/key-management.md](../docs/key-management.md).

## Consequences

- sinauth generates an RSA-2048 key pair at startup (or uses an existing PEM file).
- All tokens are signed with RS256 and include a `kid` header.
- sinauth publishes the public key at `/.well-known/jwks.json` (cached 1 hour).
- Platforms verify tokens locally using the JWKS; no sinauth call per request.
- Key rotation does not require reconfiguring any platform.
- The private key never leaves sinauth's process.
