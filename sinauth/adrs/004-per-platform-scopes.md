# ADR 004: Standard OIDC Scopes in v1 (No Custom Per-Platform Scopes)

**Status**: Accepted
**Date**: 2024-01-15
**Deciders**: sinauth core team

## Context

OAuth 2.0 allows authorization servers to define custom scopes beyond the standard OIDC set. Custom scopes can encode platform-specific permissions directly in the access token (e.g., `apiguard:scan:write`, `irflow:incident:lead`). Alternatively, sinauth can issue only standard OIDC scopes (`openid`, `profile`, `email`, `offline_access`) and let each platform manage its own role/permission model internally.

## Decision

sinauth v1 uses only the four standard OIDC scopes. Custom per-platform scopes are deferred to v2.

## Reasons

### Simplicity and standards compliance

The standard OIDC scopes are defined in the specification and understood by every OIDC client library. Using only standard scopes means sinauth's token responses, discovery document, and client registrations are immediately understandable by any developer familiar with OIDC.

Custom scopes require defining a scope registry, documenting scope semantics for each platform, and ensuring scope naming does not collide across platforms. This complexity is not necessary to get 10 platforms integrated and working with SSO.

### Sufficient for v1 requirements

The v1 requirement is single sign-on: one account across all SIN platforms, with the platform knowing who the user is (via `sub`, `email`, `name`). Standard scopes provide exactly this.

Platform-specific authorization (can this user run a scan? is this user an incident lead?) is enforced by each platform using its own roles table, keyed on the sinauth `sub`. This is a well-understood pattern that does not require sinauth involvement.

### Faster time to integration

Registering a new platform with sinauth requires configuring `client_id`, `redirect_uris`, and requesting standard scopes. There is no need to design, document, and register platform-specific scopes before integration can begin. All 10 SIN platforms can be integrated in parallel without scope coordination.

### Avoiding premature design

Designing the right custom scope model for 10 platforms with different access control needs is non-trivial. Getting it wrong early creates migration pain later. By deferring custom scopes to v2, we have time to observe how platforms actually use identity information and design the scope model from real requirements rather than speculation.

## Trade-offs

### Per-request role lookups

Without custom scopes in the access token, platforms must look up the user's role in their own database on every authenticated request (using `sub` as the key). This adds one database query per request on protected endpoints.

This is an acceptable trade-off in v1: the query is against a small, well-indexed table (`user_roles` with a UUID index) and adds microseconds of latency.

In v2, encoding the role in the access token would eliminate this lookup entirely.

### Scope mismatch risk

If a user was granted `openid profile email` by sinauth, but a platform later wants to check `apiguard:scan:read`, it cannot. The access token does not contain platform-specific claims. The platform must rely on its own authorization model — which it does anyway in v1.

## Consequences

- sinauth v1 supports exactly four scopes: `openid`, `profile`, `email`, `offline_access`.
- All OAuth clients (platforms) are registered with a subset of these four scopes.
- Platforms implement their own RBAC using the sinauth `sub` as the user identifier.
- Custom per-platform scopes are on the v2 roadmap.
- No scope registry or inter-platform scope coordination is needed in v1.
