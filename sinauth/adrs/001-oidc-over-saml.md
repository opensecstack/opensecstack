# ADR 001: OIDC + OAuth2 over SAML

**Status**: Accepted
**Date**: 2024-01-15
**Deciders**: sinauth core team

## Context

sinauth needs a standard identity protocol to federate authentication across all SIN platforms. Two dominant enterprise identity standards exist: SAML 2.0 and OpenID Connect (OIDC).

## Decision

We chose OpenID Connect + OAuth 2.0 over SAML 2.0.

## Reasons

### Modern standard designed for the web

OIDC was designed in 2014 for the HTTP/REST era. It uses JSON everywhere — JSON tokens (JWT), JSON discovery documents, JSON key sets (JWKS). Every SIN platform is an HTTP/REST service with a JSON API. OIDC is a natural fit.

SAML was designed in 2002 for XML/SOAP enterprise middleware. Its tokens (SAML Assertions) are verbose XML documents. Its binding protocols involve base64-encoded, XML-signed, XML-encrypted payloads. Every SAML operation requires an XML parser and knowledge of XML security standards (XML Signature, XML Encryption).

### Library support

OIDC and OAuth 2.0 have excellent library support in every language used by SIN platforms (Go, TypeScript, Python). The JWT standard (RFC 7519) and JWKS (RFC 7517) are implemented in hundreds of mature libraries.

SAML has far fewer maintained implementations. Many are unmaintained, have known vulnerabilities (XML Signature Wrapping attacks are a historical source of SAML authentication bypasses), and lack Go support entirely.

### Developer experience

Integrating a new SIN platform with sinauth using OIDC requires:
1. Read the discovery document (one HTTP call).
2. Generate PKCE values.
3. Redirect to the authorization endpoint.
4. Exchange the code for tokens.
5. Verify the JWT signature using the JWKS.

This is implementable from scratch in an afternoon with standard library tools.

SAML integration requires:
- Parsing and generating XML.
- Implementing XML digital signatures.
- Managing XML metadata documents.
- Handling HTTP-POST and HTTP-Redirect bindings with specific encoding requirements.

### All SIN platforms are HTTP/REST

SAML's HTTP-POST binding works by embedding base64-encoded XML in HTML form submissions. This requires browser redirects through HTML forms. Modern SPAs and mobile apps cannot easily participate in this flow. OIDC's redirect-based flow works naturally with any HTTP client.

### SAML is enterprise legacy

SAML is the right choice when integrating with existing enterprise identity providers (Active Directory Federation Services, Okta Classic). SIN is building greenfield platforms — there is no existing SAML infrastructure to integrate with. Adopting SAML would incur the complexity cost with none of the compatibility benefit.

## Trade-offs

SAML is still required in some enterprise environments (e.g., US federal government). If SIN platforms are ever deployed in environments that mandate SAML, a SAML-to-OIDC bridge (such as Keycloak) can sit in front of sinauth without changes to sinauth or any platform integration.

## Consequences

- All SIN platforms integrate with sinauth via OIDC Authorization Code + PKCE.
- sinauth does not implement any SAML endpoints.
- Platform teams do not need to learn XML security — only JSON/JWT.
