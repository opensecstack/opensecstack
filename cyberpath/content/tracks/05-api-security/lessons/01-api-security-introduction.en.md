---
id: 01-api-security-introduction
order: 1
duration_minutes: 60
---

# Lesson 1: Introduction to API Security

## The API attack surface

APIs are the connective tissue of modern software. Every mobile application, every SaaS integration, every microservice architecture, and every partner data exchange operates over an API surface — most commonly REST over HTTPS, though GraphQL, gRPC, and WebSocket APIs are increasingly common. This makes the API surface one of the most consequential attack surfaces in modern enterprise environments: it is externally reachable, often under-documented, and frequently subject to security assumptions that do not hold under adversarial conditions.

The scale of the problem is reflected in attack statistics. API-targeted attacks represent a significant and growing portion of data breaches. Threat actors are highly motivated to target APIs because a single misconfigured endpoint can expose records belonging to thousands or millions of users — a multiplier effect that makes API vulnerabilities disproportionately valuable to attack. Unlike web application vulnerabilities that require browser interaction, many API vulnerabilities are exploitable with nothing more than a scripted HTTP client.

## OWASP API Top 10 (2023)

The OWASP API Security Project publishes and maintains the API Top 10, a taxonomy of the most critical API security risks. The 2023 edition reflects the evolution of API attack patterns since the original 2019 list. The ten categories are:

1. **API1:2023 — Broken Object Level Authorization (BOLA):** An API endpoint accepts a user-controlled object identifier (an ID in a URL path or request body) and returns or modifies the referenced object without verifying that the calling user is authorised to access that specific object. BOLA is consistently the most common API vulnerability class — and the most straightforward to exploit.
2. **API2:2023 — Broken Authentication:** Weak authentication mechanisms: missing authentication on endpoints that should be protected, weak token validation, token leakage in logs or error responses, or lack of brute-force protection on login endpoints.
3. **API3:2023 — Broken Object Property Level Authorization (BOPLA):** An API accepts updates to object properties the calling user should not be permitted to modify — for example, a user changing their own `role` field from `user` to `admin` by including it in a PATCH request body.
4. **API4:2023 — Unrestricted Resource Consumption:** API endpoints without rate limiting, request size limits, or execution time constraints, enabling denial-of-service, account enumeration, or cost amplification attacks against cloud-billed backends.
5. **API5:2023 — Broken Function Level Authorization:** Administrative or privileged API functions reachable by non-privileged users — often because the developer assumed the function would "never be called" by regular users and omitted an authorization check.
6. **API6:2023 — Unrestricted Access to Sensitive Business Flows:** API sequences that, when automated, enable abuse of legitimate business logic: buying out all stock via a cart-checkout loop, extracting all user emails via a contact search API, or bypassing waitlists via direct API calls.
7. **API7:2023 — Server-Side Request Forgery (SSRF):** An API that fetches a remote resource accepts a user-supplied URL without validation, enabling attackers to probe internal services, cloud metadata endpoints, or other resources not intended to be reachable from the internet.
8. **API8:2023 — Security Misconfiguration:** CORS misconfigurations, missing security headers, verbose error messages that expose stack traces, default credentials on API management platforms, and permissive HTTP method handling.
9. **API9:2023 — Improper Inventory Management:** Undocumented, shadow, or deprecated API versions and endpoints still reachable in production — often lacking the security controls applied to the "current" version.
10. **API10:2023 — Unsafe Consumption of APIs:** A backend service consumes a third-party API without input validation, blindly trusting the third-party response — enabling supply-chain-style injection if the third-party API is compromised or returns attacker-controlled content.

## NIS2 and API security

NIS2 Article 21(2)(e) mandates "security in network and information systems acquisition, development, and maintenance." For software-producing organisations and organisations relying on third-party APIs, this directly covers API security: security testing of APIs before deployment, secure API design standards, and the management of API dependencies as part of the software supply chain.

Article 21(2)(d) — supply chain security — applies when third-party APIs are in scope. An organisation's API security posture is only as strong as the APIs it consumes: a trusted third-party API that is compromised, or that returns attacker-influenced content without validation, becomes an injection vector into the organisation's own processing pipeline.

## Why CyberPath uses APIGuard

APIGuard is the opensecstack ecosystem's API security scanning platform. It performs authenticated DAST (Dynamic Application Security Testing) against REST, GraphQL, and gRPC APIs, maps findings to OWASP API Top 10 categories, and provides remediation guidance with code-level examples. In CyberPath labs, learners run APIGuard against a deliberately vulnerable API target, analyse the findings report, and apply remediations. The APIGuard report format is the same used in production deployments — learners graduate with direct familiarity with the tool their organisation will use.
