---
status: Accepted
date: 2026-04-01
---
# ADR-002: HMAC-SHA256 for inbound webhook verification

## Context
IRFlow receives incident notifications from external systems (abuse mailboxes, peer CSIRTs, monitoring platforms). Unauthenticated webhooks are a common attack vector for injecting false incidents.

## Decision
All inbound webhook endpoints require an `X-IRFlow-Signature` header containing `HMAC-SHA256(secret, body)`. The shared secret is configured per integration via `IRFLOW_WEBHOOK_SECRET`. Requests with missing or invalid signatures are rejected with 401.

## Consequences
- Replay attacks are not prevented by HMAC alone — a timestamp/nonce check is deferred to v0.2
- Each integration needs a separate secret (rotation is manual in v0.1)
- Standard pattern — easy to implement in any language sending webhooks to IRFlow
