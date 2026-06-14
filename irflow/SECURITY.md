# Security Policy

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security problems. Email the
maintainers at `security@opensecstack.org` (PGP key available on request) with:

- A description of the vulnerability
- Steps or a proof-of-concept to reproduce it
- Your assessment of the impact and suggested severity

We aim to acknowledge within 48 hours and to publish a fix or mitigation
advisory within 30 days for high-severity findings.

## Threat Model

### Authentication

- **API:** HS256 JWT via `Authorization: Bearer …`. Tokens must be signed
  with the secret configured in `IRFLOW_AUTH_SECRET`. `alg: none` tokens are
  rejected explicitly (`ErrUnsupportedAlg`). Expired (`exp`) and
  not-yet-valid (`nbf`) tokens are rejected before claim extraction.
- **Webhooks:** HMAC-SHA256 of `timestamp + "." + body`, verified with a
  per-source secret. Replayed requests are rejected by a ±5-minute
  timestamp window. Missing secret → `503` (fail-closed).

### Authorization

Role-based; see [docs/api.md](docs/api.md) for the per-endpoint matrix. In
summary:

| Role | Read | Write | Delete |
|---|---|---|---|
| admin | ✓ | ✓ | ✓ |
| operator / service | ✓ | ✓ | — |
| verifier / viewer | ✓ | — | — |

Write endpoints are guarded by `auth.RequireWrite`; delete endpoints are
guarded by `auth.RequireDelete`. Unauthenticated callers see `401`.

### Input validation & DoS mitigation

- HTTP bodies on webhooks are bounded by `IRFLOW_WEBHOOK_MAX_BODY_SIZE`
  (default 1 MiB). Oversized → `413`.
- JSON decoding on `application/json` bodies uses `json.NewDecoder`; control
  of the payload's shape is left to the caller (validation is at the
  domain layer, not the JSON layer, so malformed objects surface as
  `400`).
- Every HTTP handler that enters a service runs under the request's context,
  so downstream timeouts propagate and the server cannot be wedged by a
  slow external call.
- MARSHAL / WORM / NIS2 client calls use bounded timeouts (10 s default,
  set via constructor options).

### Governance isolation

- CITADEL MARSHAL rejections (`REFUSE`, `HARD_STOP`) return typed errors
  that prevent the corresponding action from being persisted locally. The
  action is never recorded in the IRFlow database in that case.
- WORM anchor failures are logged but non-fatal — IRFlow still owns the
  primary record. Operators can retry anchoring out-of-band.

### Secret management

- Secrets are never logged. The audit middleware redacts tokens and only
  records `user_id`, `role`, `method`, `path`, `status`, and `duration`.
- Recommended rotation: webhook secrets quarterly, JWT secret annually or
  on suspicion of compromise (rotating the secret invalidates every
  outstanding token).

### Known limitations (v1.0.0)

- No built-in user database. Token issuance is decoupled — IRFlow only
  verifies signatures against `IRFLOW_AUTH_SECRET`. Integrate with an
  external IdP for production identity management.
- No webhook event deduplication yet. A replayed payload with a fresh
  timestamp + valid signature would be accepted. The wire format already
  carries an `event_id`; a future release will persist seen IDs with a TTL.
- MARSHAL signatures (`X-Citadel-Signature`) are emitted by IRFlow but not
  currently validated by CITADEL's handlers. They will become enforceable
  when CITADEL adds the complementary middleware.

## Supported Versions

| Version | Status |
|---|---|
| 1.0.x | Actively supported |
| < 1.0 | Development snapshots; do not run in production |
