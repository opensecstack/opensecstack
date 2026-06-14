# IRFlow RBAC Guide

IRFlow enforces role-based access control on every JWT-authenticated
endpoint. Roles are deliberately coarse — five of them — because
fine-grained scopes can be layered on later (v1.2) without rotating
every existing token.

For the role constants, see [internal/auth/roles.go](../internal/auth/roles.go).
For the middleware that enforces them, see [internal/auth/middleware.go](../internal/auth/middleware.go).

## The five roles

| Role | Read | Write (create/update) | Delete | Verify actions | Playbook auth |
|---|:-:|:-:|:-:|:-:|:-:|
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `operator` | ✓ | ✓ | ✗ | ✗ (SoD) | ✓ |
| `verifier` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `viewer` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `service` | ✓ | ✓ | ✗ | ✗ | ✓ (machine) |

### `admin`
Unrestricted. Typical holders: security leads, on-call commanders
during rotation. Use sparingly — `admin` can delete incidents, which
breaks the invariant that IRFlow records are append-only for audit.

### `operator`
The daily driver of incident response. Operators create incidents,
patch state (`open → investigating → contained`), submit actions (as
the *initiating* half of SoD), attach IOCs, and author playbooks. They
**cannot** verify their own actions — that requires a separate holder
of `verifier` or `admin`.

### `verifier`
The counterparty for Separation of Duties. Typical holders: peer
operators, security engineers who are not on-call. A verifier can
approve (`verify`) actions that an operator has submitted and see
everything the operator can, but cannot themselves initiate an action.

### `viewer`
Read-only. Use for dashboards, external auditors, executive summaries,
Grafana service accounts, anything that consumes incident state but
should not change it.

### `service`
Machine-to-machine integrations — internal frontend, playbook
scheduler, CI/CD bots. Equivalent to `operator` for writes today; a
future `service:*` scoped token format will narrow this.

## Enforcement model

RBAC lives in a chi middleware stack:

```
Request → [requestID] → [auditLog] → [metrics] → [JWT verify] → [role guard] → handler
```

The chain is fixed in [internal/api/server.go](../internal/api/server.go).
Three guard helpers wrap handlers:

| Guard | Effect |
|---|---|
| `auth.RequireRead` | Any known role passes |
| `auth.RequireWrite` | Admin, operator, service |
| `auth.RequireDelete` | Admin only |

Verifier-specific endpoints (action verification) embed the role check
in the handler rather than the middleware — the action flow also
enforces actor ≠ verifier at the service layer.

## Separation of Duties (SoD)

The service layer rejects any action where `actor_id == verifier_id`:

```
POST /api/v1/incidents/{id}/actions
  ...
  incident.Service.SubmitAction
      ├─► SoD check (actor ≠ verifier)
      ├─► MarshalClient.Evaluate
      └─► store.AddAction
```

A single user holding both `operator` and `verifier` roles **still**
cannot self-verify — SoD compares the identities (`sub` JWT claim),
not the roles. This is deliberate: an admin who tries to short-circuit
the process will be caught at the service-layer SoD guard even if the
middleware permits their role.

## Dev mode

Leaving `IRFLOW_AUTH_SECRET` empty (or setting
`IRFLOW_AUTH_DEV_MODE=true`) disables JWT verification. The middleware
then injects a synthetic `(dev, admin)` identity so downstream RBAC
guards still pass — otherwise every request would 401. A loud WARN log
(`auth middleware disabled — DEV MODE`) fires on startup. Dev mode
must **never** run in production.

## Issuing tokens

IRFlow does not mint its own tokens — bring your own IdP and sign with
HS256 against `IRFLOW_AUTH_SECRET`. The CLI can issue ad-hoc tokens
for operations:

```
$ irflow auth issue --sub alice --role operator --ttl 8h
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9....
```

Required claims:

- `sub` — user identifier (appears in audit logs and SoD comparisons)
- `role` — one of the five canonical roles above
- `exp` — expiry (enforced)
- `iss` — expected to match `IRFLOW_AUTH_ISSUER`

`iat`, `jti`, and custom claims are permitted but ignored.

## Audit log

Every request — authorised **or rejected** — produces an audit-log
line via `auth.AuditLog`, which mounts ahead of the JWT middleware.
Rejected requests log with `user_id=anonymous`; this is what lets
security teams spot probing attempts.

Sample line (redacted):

```
{"level":"info","ts":"...","request_id":"abc","method":"POST",
 "path":"/api/v1/incidents","user_id":"alice","role":"operator",
 "status":201,"duration_ms":14}
```

## Common role mapping patterns

| Use case | Suggested role |
|---|---|
| Security engineer on 24/7 rotation | `operator` + issued `admin` token only during severe incidents |
| Peer reviewer for sensitive containment actions | `verifier` |
| CI pipeline creating playbooks | `service` |
| Read-only NOC dashboard | `viewer` token on a shared service account |
| Compliance auditor with quarterly access | `viewer` with 24-hour tokens re-issued on demand |

## Related

- [API reference](./api.md) — per-endpoint permission requirements
- [Architecture § Audit log before auth](./architecture.md#audit-log-before-auth)
- [Governance integration](./governance-integration.md) — how SoD feeds into CITADEL MARSHAL Gate 3
