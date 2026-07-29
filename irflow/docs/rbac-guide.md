# IRFlow RBAC Guide

IRFlow enforces role-based access control on every JWT-authenticated
endpoint. Roles are deliberately coarse — five of them — because
fine-grained scopes can be layered on later (v1.2) without rotating
every existing token.

For the role constants, see [internal/auth/roles.go](../internal/auth/roles.go).
For the middleware that enforces them, see [internal/auth/middleware.go](../internal/auth/middleware.go).

## The five roles

| Role | Read | Write (create/update) | Delete | Approve/reject pending actions | Playbook auth |
|---|:-:|:-:|:-:|:-:|:-:|
| `admin` | ✓ | ✓ | ✓ | ✓ (role gate only — cannot approve own proposal, see SoD below) | ✓ |
| `operator` | ✓ | ✓ | ✗ | ✓ (role gate only — cannot approve own proposal, see SoD below) | ✓ |
| `verifier` | ✓ | ✗ | ✗ | ✓ | ✗ |
| `viewer` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `service` | ✓ | ✓ | ✗ | ✓ (role gate only — cannot approve own proposal, see SoD below) | ✓ (machine) |

### `admin`
Unrestricted. Typical holders: security leads, on-call commanders
during rotation. Use sparingly — `admin` can delete incidents, which
breaks the invariant that IRFlow records are append-only for audit.

### `operator`
The daily driver of incident response. Operators create incidents,
patch state (`open → investigating → contained`), *propose* governed
actions (`POST /actions`, the initiating half of the two-person-rule
flow), attach IOCs, and author playbooks. Because `canApprove` also
covers `operator`, an operator can approve or reject a peer's proposal —
but **cannot** approve their own: `incident.Service.ApproveAction`
compares the authenticated caller's sinauth UUID against the proposing
Operator's stored UUID and rejects a match with `ErrSelfApproval`,
regardless of role.

### `verifier`
The default counterparty for Separation of Duties. Typical holders: peer
operators, security engineers who are not on-call. A verifier can approve
or reject pending actions that an operator has proposed
(`POST /actions/{actionID}/approve` or `.../reject`) and see everything the
operator can, but cannot themselves propose an action (`RequireWrite`
excludes `verifier`).

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
Four guard helpers wrap handlers:

| Guard | Effect |
|---|---|
| `auth.RequireRead` | Any known role passes |
| `auth.RequireWrite` | Admin, operator, service — gates `POST /incidents`, `PATCH /incidents/{id}`, `POST /actions` (propose) |
| `auth.RequireDelete` | Admin only |
| `auth.RequireApprove` | Admin, operator, verifier, service — gates `POST /actions/{actionID}/approve` and `.../reject` |

`RequireApprove` is deliberately broader than `RequireWrite` (it also
admits `verifier`): the same coarse role (`operator`) can legitimately act
as either party on different actions, so the role gate alone cannot
enforce SoD — it just narrows who may attempt an approval. The actual
guarantee is enforced one layer down, in the service.

## Separation of Duties (SoD) — the two-person-rule action flow

IRFlow's incident-action model is a two-step propose/approve flow, not a
single call: an Operator proposes an action from their own authenticated
session (`POST /api/v1/incidents/{id}/actions`), and it is only ever
evaluated by CITADEL MARSHAL when a SECOND, distinct authenticated user
(the Verifier) approves it with their own bearer token
(`POST /api/v1/incidents/{id}/actions/{actionID}/approve`). A single HTTP
caller can never supply both identities — each is derived from
`auth.ClaimsFromContext` on its own request, never from a request body
field.

```
POST /api/v1/incidents/{id}/actions                     (Operator's session)
  incident.Service.ProposeAction
      └─► store.CreatePendingAction (status="pending")

POST /api/v1/incidents/{id}/actions/{actionID}/approve   (Verifier's session)
  incident.Service.ApproveAction
      ├─► SoD check (verifierUserID == pa.OperatorUserID → ErrSelfApproval, 400)
      ├─► MarshalClient.Evaluate
      └─► store.AddAction
```

The service layer rejects approval/rejection whenever the caller's user ID
matches the proposal's `operator_user_id`. A single user holding both
`operator` and `verifier` roles **still** cannot self-approve — the SoD
check compares real sinauth UUIDs from two separate authenticated
sessions, not roles. This is deliberate: an admin who tries to
short-circuit the process is caught at the service-layer SoD guard even
though `RequireApprove` would otherwise let their role through.

The check is enforced in two independent places, so a bug in one does not
silently break the guarantee:

1. **Application layer** — `incident.Service.ApproveAction` /
   `RejectAction` return `ErrSelfApproval` (mapped to HTTP 400) when
   `verifierUserID == pa.OperatorUserID`.
2. **Database layer** — `migrations/003_pending_actions.sql` adds
   `CHECK (verifier_user_id = '' OR verifier_user_id <> operator_user_id)`
   on the `pending_actions` table, so even a direct SQL write or a future
   application bug cannot persist a self-approved row.

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
