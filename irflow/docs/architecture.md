# IRFlow Architecture

IRFlow is the incident response workflow engine for OpenSecStack. It
owns the full lifecycle of an incident — creation, state transitions,
governed actions, IOC enrichment, timeline, playbook execution — and
integrates with the rest of the ecosystem through typed HTTP clients
and HMAC-signed webhooks.

For the public API, see [api.md](./api.md). For deployment, see
[deployment.md](./deployment.md). For playbook authoring, see
[playbook-authoring.md](./playbook-authoring.md).

## Component map

```
                   +-------------------------------+
   APIGuard  ────► | POST /api/v1/webhooks/apiguard|
   CITADEL   ────► | POST /api/v1/webhooks/citadel |
   ThreatFlow ───► | POST /api/v1/webhooks/threatfw|
                   +---------------+---------------+
                                   |
                                   v
          JWT-protected REST API   +   public webhooks
                   |                         |
         +---------v-------------------------v---------+
         |              chi router + middleware         |
         |  (RequestID · AuditLog · HTTP metrics · JWT) |
         +---------+-------------------+----------------+
                   |                   |
         +---------v---------+ +-------v---------+
         |  incident.Service | | playbook.Service|
         +---------+---------+ +-------+---------+
                   |                   |
                   |                   +--► Executor (graph traversal)
                   |
         +---------v---------+  +-----------------+  +-----------------+
         |  CITADEL MARSHAL  |  | CITADEL WORM    |  | NIS2 Compass    |
         |  dual-control     |  | audit chain     |  | Art. 23 notify  |
         +-------------------+  +-----------------+  +-----------------+
                   |                   |                       |
                   +---------+---------+-----------------------+
                             |
                   +---------v---------+
                   |   PostgreSQL 16   |
                   +-------------------+
```

Three concentric responsibilities:

1. **Transport** — chi HTTP server, middleware stack (request ID, audit
   log, Prometheus metrics, JWT auth, HMAC verification for webhooks).
2. **Domain services** — `incident.Service` and `playbook.Service`
   encode the business rules (valid status transitions, Separation of
   Duties, NIS2 notification thresholds, playbook step branching).
3. **Persistence + governance** — PGStore adapters, CITADEL clients,
   NIS2 Compass client. All boundary crossings are HMAC-signed.

## Package layout

| Package | Role |
|---|---|
| `cmd/irflow` | CLI (`serve`, `migrate`, `version`, `auth issue`) |
| `internal/api` | chi router, middleware stack, HTTP handlers |
| `internal/auth` | JWT verification, RBAC guards, audit logging, Argon2id hasher wrapper |
| `internal/config` | Viper-backed env + YAML configuration |
| `internal/db` | pgxpool, `PGStore` (incidents), `PGPlaybookStore` |
| `internal/governance` | `CitadelClient` (MARSHAL + WORM), `NIS2Client` |
| `internal/incident` | Domain types, `Service`, governance-client interfaces, `Stats` |
| `internal/metrics` | Prometheus registry + `HTTPMiddleware` |
| `internal/playbook` | Domain types, `Service`, `Executor` (graph traversal) |
| `internal/version` | Build-time version stamps injected via ldflags |
| `internal/webhook` | HMAC-SHA256 verifier + typed inbound payloads |
| `migrations/` | SQL migrations (versioned + tracked in `schema_migrations`) |

## Dependency direction

```
api  ──► incident.Service  ──► incident.Store (interface)
api  ──► playbook.Service  ──► playbook.Store (interface)
incident.Service  ──► incident.Marshal/WORM/NIS2Client (interfaces)
playbook.Service  ──► playbook.Executor

governance.CitadelClient  implements  incident.MarshalClient  +  WORMClient
governance.NIS2Client     implements  incident.NIS2Client
db.PGStore                implements  incident.Store
db.PGPlaybookStore        implements  playbook.Store
```

The service layer depends on interfaces defined next to its own
domain types, not on the concrete `db` or `governance` packages. This
is what lets unit tests run against in-memory mocks and integration
tests run against live PostgreSQL without changing any service code.

## Request lifecycle

### Incident creation

```
POST /api/v1/incidents
  → chi middleware (request-id, audit log, metrics)
  → JWT verification + RBAC (RequireWrite)
  → handleCreateIncident
  → incident.Service.Create
      ├─► PGStore.Create (INSERT)
      ├─► WORMClient.Emit (anchor incident.created in CITADEL)
      │   └─► store.Update (persist returned worm_entry_id)
      └─► if NIS2-significant: goroutine → NIS2Client.NotifyIncident
          └─► store.Update (persist nis2_notified_at on success)
  → 201 Created + Incident
```

The NIS2 notification runs asynchronously in a detached goroutine so a
slow Compass API can never block the incident creation path — a slow
NIS2 would otherwise violate its own Article 23 deadline.

### Governed action submission

```
POST /api/v1/incidents/{id}/actions
  → chi middleware + JWT + RequireWrite
  → handleSubmitAction
  → incident.Service.SubmitAction
      ├─► SoD check (actor ≠ verifier — enforced at the HTTP layer)
      ├─► store.Get (fetch incident for project_id)
      ├─► MarshalClient.Evaluate (dual-control Kerkese)
      │     ├─► outcome EXECUTE: continue
      │     ├─► outcome REFUSE:  return ErrMarshalRefused → 403
      │     └─► outcome HARD_STOP: return ErrMarshalHardStop → 403
      └─► store.AddAction (persist with marshal_decision + worm_entry_id)
  → 201 Created + IncidentAction
```

### Playbook execution

```
POST /api/v1/playbooks/{id}/execute
  → chi + JWT + RequireWrite
  → handleExecutePlaybook
  → playbook.Service.Execute
      ├─► store.Get (fetch playbook definition)
      ├─► policy: playbook must be status=active
      ├─► store.CreateExecution (Execution in 'pending')
      └─► goroutine: Service.runExecution
                       ├─► store.UpdateExecution ('running')
                       ├─► Executor.Run (graph traversal)
                       └─► store.UpdateExecution ('completed'|'failed'|'cancelled')
  → 202 Accepted + Execution  (clients poll /executions/{id})
```

## Design choices

### Async NIS2 notification

The NIS2 Compass API can be slow — regulated-entity deployments often
sit behind VPN tunnels or shared infrastructure. Blocking incident
creation on NIS2 would let a single slow dependency derail the whole
response process, which is exactly what the regulator does not want.
IRFlow therefore fires-and-forgets the notification on a separate
goroutine with a 30-second per-attempt timeout and persists
`nis2_notified_at` only when the call succeeds. Failures are logged;
retry is a planned v1.1 feature.

### MARSHAL-blocks-on-failure

Conversely, CITADEL MARSHAL **must not** be bypassed when CITADEL is
unreachable. A caller who encounters a 5xx from `Evaluate` sees a
surfaced error and the action is not stored locally. This is a
deliberate asymmetry: NIS2 misses are recoverable (resubmit within
deadline), but an unauthorised action persisted without MARSHAL
approval is never recoverable.

### Graph-based playbook executor

Earlier designs iterated steps linearly in the order they appeared in
the YAML. That breaks as soon as playbooks branch — an `on_failure`
path has to be able to jump backwards or skip steps entirely. The
current `Executor` builds a step-ID lookup map and traverses it via
`OnSuccess` / `OnFailure` pointers, with a cycle guard
(`maxStepsPerExecution = 100`) to contain misconfigured playbooks.

### Audit log before auth

The `AuditLog` middleware is mounted **before** the auth middleware in
the stack. That means rejected requests (401, 403) are also logged,
with `user_id=anonymous`. Without this, an attacker probing the API
with invalid tokens would leave no trace.

## Observability

| Signal | Source |
|---|---|
| Structured JSON logs with `request_id` | `auth.AuditLog` middleware + `zap` across services |
| Prometheus metrics | `/metrics` endpoint, unauthenticated (separate from the JWT-protected API) |
| DB pool gauges | Refreshed every 15 s from `pgxpool.Pool.Stat()` |
| Governance call counters | `governance_calls_total{target, result}` — see every CITADEL/NIS2 success/failure |

See the full metrics catalogue in [api.md § Metrics catalogue](./api.md#metrics-catalogue).

## Scaling characteristics

| Axis | Property |
|---|---|
| Stateless request handling | Yes — IRFlow can run behind a load balancer with N replicas |
| Shared database | Yes — PostgreSQL is the single source of truth; use read replicas for reporting queries |
| Playbook execution | Today, executions run on the IRFlow instance that received the `execute` request; a horizontal scaling design using a distributed job queue is planned for v1.2 |
| Webhook ingestion | Stateless; scales linearly with the number of replicas |

## Related

- [API reference](./api.md) — wire format for every endpoint
- [Deployment](./deployment.md) — how to run this in production
- [Playbook authoring](./playbook-authoring.md) — YAML schema and examples
- [Ecosystem architecture](../../ARCHITECTURE.md)
