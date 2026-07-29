# IRFlow

**IRFlow** is the incident response workflow engine for the
[OpenSecStack](https://github.com/opensecstack/opensecstack) ecosystem. It
manages the full incident lifecycle — from detection through containment,
eradication, recovery, and closure — while enforcing CITADEL governance and
tracking NIS2 Article 23 deadlines at every step.

Current release: **v1.0.0** — see [CHANGELOG.md](CHANGELOG.md).

## Features

- **Incident lifecycle** — guarded state machine (`open → investigating → contained → eradicating → recovering → closed`), actions, IOC enrichment, append-only timeline.
- **Two-person-rule action flow** — an Operator proposes a governed action from their own authenticated session; a SECOND, distinct authenticated user (the Verifier) must approve or reject it before CITADEL MARSHAL is ever evaluated. Self-approval is rejected both at the application layer and by a DB-level `CHECK` constraint.
- **CITADEL MARSHAL** — on approval, the action is evaluated through the 5-gate engine; `REFUSE` / `HARD_STOP` outcomes prevent local persistence (HTTP 403).
- **CITADEL WORM** — incident creation is anchored in the tamper-evident audit chain.
- **NIS2 Compass** — regulatory-significant incidents (P1/P2/P3) are notified asynchronously to the Article 21(2)(b) Incident Handling control.
- **Playbook automation** — graph-based executor with `OnSuccess` / `OnFailure` branching, per-step timeouts, and cycle protection.
- **Webhook ingestion** — HMAC-SHA256 signed inbound events from APIGuard, CITADEL, and ThreatFlow (replay-protected ±5 min).
- **JWT auth + RBAC** — HS256 bearer tokens with 5 canonical roles (`admin`, `operator`, `verifier`, `viewer`, `service`).
- **Observability** — Prometheus metrics at `/metrics`, structured audit log with `request_id` propagation.
- **Testing** — unit tests plus a full HTTP E2E suite behind an `integration` build tag.

## Architecture

```
           +-----------+                                +-----------+
           |  APIGuard |---- webhook (HMAC) ----------->|           |
           +-----------+                                |           |
                                                        |           |---- Kerkese evaluate ----> CITADEL MARSHAL
           +-----------+                                |  IRFlow   |
           | ThreatFlow|---- webhook (HMAC) ----------->|  :8083   |---- anchor -----------------> CITADEL WORM
           +-----------+                                |           |
                                                        |           |---- Article 23 notify -----> NIS2 Compass
           +-----------+                                |           |
           |  CITADEL  |---- webhook (HMAC) ----------->|           |
           +-----------+                                +-----+-----+
                                                              |
                                                        Postgres 16
```

## API (summary)

Full catalogue in [docs/api.md](docs/api.md). Every `/api/v1/*` route
requires a valid JWT unless otherwise noted.

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | public | Liveness |
| GET | `/health/detail` | public | Liveness + DB ping + version info |
| GET | `/metrics` | public | Prometheus scrape endpoint |
| POST | `/api/v1/webhooks/{apiguard\|citadel\|threatflow}` | HMAC | Inbound events |
| GET | `/api/v1/incidents` | JWT | Paginated + filtered list |
| POST | `/api/v1/incidents` | JWT + write | Create incident |
| GET | `/api/v1/incidents/{id}` | JWT | Fetch one |
| PATCH | `/api/v1/incidents/{id}` | JWT + write | Partial update (enforces transition rules) |
| DELETE | `/api/v1/incidents/{id}` | JWT + admin | Delete |
| POST | `/api/v1/incidents/{id}/actions` | JWT + write | Operator proposes a governed action (two-person-rule step 1; not yet evaluated by MARSHAL) |
| GET | `/api/v1/incidents/{id}/actions` | JWT | List actions |
| GET | `/api/v1/incidents/{id}/actions/pending` | JWT | List pending (unresolved) proposed actions |
| POST | `/api/v1/incidents/{id}/actions/{actionID}/approve` | JWT + approve | Verifier approves a pending action (two-person-rule step 2; evaluated via MARSHAL) |
| POST | `/api/v1/incidents/{id}/actions/{actionID}/reject` | JWT + approve | Verifier rejects a pending action outright |
| GET | `/api/v1/incidents/{id}/timeline` | JWT | Chronological timeline |
| POST/GET | `/api/v1/incidents/{id}/iocs` | JWT + write / read | Attach / list IOCs |
| GET | `/api/v1/playbooks` | JWT | Playbook list |
| POST | `/api/v1/playbooks` | JWT + write | Create playbook |
| GET/PATCH | `/api/v1/playbooks/{id}` | JWT / JWT + write | Fetch / update |
| DELETE | `/api/v1/playbooks/{id}` | JWT + admin | Delete |
| POST | `/api/v1/playbooks/{id}/execute` | JWT + write | Async execution; returns 202 with `Execution` |
| GET | `/api/v1/playbooks/{id}/executions` | JWT | Executions for a playbook |
| GET | `/api/v1/executions/{id}` | JWT | Fetch a single execution |
| GET | `/api/v1/stats` | JWT | Dashboard aggregation |

## Authentication

IRFlow authenticates operators via [sinauth](../sinauth/docs/integration/irflow.md) SSO — the SIN identity provider (OAuth 2.0 / OIDC, authorization code + PKCE).
Access tokens are RS256-signed JWTs issued by `https://auth.sin.to`; IRFlow validates them against the sinauth JWKS endpoint at `https://auth.sin.to/.well-known/jwks.json`.
See the [sinauth integration guide](../sinauth/docs/integration/irflow.md) for token validation setup, RBAC mapping, and MFA configuration.

## Configuration

Every setting is loaded from environment (prefix `IRFLOW_`), an optional
`irflow.yaml`, or defaults. See [.env.example](.env.example) for the full
list.

Minimum production configuration:

```bash
IRFLOW_DB_PASSWORD=...                  # required
IRFLOW_AUTH_SECRET=...                  # required to enforce JWT; empty → dev mode
IRFLOW_CITADEL_API_URL=https://...      # required to enforce MARSHAL
IRFLOW_CITADEL_KEY_SECRET=...
IRFLOW_NIS2_API_URL=https://...         # required to notify NIS2
IRFLOW_NIS2_API_KEY=...
IRFLOW_NIS2_ASSESSMENT_ID=...
IRFLOW_WEBHOOK_APIGUARD_SECRET=...      # per-source webhook secrets
IRFLOW_WEBHOOK_CITADEL_SECRET=...
IRFLOW_WEBHOOK_THREATFLOW_SECRET=...
```

## Quick start

```bash
# Build
make build

# Apply database migrations
./bin/irflow migrate

# Start the server
./bin/irflow serve

# Issue a dev JWT (local testing only)
export IRFLOW_AUTH_SECRET=local-secret
./bin/irflow auth issue --user alice --role operator --ttl 1h

# Hit a protected endpoint
curl -H "Authorization: Bearer $TOKEN" http://localhost:8083/api/v1/incidents
```

Docker:

```bash
docker build -t irflow .
docker run -p 8083:8083 --env-file .env irflow
```

## Documentation

| Document | Description |
|---|---|
| [docs/api.md](docs/api.md) | Complete REST API reference with examples |
| [CHANGELOG.md](CHANGELOG.md) | Release history |
| [ROADMAP.md](ROADMAP.md) | Post-1.0 direction |
| [SECURITY.md](SECURITY.md) | Vulnerability reporting + threat model |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev workflow and coding conventions |

## Development

```bash
make test    # unit tests with race detector
make lint    # golangci-lint
```

### Integration tests

The integration suite boots the full HTTP stack against a real PostgreSQL.

```bash
make compose-test-up      # ephemeral Postgres on :54832
make test-integration     # runs with -tags=integration
make compose-test-down
```

Integration tests `t.Skip()` when `IRFLOW_TEST_DB_URL` is unset, so CI jobs
without Docker keep passing.

## Licence

AGPL-3.0 — see [LICENSE](LICENSE).
