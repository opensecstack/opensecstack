# Safety Controls

**CRITICAL DOCUMENT** — Read this before running any scenario.

SecureLab contains offensive tooling. These safety controls are mandatory and are enforced at the platform level. They cannot be disabled.

## Summary of safety controls

| Control | Mechanism | Enforced By |
|---|---|---|
| Target URL blocklist | Rejects environments with URLs matching blocked keywords | API validation layer |
| Internal Docker networks | `--internal` flag on all test networks | Docker Compose configuration |
| Rate caps | Maximum packets/requests per second per attack type | Execution engine |
| Scenario timeout | Hard wall-clock limit per scenario | Execution engine |
| Admin-only environment creation | `admin` role required to create environments | RBAC middleware |
| Audit logging | Every run and environment action recorded before execution | Execution engine + DB |
| CITADEL evidence | Every run emits a `securelab.run_completed` event | CITADEL emitter |

---

## 1. Target URL blocklist

Before any environment is created or any scenario is executed, SecureLab validates the target URL against a blocklist.

**Default blocked keywords** (case-insensitive):
- `production`
- `prod`
- `live`

Any configured additional keywords from `SECURELAB_BLOCKED_TARGETS`.

**Behavior**: the API returns `HTTP 422 Unprocessable Entity` with a clear error message if a blocked keyword is detected. The environment is not created and the scenario is not executed.

This check runs at both environment creation time AND at scenario execution time. A blocked URL at execution time causes the run to fail immediately with status `blocked`.

---

## 2. Internal Docker networks

All test target environments are created on Docker bridge networks with `internal: true`. This means:

- Target containers cannot establish outbound connections to the internet.
- Target containers cannot reach any host outside the test network.
- Attack simulation traffic is confined to the isolated test network.

This is enforced in `docker-compose.test.yml` and cannot be overridden via the SecureLab API.

**If you are provisioning custom target environments**, you must use the `--internal` flag. SecureLab will refuse to activate an environment that does not have this flag set.

---

## 3. Rate caps

Each attack type has a maximum configurable rate that the execution engine enforces:

| Attack Kind | Maximum Rate |
|---|---|
| `syn_flood` | 500k PPS |
| `udp_flood` | 500k PPS |
| `http_flood` | 100k RPS |
| `bola` | 1000 requests/s |
| `jwt_brute` | 500 attempts/s |
| `rate_limit_bypass` | 1000 requests/s |
| `api_enum` | 500 requests/s |

Scenarios that specify rates above these caps are rejected at validation time.

---

## 4. Scenario timeout

Every scenario has a mandatory `timeout` field. The execution engine enforces this as a hard wall-clock limit. When the timeout is reached:

1. All in-progress attack steps are cancelled.
2. Any network connections opened by the scenario are closed.
3. The run is marked as `timed_out`.
4. A CITADEL event is emitted with the partial results.

The maximum scenario timeout is 30 minutes. Scenarios requesting longer timeouts are rejected at validation.

---

## 5. Admin-only environment creation

Only users with the `admin` role can create or delete environments. Regular users with `operator` role can execute scenarios against existing environments but cannot provision new ones.

This prevents unprivileged users from pointing SecureLab at arbitrary targets.

---

## 6. Audit logging of all runs

Every scenario run is recorded in the audit log **before execution begins** — not after. This means:

- A run that is blocked by safety validation still appears in the audit log with status `blocked`.
- A run that times out has a complete audit trail including the timeout event.
- There is no path to execute a scenario without creating an audit record.

The audit log is append-only at the database level (enforced via PostgreSQL row-level security — INSERT only, no UPDATE/DELETE on audit tables).

---

## 7. CITADEL evidence emission

Every completed scenario run (including failed, timed out, and blocked runs) emits a `securelab.run_completed` event to CITADEL. This provides an immutable, externally verifiable record of all simulation activity.

CITADEL events are HMAC-SHA256 signed using `SECURELAB_CITADEL_HMAC_SECRET`. Set `SECURELAB_CITADEL_DRY_RUN=true` (the default) to log events without sending them during initial setup.

---

## Reporting safety control bypasses

If you discover a way to bypass any of these safety controls, treat it as a critical security vulnerability and report it via the channels in [SECURITY.md](../SECURITY.md). Do not attempt to exploit it.
