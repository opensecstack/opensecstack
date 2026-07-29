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
| Application-record trail | `scenarios`, `environments`, `scenario_runs` rows are the available record of activity (no dedicated audit-log table exists) | PostgreSQL |
| CITADEL evidence | Every completed run emits a `securelab.run_completed` event | CITADEL emitter |

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

## 6. Application-record trail (no dedicated audit-log table)

**There is no dedicated append-only audit-log table in the current implementation, and no PostgreSQL row-level security (RLS) policies protecting one.** This was previously documented incorrectly in this file; the statement has been corrected here and in [docs/operator-handbook.md](operator-handbook.md) and [SECURITY.md](../SECURITY.md).

What actually exists today: `scenario_runs` rows (see `internal/db/migrations/003_results.sql`) record `status`, `started_at`, `finished_at`, `attack_events`, `detection_events`, `detection_latency_ms`, and `detected` for every run, alongside the `scenarios` and `environments` tables. These are ordinary application tables — they are not append-only, are not protected by RLS or `CREATE POLICY` rules, and can be updated or deleted like any other row in the database. In an incident, these tables are the available record; see [docs/operator-handbook.md § Incident response](operator-handbook.md#incident-response--unauthorised-access).

A blocked or timed-out run is still recorded as a `scenario_runs` row with the corresponding status (`blocked`, `timed_out`, etc.) — see `internal/scenarios/validator.go` for the production-hostname blocklist check that produces `blocked` runs.

A dedicated append-only audit-log table with RLS enforcement is reasonable future work — see [docs/operator-handbook.md § Future / Not Yet Implemented](operator-handbook.md#future--not-yet-implemented) — but do not rely on it until it is actually implemented.

---

## 7. CITADEL evidence emission

Every completed scenario run (including failed, timed out, and blocked runs) emits a `securelab.run_completed` event to CITADEL. This provides an immutable, externally verifiable record of all simulation activity.

CITADEL events are HMAC-SHA256 signed using `SECURELAB_CITADEL_HMAC_SECRET`. Set `SECURELAB_CITADEL_DRY_RUN=true` (the default) to log events without sending them during initial setup.

---

## Reporting safety control bypasses

If you discover a way to bypass any of these safety controls, treat it as a critical security vulnerability and report it via the channels in [SECURITY.md](../SECURITY.md). Do not attempt to exploit it.
