# SecureLab Operator Handbook

> **Audience:** authorised operators running SecureLab in a deployed
> environment — red-team leads, SOC managers, and detection engineers
> with `operator` or `admin` role on the SecureLab API.
>
> **Prerequisite:** Confirm the isolation requirements in
> [docs/deployment.md](deployment.md) are met and you have explicit
> written authorisation to run scenarios against your target
> environments before following any procedure in this handbook.

## Daily operations checklist

Run this before executing any scenario:

- [ ] Confirm SecureLab is healthy: `curl http://<host>:8080/health`
- [ ] Confirm the target environment is registered and `status: ready`
      (`GET /api/v1/environments`)
- [ ] Confirm no runs are stuck in `pending`/`running` from a previous
      session (`GET /api/v1/runs`)
- [ ] Confirm your execution has been approved per your organisation's
      change-management procedure

## Running a scenario

### Step 1 — Select the scenario

```bash
curl http://localhost:8080/api/v1/scenarios \
     -H "Authorization: Bearer <token>"
```

Review the scenario's `mitre_technique_ids`, `tags`, `severity`, and
`yaml_content` before running it — see
[docs/scenario-spec.md](scenario-spec.md) for the YAML format.

### Step 2 — Confirm the target environment

```bash
curl http://localhost:8080/api/v1/environments \
     -H "Authorization: Bearer <token>"
```

`RunScenario` (`POST /api/v1/scenarios/{id}/run`) requires the target
environment to be in `status: ready`; it returns `409 Conflict`
otherwise. There is no separate dry-run mode at the API level in the
current implementation — running a scenario dispatches it to the
scheduler against the named environment.

### Step 3 — Run the scenario

```bash
curl -X POST http://localhost:8080/api/v1/scenarios/<scenario-id>/run \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"environment_id": "<environment-id>"}'
```

Response `202 Accepted` returns `{"run_id": "<id>"}`.

### Step 4 — Monitor the run

```bash
curl http://localhost:8080/api/v1/runs/<run-id> \
     -H "Authorization: Bearer <token>"
```

The run record includes `status`, `started_at`, `finished_at`,
`attack_events`, `detection_events`, `detection_latency_ms`, and
`detected`. See [docs/api.md](api.md) for the full field reference.

### Step 5 — Check CITADEL emission

CITADEL emission (`securelab.run_completed`) happens synchronously at
run completion when `SECURELAB_CITADEL_API_URL` is set and
`SECURELAB_CITADEL_DRY_RUN=false` (see `internal/citadel/connector.go`
and [docs/citadel-integration.md](citadel-integration.md)). If the
POST to CITADEL fails, the failure is logged; there is currently no
retry queue, circuit breaker, or manual re-emit endpoint. If CITADEL
emission fails, check the API server logs for the run ID and retry
the CITADEL connectivity check manually.

## Interpreting run results

The `detected` field on a run record is a boolean: `true` once the
configured detection platforms (OpenScrub, APIGuard, ThreatFlow — see
`internal/detection`) confirm the attack was observed within the
detection window, `false`/`null` otherwise. There are no additional
verdict states (`inconclusive`, `timeout`, `not_applicable`, `partial`)
in the current implementation — treat a run without a `detected: true`
result as a detection gap worth investigating.

## Coverage monitoring

See [docs/mitre-attack-coverage.md](mitre-attack-coverage.md) for the
`mitre_coverage` table and the `GET /api/v1/coverage` endpoint. Note
that this table is not populated automatically by run completion in
the current implementation — treat coverage numbers as only as fresh
as your last manual/administrative update, until that wiring lands.

## Roles

RBAC roles enforced by `internal/api/middleware.RequireRole`:

| Role | Can do |
|---|---|
| `analyst` | Read scenarios, runs, environments, coverage |
| `operator` | Everything `analyst` can, plus create scenarios and run them |
| `admin` | Everything `operator` can, plus create/delete environments |

Roles come from the authenticated token (local JWT or sinauth SSO —
see [docs/configuration.md](configuration.md)). There is no local
`/auth/revoke-all` endpoint in the current implementation; if you
suspect a compromised token, rotate `SECURELAB_JWT_SECRET` (which
invalidates all locally-issued tokens) and/or revoke the session at
your sinauth identity provider.

## Incident response — unauthorised access

If you suspect an unauthorised actor has accessed the SecureLab API
or dashboard:

1. Rotate `SECURELAB_JWT_SECRET` and any active `SECURELAB_CITADEL_HMAC_SECRETS`,
   then restart the API server so the new values take effect.
2. Revoke the operator's session at your sinauth identity provider.
3. Review recent rows in `scenarios`, `environments`, and
   `scenario_runs` for the suspected time window — there is no
   dedicated audit-log table in the current implementation, so these
   application tables are the available record.
4. Notify your security team and escalate via your incident-response
   procedure.
5. Treat any scenario runs triggered during the suspected window as
   potentially unauthorised when reviewing CITADEL evidence.

An unauthorised access event must be treated as a critical security
incident. Escalate to your CISO.

## Future / Not Yet Implemented

The following operational capabilities are reasonable future work but
do not exist in the codebase today: a dedicated append-only audit-log
table and query endpoint, Prometheus metrics (`/metrics` is not
exposed by the API), a CITADEL emission retry queue / circuit breaker
with manual re-emit, and a token-revocation API. Do not rely on any of
these until they are actually implemented.

## Related

- [SECURITY.md](../SECURITY.md) — threat model and access control
- [docs/deployment.md](deployment.md) — isolation architecture
- [docs/configuration.md](configuration.md) — env vars
- [docs/citadel-integration.md](citadel-integration.md) — CITADEL emission
- [docs/mitre-attack-coverage.md](mitre-attack-coverage.md) — coverage model
