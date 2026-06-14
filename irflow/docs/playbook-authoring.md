# Authoring IRFlow Playbooks

A playbook is a YAML / JSON document describing an automated incident
response workflow. When IRFlow receives a trigger (a webhook, a manual
`execute` call, or — in v1.2 — a scheduled run), it traverses the
playbook's step graph and records every step's outcome in the
`playbook_executions.step_results` JSONB field.

For the API that creates and runs playbooks, see
[api.md § Playbooks](./api.md#playbooks). For the run-time internals,
see [architecture.md § Graph-based playbook executor](./architecture.md#graph-based-playbook-executor).

## Playbook document

Minimum shape:

```yaml
name: "Critical Finding Response"
description: "Automated response when APIGuard reports a CRITICAL finding."
version: "1.0"
status: active          # draft | active | archived

trigger:
  event_type: apiguard.finding.critical
  severity:   P1                           # optional filter
  source:     apiguard                     # optional filter

steps:
  - id: create_incident
    name: "Create incident"
    type: action
    config:
      action_type: create_incident
      severity:   P1
    on_success: notify_team

  - id: notify_team
    name: "Page security"
    type: notify
    config:
      channel:          "security-incidents"
      message_template: "P1 incident created: {{.incident.title}}"
    on_success: enrich_iocs

  - id: enrich_iocs
    name: "Pull related IOCs"
    type: enrich
    config:
      sources:   [threatflow]
      ioc_types: [ip, domain]
    on_success: contain
    on_failure: notify_escalation

  - id: contain
    name: "Contain affected endpoint"
    type: action
    timeout: 5m
    config:
      action_type: contain

  - id: notify_escalation
    name: "Escalate to incident commander"
    type: notify
    config:
      channel:          "security-escalation"
      message_template: "Containment failed — human takeover required."
```

Only three fields at the root are strictly required: `name`, `status`,
and `steps`. `version` defaults to `"1.0"` and `status` defaults to
`draft` if omitted.

## Step types

| `type` | What it does (v1.0.0) |
|---|---|
| `action` | Submit a governed action via CITADEL MARSHAL. In v1.0.0 this is a **dry-run stub** that records intent; the real dispatcher arrives with Phase-4 client wiring |
| `notify` | Enqueue a notification. Same dry-run status in v1.0.0 — the step records the channel and template; the external push is pluggable |
| `wait` | Sleep for `config.timeout`, or return immediately when no timeout is set. Respects context cancellation |
| `enrich` | Pull IOCs from ThreatFlow and attach them to the current incident. Dry-run in v1.0.0 |
| `scan` | Trigger an APIGuard scan of the named target. Dry-run in v1.0.0 |
| `conditional` | Branch based on `config.expression`. Dry-run today (always passes); CEL evaluation lands with v1.2 |

Every step type returns a `StepResult` with `status` = `"success"` or
`"failed"` plus a short `output` string. Dry-run types still record the
intent — the persistence shape is stable, only the side effects change
when real dispatchers land.

## Traversal rules

- Execution starts at the **first step** in the `steps` list — in
  practice, put your entry point first.
- After each step, the executor follows `on_success` when the step
  returns `success`, or `on_failure` when it returns `failed`.
- A step with **no `on_success`** and a successful result ends the
  execution cleanly (`Execution.status = completed`).
- A step with **no `on_failure`** and a failed result ends the
  execution with `Execution.status = failed`.
- A step with an `on_failure` that leads to a `notify` or `conditional`
  can recover — the execution still ends in `completed` once the
  fallback chain returns success.
- A `currentID` that doesn't match any step in `stepMap` aborts the
  execution with `Execution.error = "unknown step id: ..."`.
- There's a hard cap of **100 step invocations per execution**. Cycles
  (A → B → A) are caught by this guard.

## Timeouts

`step.timeout` accepts a Go `time.Duration` string: `"30s"`, `"5m"`,
`"1h"`. When set, the step runs under a derived context with that
deadline; if the step hasn't returned by then, it fails with a
context-deadline error — the step's `StepResult.status` becomes
`"failed"` and the executor follows `on_failure`.

Unset timeouts inherit the enclosing 1-hour execution-level deadline.

## Trigger matching

The `trigger` block determines which inbound events can auto-execute a
playbook. In v1.0.0, trigger matching is **advisory only** — playbooks
are executed on demand via `POST /api/v1/playbooks/{id}/execute`.
Automatic trigger-based dispatch is a v1.2 feature; documenting the
`trigger` block now means you won't have to re-author your playbooks
later.

| Field | Matches |
|---|---|
| `event_type` | Exact match against the inbound event's `event_type` |
| `severity` | Optional — restrict to events carrying this severity |
| `source` | Optional — restrict to events from this platform (`apiguard`, `citadel`, `threatflow`) |
| `condition` | Optional — free-form CEL expression, v1.2+ |

## Anti-patterns

- **Don't make `action` the last step without an `on_success`** — if
  the action fails you'll miss the failure path. Always pair it with
  either a follow-up step or an explicit `on_failure` that notifies.
- **Don't use `wait` without a timeout** — the step will return
  immediately, which is rarely the intent.
- **Don't build cycles deliberately** — the 100-step guard will kill
  the execution. If you need a retry loop, model it explicitly with
  bounded counts (fail → `wait` → try-again → done).
- **Don't embed secrets in `config`** — the full step definition is
  stored in the DB and returned by `GET /api/v1/playbooks/{id}`.
  References (e.g. `config.credential_ref: "apikey/prod"`) that the
  dispatcher resolves at runtime are the right pattern.

## Examples shipped with IRFlow

Two reference playbooks live under [`../examples/`](../examples/):

- [`playbook_critical_finding.yaml`](../examples/playbook_critical_finding.yaml) — 7-step response to an APIGuard CRITICAL, including enrichment and verification rescan
- [`playbook_hard_stop.yaml`](../examples/playbook_hard_stop.yaml) — 3-step response to a CITADEL HARD_STOP, covering incident creation, multi-channel notification, and project-freeze verification

Use them as a starting point; copy, rename, and tweak.

## Workflow

1. Author the playbook YAML locally.
2. `POST /api/v1/playbooks` with the parsed JSON body — IRFlow stores
   it and returns the generated `id`.
3. Mark it active (default is `draft` for safety) either at creation
   time with `status: active` or via `PATCH /api/v1/playbooks/{id}`.
4. Run it: `POST /api/v1/playbooks/{id}/execute` with
   `{"incident_id": "..."}`. IRFlow returns a 202 Accepted and an
   `Execution` in `pending`.
5. Poll `GET /api/v1/executions/{id}` until `status` is terminal.

For CI-managed playbook definitions, commit them to your operational
repo and re-apply them on every deploy via a small script that hits the
API — there's no built-in "sync from filesystem" command in v1.0.0.

## Related

- [API reference § Playbooks](./api.md#playbooks)
- [Architecture § Graph-based playbook executor](./architecture.md#graph-based-playbook-executor)
- [Example playbooks](../examples/)
