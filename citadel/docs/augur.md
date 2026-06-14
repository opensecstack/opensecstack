# AUGUR — Behavioural Heuristics (Gate 4)

AUGUR is the behavioural-analysis layer of MARSHAL. Where Gates 1-3
answer "is this caller *allowed* to do this?", AUGUR asks "does this
fit the normal pattern of how this caller behaves?". It is the gate
most likely to catch insider abuse and credential-compromise attacks
that pass cleanly through AuthN/AuthZ/NDS.

For the gate in the wider MARSHAL context, see [marshal-engine.md § Gate 4](./marshal-engine.md#gate-4--augur-behavioural-heuristics).
For the Go implementation, see [internal/marshal/marshal.go:208](../internal/marshal/marshal.go#L208).

## Rule catalogue (v1.0.0)

Three rules ship with v1.0.0. They are intentionally conservative — an
enterprise can tune thresholds through configuration, but the rule
*shape* is stable and WORM-observable so auditors can reason about
outcomes.

### rule_01 — Off-hours action

**Condition:** `kerkese.ts_utc.Hour() < 7 || kerkese.ts_utc.Hour() >= 19`

**Rationale:** most legitimate operator activity happens during
business hours (07:00–19:00 UTC). An action at 03:00 UTC is worth
flagging even if it passes every other gate.

**Status:** `WARN` — logged but does not block. An actual blocking
rule for off-hours would cause too many false positives for 24/7
operations; the warn surface is enough for after-the-fact review.

**Reason string:**
`AUGUR_rule_01: action initiated outside business hours (hour=N UTC)`

**Thresholds tunable via:** (v1.1+) `CITADEL_AUGUR_BUSINESS_HOURS_START`
and `CITADEL_AUGUR_BUSINESS_HOURS_END`.

### rule_02 — High frequency

**Condition:** the same `actor.user_id` has logged more than 10 Kerkese
evaluations in the last 5 minutes.

**Rationale:** human operators rarely sustain > 10 governed actions in
5 minutes. Spikes indicate either a scripted attack trying to race
past a window, or a legitimate automation that should be migrated to
a `service` role token.

**Status:** `WARN` — appended to the existing reason string if
rule_01 also fired.

**Reason string addition:**
`AUGUR_rule_02: high frequency (N actions in 5min)`

**Implementation:** `Store.ActionCount(ctx, userID, 5*time.Minute)`
queries a sliding-window counter maintained by the WORM append path.

### rule_03 — `DATA_EXPORT` without incident

**Condition:** `action.type == "DATA_EXPORT"` AND `action.incident_id` is empty.

**Rationale:** data exfiltration without an active incident context
is the single highest-risk pattern in the threat model. An attacker
who has captured a live session will often try a bulk export first;
an honest operator always ties exports to a specific investigation.

**Status:** `HARD_STOP` — overrides any prior WARN.

**Reason string:**
`AUGUR_rule_03: DATA_EXPORT attempted without incident_id — HARD_STOP`

## Why only three rules?

Three rules are what v1.0.0 ships because each one:

1. Has a **clear, WORM-observable signal** — an auditor reading the
   chain can reproduce the decision without re-running the engine.
2. Has **low false-positive rate** — fewer than 1 in 100 legitimate
   operations should trigger rule_01; rule_02 and rule_03 should
   approach zero.
3. Is **implementable in-process** — no external ML model, no
   time-series database, no reliance on uptime of a separate service.

Expanding the catalogue is explicitly out of scope until v1.2. At that
point, a rule-as-code plugin system becomes justifiable; adding rules
today means maintaining an API surface that may need to change when
the plugin story lands.

## Status severity

| Status | Meaning | Effect on outcome |
|---|---|---|
| `PASS` | All rules evaluated cleanly | No change — outcome determined by other gates |
| `WARN` | rule_01 or rule_02 fired | Logged in reasons; outcome unchanged (still EXECUTE/REFUSE from prior gates) |
| `HARD_STOP` | rule_03 fired | Outcome forced to HARD_STOP |

## Interaction with IRFlow

When AUGUR emits `HARD_STOP`, downstream effect in IRFlow:

1. `POST /api/v1/incidents/.../actions` returns `403 ErrMarshalHardStop`.
2. IRFlow's webhook handler (if CITADEL → IRFlow HARD_STOP webhook
   is configured) receives `citadel.marshal.hard_stop` and creates
   a P1 incident.
3. Project freeze runbook fires if configured.
4. On-call is paged.

The WARN statuses are audit-only: IRFlow logs them into the action's
`marshal_decision` field but does not escalate. An operator reviewing
a week of actions can `grep AUGUR_rule_01` to spot after-hours
patterns.

## Observability

Metrics:

| Metric | Meaning |
|---|---|
| `citadel_augur_rule_fires_total{rule, status}` | Counter per rule per status |
| `citadel_augur_hard_stops_total` | Convenience counter for rule_03 specifically |

Alerting rule: `rate(citadel_augur_hard_stops_total[5m]) > 0` — a
HARD_STOP event is per-se incident-worthy. Rule_01 and rule_02 warns
are expected background noise; alert only on sustained > 10% of all
decisions.

## Tuning guidance

| Parameter | Default | When to change |
|---|---|---|
| Business-hours window | 07:00–19:00 UTC | Organisations operating primarily in a single non-UTC timezone; shift per local business hours |
| High-frequency threshold | 10 actions / 5 min | Raise to 20–30 for organisations with heavy automation under `service` role; consider separate threshold for `service` in v1.1 |
| DATA_EXPORT without incident | `HARD_STOP` always | Do not change — this rule exists precisely to make the behaviour impossible |

## Future work

- **rule_04 (v1.2):** geographic mismatch — actor's recent auth IPs
  come from > N countries in < M hours. Requires a session-location
  store.
- **rule_05 (v1.2):** rare action type — actor has never performed
  this `action.type` before AND no peer in their role group has
  either in the last 30 days. Requires historical query on WORM.
- **Plugin system (v2.0):** rules authored as Go plugins with a
  stable interface for third-party security teams to add their own
  heuristics without forking CITADEL.

## Related

- [MARSHAL engine](./marshal-engine.md) — how AUGUR fits the overall flow
- [WORM log](./worm-log.md) — where rule outcomes are recorded
- [Known limitations](./known-limitations.md) — what AUGUR deliberately does *not* catch
