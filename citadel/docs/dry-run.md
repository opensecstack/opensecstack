# Dry-Run Mode

CITADEL supports a dry-run mode for MARSHAL evaluations: callers
receive a full `Decision` with all five gate results, **but** Gate 5
is deliberately skipped — no WORM entry is appended. This makes
dry-run useful for testing, policy simulation, and
before-you-ship validation, without polluting the audit chain with
fictional decisions.

This document explains when dry-run is appropriate, when it emphatically
is not, and how to detect accidental production use.

For Gate 5 in a normal evaluation, see [marshal-engine.md § Gate 5](./marshal-engine.md#gate-5--worm-audit).
For the Kerkese schema's `dry_run` field, see [kerkese-spec.md § `dry_run`](./kerkese-spec.md#dry_run--boolean).

## How it works

```
Caller sends Kerkese with "dry_run": true
    ↓
MARSHAL runs gates 1-4 as normal
    ↓
Gate 5 (WORM append) is SKIPPED
    ↓
Response returned with full decision shape,
but worm_entry_id = null (or omitted)
```

The decision object itself is fully populated — outcome, gate
results, reasons — so callers can see *what would have happened*.
They just don't get a WORM entry to reference later.

## Legitimate uses

### Client integration tests

Callers testing their Kerkese construction want to know MARSHAL
accepts the payload shape and their role/action mapping is correct.
Real WORM entries during `go test` would clutter the chain with
entries that never correspond to real business events.

```go
// In a test
k := buildKerkese()
k.DryRun = true

decision, err := citadelClient.Evaluate(ctx, k)
assert.NoError(t, err)
assert.Equal(t, "EXECUTE", decision.Outcome)
```

### Policy simulations

A security engineer considering a new AUGUR rule wants to see how many
historical-like Kerkeses would have triggered it. Dry-run mode lets
them run the engine over synthetic inputs without polluting the
chain with simulated-attack events.

### Before-deploy validation

Just before a major deploy, an operator can submit a canary Kerkese in
dry-run mode to confirm the engine is reachable and configured. A
production EXECUTE Kerkese for a no-op action would work too, but
dry-run avoids creating a "deployment test" audit record.

### Staging environments

Staging environments that share config with production — except for
the `DRY_RUN` flag being true — can exercise the full API surface
without touching the production WORM chain. The CITADEL side can be
configured with `CITADEL_DRY_RUN=true` to force every evaluation into
dry-run regardless of the Kerkese's own setting.

## Misuses — never do this

### As a "turn off governance temporarily" switch

Dry-run has appeared in incident runbooks (incorrectly) as a way to
keep the system working when CITADEL is misbehaving. Do not use it
this way:

- The action is not recorded as either EXECUTE or REFUSE in the chain.
- Auditors cannot reconstruct what happened.
- Any post-hoc claim about whether the action was authorised is
  unsupported.

If CITADEL is down, accept the outage. See [sop-012-incident.md § SOP-012C](./sop-012-incident.md#sop-012c--citadel-unavailable).

### For performance reasons

Dry-run is faster than a full evaluation because it skips the 4.22 ms
WORM append. The idea "let's dry-run high-volume calls and WORM-log
one in ten" gets floated periodically.

Reject it. Sampling the audit chain defeats the chain. An attacker
who knows only 1-in-10 calls are logged learns to pace their abuse
to fall between the logged windows.

### To "test in production"

Dry-run Kerkeses look identical to real ones in call-rate metrics.
Mixing dry-run and real in production makes operational metrics
unreliable. Keep dry-run strictly in non-production environments.

## Detection

Dry-run abuse detection should be automated:

### Per-environment flag

Production CITADEL should have `CITADEL_DRY_RUN_ALLOWED=false` set.
When the flag is false, any inbound Kerkese with `dry_run: true` is
**rejected with 400** rather than honoured.

```
{ "error": "dry_run is not allowed in this environment" }
```

This is the primary defence. Staging and dev have the flag true;
production has it false.

### Audit on flag change

Any change to the `DRY_RUN_ALLOWED` flag is itself a governance event
and passes through MARSHAL with its own WORM entry. You cannot
silently enable dry-run in prod — the audit chain shows who did it
and when.

### Metrics

```
citadel_marshal_decisions_total{outcome="EXECUTE",dry_run="true"}
```

Should be zero in production. Any non-zero value is either a bug or
misconfiguration; investigate immediately.

## Dry-run in CI

The recommended CI setup:

```yaml
# .github/workflows/ci.yml
env:
  CITADEL_DRY_RUN_ALLOWED: "true"
  CITADEL_DRY_RUN: "false"   # don't force; let tests opt in

# Tests opt in per-case:
# k.DryRun = true
```

Shared test-CITADEL instances across projects should have
`DRY_RUN_ALLOWED=true` and pair with `WORM_READONLY=true` — combine
for maximum isolation: even if a test accidentally sends `dry_run:
false`, the WORM append fails rather than pollute the chain.

## Related

- [MARSHAL engine § Dry-run mode](./marshal-engine.md#dry-run-mode) — short cross-reference
- [Kerkese schema § `dry_run`](./kerkese-spec.md#dry_run--boolean)
- [Operator runbook § Dry-run mode](./operator-runbook.md#dry-run-mode) — operational knob
- [Known limitations](./known-limitations.md) — audit of what dry-run cannot do
