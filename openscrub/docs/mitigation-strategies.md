# Mitigation Strategies

## Three-Tier Mitigation Model

OpenScrub applies mitigation in three escalating tiers. Each tier is more disruptive than the previous but handles a wider class of attacks.

| Tier | Method | Impact | Target scenario |
|------|--------|--------|-----------------|
| 1 | XDP drop | Drops matching packets in kernel, legitimate traffic unaffected | Rate-limit violations, blocklisted sources |
| 2 | BGP blackhole (RTBH) | Drops all traffic to victim prefix at upstream edge | Link-saturation attacks, exhausted scrubbing capacity |
| 3 | Upstream null-route | Provider-side discard, coordinated out-of-band | Attacks exceeding RTBH peer capacity |

Tier 3 requires out-of-band coordination with upstream transit providers. OpenScrub automates tiers 1 and 2; tier 3 is triggered via operator action informed by an OpenScrub alert.

---

## When Each Tier Activates

**Tier 1 (XDP drop):**

- Any threshold breach at any severity level.
- Specific source IPs or prefixes matching ThreatFlow IOC blocklist entries.
- Activates within one evaluation tick (default: 5 seconds).

**Tier 2 (BGP blackhole):**

- Attack severity reaches Critical (threshold breach > 100%), or
- Scrubbing interface utilisation exceeds `mitigation.bgp.escalation_bw_percent` (default: 80% of link capacity), or
- Tier 1 has been active for longer than `mitigation.bgp.escalation_delay_seconds` (default: 120) without the attack subsiding.

**Tier 3 (upstream null-route):**

- Operator-initiated only. OpenScrub generates a pre-filled null-route request ticket via the REST API (`POST /api/v1/mitigation/upstream-nullroute`) with prefix, AS path, and event ID for provider submission.

---

## Automatic Escalation Logic

`internal/mitigation/scrubber.go` runs the central mitigation loop:

1. Receives attack events from the detection engine.
2. Evaluates the current tier for the affected prefix.
3. Applies or escalates mitigation based on the rules above.
4. Records every state transition to the event log with timestamp and reason.
5. Periodically re-evaluates active mitigations to check for de-escalation eligibility.

De-escalation happens when traffic drops below threshold for the full cool-down period (`mitigation.cooldown_seconds`, default: 300). De-escalation always steps down one tier at a time: tier 2 → tier 1 → cleared.

The scrubber goroutine is the single writer to both XDP maps and BGP state. No other code path modifies active mitigation directly.

---

## Safe Rollback

`internal/mitigation/rollback.go` provides atomic rollback for mitigation state:

- `RollbackPrefix(prefix)` — withdraws any BGP blackhole for the prefix and flushes all XDP rules matching that prefix.
- `RollbackAll()` — full state reset: clears the XDP blocklist map and withdraws all active blackholes.
- Before any rollback, current state is snapshotted to the database so the action is auditable.
- Rollback is idempotent; calling it on a prefix with no active mitigation is a no-op.

Rollback does not suppress the detection engine. If the attack is still ongoing, the scrubber will re-apply mitigation within the next evaluation cycle. Use the safelist to prevent re-application if rollback was triggered by a confirmed false positive.

---

## Manual Override via CLI

```bash
# Force XDP drop for a prefix
openscrub mitigate xdp drop 203.0.113.42/32

# Trigger BGP blackhole manually
openscrub mitigate bgp blackhole 203.0.113.0/24

# Rollback a specific prefix
openscrub mitigate rollback 203.0.113.0/24

# Rollback everything
openscrub mitigate rollback --all

# Check active mitigations
openscrub mitigate status
```

## Manual Override via REST API

```
POST /api/v1/mitigation/xdp/drop
POST /api/v1/mitigation/bgp/blackhole
POST /api/v1/mitigation/rollback
GET  /api/v1/mitigation/status
```

All REST API calls require a valid bearer token. See `docs/api.md` for authentication details. Every manual action is logged with the authenticated user identity for audit purposes.
