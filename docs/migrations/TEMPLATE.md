# Migration Guide: v<X> → v<Y>

> **Copy this file when cutting a major release.** Rename to
> `<scope>-v<X>-to-v<Y>.md` (e.g. `citadel-v1-to-v2.md`) and fill in
> every section. Remove this banner and the template comments before
> merging.

Release date: `<YYYY-MM-DD when the final tag ships>`
Applies to: `<platform name or "ecosystem">`
From: `v<X>.<last-minor>.<last-patch>`
To: `v<Y>.0.0`

## TL;DR

<!-- Three-sentence summary: what's breaking, what's the minimum work
     to migrate, roughly how long it takes on a production deploy. -->

## Breaking changes

<!-- List every breaking change. One row per change. If a change
     was deprecated in a prior minor (per deprecation-policy.md),
     still list it here — removal is what makes it breaking. -->

| Category | What changed | Where |
|---|---|---|
| API endpoint | `DELETE /api/v1/incidents/archive` removed; use `PATCH /api/v1/incidents/{id}` with `{status:"archived"}` | irflow/internal/api/handlers |
| Config | `IRFLOW_WEBHOOK_SECRET` removed; set per-source secrets | .env.example |
| SDK | `NewClientLegacy()` removed from `sdk/go`; use `NewClient(url, opts...)` | sdk/go/opensecstack/client.go |
| Schema | `incidents.criticality` renamed to `incidents.severity` | irflow/migrations/005_rename_severity.sql |
| Behaviour | Default webhook clock skew reduced from 10m to 5m | internal/webhook/hmac.go |

## Migration path

### Prerequisites

<!-- Required state before starting. -->

- Deployed on `v<X>.<last-minor>.<last-patch>` — upgrade to the latest
  minor of the prior major first.
- Backup taken within the last 24h.
- Staging environment that mirrors production.
- `<list other upstream dependencies and their minimum versions>`.

### Step 1 — Review deprecation warnings

During `v<X>` operation, the process should have been logging
deprecation warnings for each item in the Breaking Changes table.
Grep the last 30 days of logs:

```bash
grep -i "deprecat" /var/log/<platform>/*.log | sort | uniq -c | sort -rn
```

Every match corresponds to code or config you must update.

### Step 2 — Update callers (if applicable)

<!-- For each removed API, config, or SDK function — show the before
     and after. -->

**Example — API endpoint removal:**

```diff
- curl -X DELETE $IRFLOW/api/v1/incidents/archive -d '{"id":"inc_123"}'
+ curl -X PATCH  $IRFLOW/api/v1/incidents/inc_123 -d '{"status":"archived"}'
```

**Example — Config rename:**

```diff
- IRFLOW_WEBHOOK_SECRET=<secret>
+ IRFLOW_WEBHOOK_APIGUARD_SECRET=<secret>
+ IRFLOW_WEBHOOK_CITADEL_SECRET=<secret>
+ IRFLOW_WEBHOOK_THREATFLOW_SECRET=<secret>
```

### Step 3 — Database migrations

<!-- If schema changes are involved, describe them explicitly. -->

```
-- For each migration file between vX and vY:
migrations/005_rename_severity.sql          # NEW in v2.0
migrations/006_add_index_worm_timestamp.sql # NEW in v2.0
```

Apply on a staging replica first:

```bash
<platform> migrate --target v<Y>.0.0
```

Check that the migration runs in reasonable time on production-like
data. A migration that takes > 5 minutes on production-size data
should be broken into online steps (add column nullable → backfill
→ set NOT NULL) across multiple minor releases.

### Step 4 — Deploy v<Y>.0.0

Standard rolling deploy:

```bash
kubectl set image deployment/<platform> <platform>=ghcr.io/opensecstack/<platform>:<Y>.0.0
kubectl rollout status deployment/<platform>
```

Health check:

```bash
curl -sf https://<platform>.internal/api/v1/health | jq .
```

Confirm `version` reflects the new tag on every pod.

### Step 5 — Verify end-to-end

<!-- For each major feature, what to test. -->

- [ ] Create a test incident; verify state transitions.
- [ ] Submit a governed action; verify MARSHAL decision path.
- [ ] Send a test webhook from each configured source.
- [ ] `GET /api/v1/worm/verify` over the last hour — must return
      `{"valid": true}`.

## Rollback plan

Rollback is supported within the first 48 hours if no forward-only
changes have been committed:

```bash
# Revert to the prior image
kubectl set image deployment/<platform> <platform>=ghcr.io/opensecstack/<platform>:<X>.<last>.<patch>

# Rollback DB if migrations were destructive
<platform> migrate --target v<X>.<last>.<patch>
```

**Forward-only changes** (no rollback possible) include:

- New WORM entries (cannot be deleted).
- NIS2 notifications already sent.
- Cross-platform state updates to CITADEL.

If you have forward-only state and need to go back, you migrate
forward to v<Y> then forward again to v<Y+1> if a fix lands —
don't try to back-migrate out of these.

## Compatibility during the transition

| Platform | Minimum version during transition |
|---|---|
| CITADEL | `<minimum compat version — see compatibility-matrix.md>` |
| IRFlow | `<...>` |
| ThreatFlow | `<...>` |
| APIGuard | `<...>` |
| NIS2 Compass | `<...>` |
| SDK | `<...>` |

Until **all** upstream and downstream platforms are at a compatible
version, leave the migration paused at its last safe checkpoint.

## Data migration

<!-- If this migration rewrites data, describe:
     - Estimated duration on production-size data.
     - Zero-downtime pattern (if applicable).
     - What happens mid-migration if the process is interrupted.
     - Validation queries to run after. -->

**Example — schema rename with backfill:**

```sql
-- Phase 1 (v1.9): add new column, nullable
ALTER TABLE incidents ADD COLUMN severity TEXT;

-- Phase 2 (v1.9): backfill via background worker
UPDATE incidents SET severity = criticality WHERE severity IS NULL;

-- Phase 3 (v2.0): constrain new column, drop old
ALTER TABLE incidents ALTER COLUMN severity SET NOT NULL;
ALTER TABLE incidents DROP COLUMN criticality;
```

## Testing checklist

- [ ] Unit tests pass on the new version.
- [ ] Integration tests pass against a staging instance.
- [ ] Smoke tests pass on production immediately after deploy.
- [ ] Monitoring dashboards show no unexpected error spike.
- [ ] A sample of pre-upgrade audit records still validates.
- [ ] A sample of post-upgrade records is produced correctly.

## Known issues

<!-- Populated during RC soak period. Each entry:
     - Symptom.
     - Workaround or fix target (patch release).
     - GitHub issue link. -->

## Erratum

<!-- If something turns out wrong after publication, add a dated
     entry here rather than editing the body above. Deployers may
     have followed the original; their records should match. -->

---

## FAQ

### Can I skip from `v<X-1>.x` to `v<Y>.0` directly?

No. Always upgrade to the latest minor of the prior major first, then
follow this guide. Skipping majors is not supported — deprecation
warnings accumulate and removals from multiple major jumps at once
are hard to diagnose.

### What if I have a custom integration?

Check the SDK migration notes in the same major bump. If you're
calling the platform's HTTP API directly (not through the SDK), the
Breaking Changes table above lists every HTTP-level change.

### How long does the migration window last?

`v<X>.x` continues to receive security-only fixes for **12 months**
after `v<Y>.0.0` ships. Plan the migration within that window.

## Related

- [Release process](../release-process.md) — how this version was cut
- [Deprecation policy](../deprecation-policy.md) — items marked Deprecated in earlier minors
- [Compatibility matrix](../compatibility-matrix.md) — version pairing during migration
- CHANGELOG entry for this release — `[<Y>.0.0] — <YYYY-MM-DD>` section
