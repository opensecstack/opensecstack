# SOP-012 — CITADEL Incident Response

Standard Operating Procedure for responding to incidents **affecting
CITADEL itself** — the governance engine that every other platform
depends on. This is the "break the glass" runbook; for incidents in
other platforms, see their respective operator handbooks.

Incident types covered:

- [SOP-012A: WORM chain verification failure](#sop-012a--worm-chain-verification-failure)
- [SOP-012B: Anchor key compromise](#sop-012b--anchor-key-compromise)
- [SOP-012C: CITADEL unavailable](#sop-012c--citadel-unavailable)
- [SOP-012D: MARSHAL decision divergence](#sop-012d--marshal-decision-divergence)

Each SOP is numbered and versioned; quote `SOP-012X v1` in the
incident post-mortem for traceability.

---

## SOP-012A — WORM chain verification failure

**Symptom:** `GET /api/v1/worm/verify` returns `{"valid": false, ...}`
with a non-empty `break_at`.

**Severity:** **P1** — the audit chain's integrity is the core CITADEL
guarantee; a failure here voids evidence claims until root cause is
known.

### Step 1 — Freeze the chain

Stop CITADEL's WORM writes immediately:

```bash
# Edit the deployment to set this flag:
CITADEL_WORM_READONLY=true
kubectl rollout restart deployment/citadel
```

With `WORM_READONLY=true`, MARSHAL still evaluates but Gate 5 refuses
to append — callers receive 503 on mutating operations. This prevents
a compromised chain from growing while you investigate.

### Step 2 — Identify the break point

Take the `break_at` string from the verification response:

```
break_at: "sequence_num=12847: triple_hash mismatch"
```

- `triple_hash mismatch` → the payload bytes on disk don't match the
  original hash. Either DB corruption or direct tampering with the
  payload column.
- `chain_hash mismatch` → the chain_hash was rewritten without
  recomputing. Almost always tampering (corruption would usually hit
  triple_hash first).
- `prev_hash does not match prior chain_hash` → an entry was spliced
  into a chain it doesn't belong to.

### Step 3 — Preserve evidence

Do **not** `DELETE`, `UPDATE`, or `VACUUM FULL` any WORM table.
Instead:

```sql
-- Snapshot the relevant window for forensics
CREATE TABLE worm_entries_snap_20260419 AS
SELECT * FROM worm_entries
WHERE sequence_num BETWEEN :break_point - 100 AND :break_point + 100;

CREATE TABLE chain_anchors_snap_20260419 AS
SELECT * FROM chain_anchors
WHERE sequence_num BETWEEN :break_point - 200 AND :break_point + 200;
```

Snapshot the DB cluster-level WAL for the same period — the PITR
backup is critical for reconstructing the attack timeline.

### Step 4 — Contact the auditor

Any WORM break affects **every** evidence claim made from that entry
forward. Notify:

- NIS2 competent authority (if in scope, 24-hour window).
- Legal / compliance team.
- Auditors holding recent exports — their bundles may need to be
  restamped from a pre-break anchor.

### Step 5 — Root-cause and recover

Run the full DB consistency check (`pg_amcheck --all`) on the
snapshot. Check OS logs, `pg_stat_activity` history, any DDL that
touched the table.

Once root cause is known:

1. If DB corruption → restore from PITR to the latest verified point
   and replay from IRFlow's `incident_actions` (the mutable mirror)
   to re-emit entries. **Every new entry has a new sequence_num** —
   there is no "rewind and rewrite".
2. If tampering → rotate all operator credentials, audit the access
   path, file a SECURITY issue per [SECURITY.md](../SECURITY.md).
3. Issue a new anchor over the recovered chain; invalidate and
   rotate the anchor key.

### Step 6 — Un-freeze

```bash
CITADEL_WORM_READONLY=false
kubectl rollout restart deployment/citadel
```

Post-mortem within 5 business days.

---

## SOP-012B — Anchor key compromise

**Symptom:** `CITADEL_CITADEL_MASTER_KEY` is suspected or confirmed
leaked. Indicators: repository leak, bastion compromise, former
admin whose access wasn't rotated, etc.

**Severity:** **P1** — anchors are the only thing standing between
tamper-evident and tamper-resistant guarantees.

### Step 1 — Rotate the key

1. Generate fresh Ed25519 keypair.
2. Store new private key in the secret manager under a new path
   (`citadel-anchor-key-2026-04-19`).
3. Update `CITADEL_CITADEL_MASTER_KEY` to reference the new path.
4. Publish the **new pubkey** under a new `pubkey_id` — publish, do
   not wait.
5. Roll CITADEL deployment.

### Step 2 — Mark the old key as revoked

In the pubkey registry (wherever auditors look up the pubkeys —
typically [../SECURITY.md](../SECURITY.md) or a dedicated key registry):

```yaml
- id:       "citadel-anchor-2026Q1"
  pubkey:   "..."
  issued:   "2026-01-01"
  revoked:  "2026-04-19"       # today
  reason:   "compromised"
  replaced_by: "citadel-anchor-2026-04-19"
```

**Do not delete** the old pubkey entry — anchors signed with it are
still valid for integrity checks up to the revocation date.

### Step 3 — Audit the exposure window

Anchors signed during the exposure window are **suspect**. An
attacker with the private key could have forged anchors that
validate.

Scope the window:

- `issued` date of compromised key.
- `revoked` date — today.
- Query anchors in that range, for each downstream export bundle that
  includes any of them.

### Step 4 — Notify holders of suspect bundles

Anyone holding an export bundle whose anchors fall in the exposure
window receives a signed notification listing the affected anchor
IDs and offering a re-stamp: new anchors signed with the new key
over the same historical chain_hashes.

### Step 5 — Post-mortem and hardening

- Where did the key live that allowed the compromise?
- Are all other secrets in the same store also suspect?
- Is HSM migration now justified (v2.0 KMIP work accelerates)?

---

## SOP-012C — CITADEL unavailable

**Symptom:** `/health` returns 5xx, or CITADEL pods crashloop, or
downstream platforms report `502 Bad Gateway` for MARSHAL calls.

**Severity:** **P1** — every governance-gated action across the
ecosystem is blocked.

### Step 1 — Confirm scope

```bash
# From outside the cluster
curl -v https://citadel.internal/api/v1/health

# From inside
kubectl get pods -l app=citadel
kubectl logs -l app=citadel --tail=200
```

If **all** replicas are down: infrastructure / DB / config issue.
If **some** replicas up: load balancer / network issue.

### Step 2 — Downstream impact

IRFlow and other callers are now returning 502 to their own clients.
Do **not** flip them to local-only mode to "keep working" — that
means persisting actions without MARSHAL approval, which is
unrecoverable policy damage.

Instead: accept the outage, post on the status channel, and focus on
CITADEL recovery.

### Step 3 — Standard K8s recovery

- Rollback to the prior image if the last deploy was recent.
- Check CITADEL's Postgres health (`pg_isready`).
- Re-issue startup env checks — a typo'd `CITADEL_DB_URL` on a config
  rollout is a common cause.

### Step 4 — If DB is the issue

Failover to a standby per your DB operator's runbook. CITADEL is
stateless and will reconnect once the DB is reachable; no CITADEL-side
state needs massaging.

### Step 5 — Post-mortem

Availability P1s compete for post-mortem slots with P1 security
incidents. Both are required within 5 business days.

---

## SOP-012D — MARSHAL decision divergence

**Symptom:** two identical Kerkeses submitted to two CITADEL replicas
return different outcomes.

**Severity:** **P2** — the gate logic is stateless (mostly), so
divergence points at a config or data-layer mismatch, not a fundamental
bug.

### Step 1 — Collect divergent pairs

Log both decisions with `decision.execution_id`, the exact Kerkese,
both responses, and the target replica (`hostname` in the CITADEL
response headers).

### Step 2 — Narrow the cause

- **Sinauth reachability:** if replica A can reach the sinauth JWKS
  endpoint (`CITADEL_SINAUTH_ISSUER_URL`) but replica B can't (DNS,
  egress NetworkPolicy, or a stale cached JWKS), Gate 1/Gate 3 token
  verification diverges between replicas. This is a network/config
  check on the affected replica, not a DB question — CITADEL has no
  local session table (see [ADR-005](../adrs/005-sinauth-identity-bridge.md)).
- **Rate-limit counters:** replica-local counter lag can cause Gate
  4 rule_02 divergence. The counters are in the DB, so genuine lag
  is a replication-bug indicator.
- **AUGUR time window:** the off-hours check uses
  `kerkese.ts_utc.Hour()` — the caller's timestamp — so clock
  divergence between replicas shouldn't matter. Verify.

### Step 3 — Un-route the suspect replica

Drain traffic from the replica returning the divergent answer.
Keep it alive for forensics.

### Step 4 — Reproduce in-situ

On the drained replica, replay the Kerkese with a fresh execution_id
and capture full logs. Compare DB state (`signing_keys`,
`rate_limit_counters`) and sinauth connectivity against a healthy
replica.

### Step 5 — Recover

Most commonly: wrong DB pointed at, or a stale env var. Fix config,
restart, re-join to load balancer. File a post-mortem.

---

## Follow-up for all SOP-012 incidents

- Write a post-mortem in the issue tracker (public by default unless
  the cause is a confidential security finding).
- Update this document if a new failure mode is discovered.
- Rehearse the runbook annually; note the rehearsal date in the
  operator log.

## Related

- [Hard-stop playbook](./hard-stop-playbook.md) — for non-CITADEL HARD_STOP events
- [Pre-freeze checklist](./pre-freeze-checklist.md) — prevention side
- [SECURITY.md](../SECURITY.md) — key rotation runbook in full
- [Operator runbook](./operator-runbook.md) — everyday operations
