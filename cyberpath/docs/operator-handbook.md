# CyberPath Operator Handbook

Day-to-day operational guide for CyberPath. For incident response,
see [../SECURITY.md](../SECURITY.md). For deployment, see
[../../docs/deployment-topology.md](../../docs/deployment-topology.md).
For architecture, see [./architecture.md](./architecture.md). For
the instructor-facing flows, see
[./instructor-handbook.md](./instructor-handbook.md).

> Status: design intent for v1.0.0 / v1.0.0. Field names and CLI
> flags will firm up as code lands. The shape mirrors VertGuard's
> [operator-handbook.md](../../vertguard/docs/operator-handbook.md)
> for cross-platform familiarity.

## Morning routine (5 minutes)

```bash
# 1. Health
curl -sf https://cyberpath.internal:8086/api/v1/health | jq .

# 2. Integrations
curl -sf https://cyberpath.internal:8086/api/v1/health | jq '.integrations'
# Expect: { "citadel": "connected", "nis2compass": "connected", "irflow": "connected" }

# 3. Sandbox health (v1.0.0+)
curl -sf https://cyberpath.internal:8086/metrics | grep 'cyberpath_lab_session'

# 4. Alert queue
# Check Grafana / alert channel for any overnight CyberPath alerts
```

Healthy state:

- All modules report `active` (or `inactive` for v1.0.0 modules
  not yet shipped, as expected)
- CITADEL + NIS2 Compass + IRFlow integrations `connected`
- `cyberpath_citadel_queue_depth` near 0
- No sustained 5xx on `/api/v1/quizzes/{id}/submit` or
  `/api/v1/labs/{id}/start`
- `cyberpath_content_hash_mismatch_total` is **0**. Any non-zero
  value is a content-versioning integrity break — page on-call.

## Daily monitoring

Dashboards (Prometheus / Grafana):

| Panel | Healthy | Action threshold |
|---|---|---|
| `/health` uptime | 100% | < 99.9% over 5m → P1 |
| Active lab sessions | deployment baseline | > 90% sandbox concurrency cap → scale |
| Sandbox crashloop count | 0 | > 3 in 10m → page |
| Completion submission failure rate | < 0.1% | > 1% over 10m → P2 |
| `cyberpath_citadel_queue_depth` | < 100 | > 1000 sustained → P2 |
| `cyberpath_content_hash_mismatch_total` | 0 | > 0 ever → P1 |
| Quiz submission p95 latency | < 200ms | > 500ms over 30m → P3 |

Alert signals worth wiring up specifically:

- **sandbox-crashloop** — wasmtime exit codes != 0 in pattern
  suggesting environment-level breakage, not learner-level error.
- **completion-submission-failure** — `POST
  /api/v1/lessons/{id}/complete` 5xx. Each failure is a learner
  who *did* the work and the platform may be losing the record.
- **content-hash-mismatch** — `content_versions.content_hash` does
  not match the recomputed hash. Either FS corruption or
  unauthorised content edit. P1 by default.

## Backup verification cadence

CyberPath persists in PostgreSQL only; the wasm sandbox is stateless
per session and the lab images are content-addressed in the
registry. Critical tables: `users`, `paths`, `modules`, `lessons`,
`completions`, `certifications`, `content_versions`, `lab_sessions`.

Cadence:

- **Daily** — automated PG backup (handled by infra).
- **Weekly** — operator runs a restore-into-staging drill on the
  most recent backup; spot-checks 5 random `completions` rows
  resolve to valid CITADEL WORM entries.
- **Monthly** — full restore into a clean cluster; verify a
  certificate signature against the published Ed25519 public key.
- **Quarterly** — disaster-recovery rehearsal (full doc lands at
  `docs/disaster-recovery.md` with v1.0.0; until then follow the
  general operations runbook from the ecosystem docs).

## User support runbooks

Most user issues are handled through the opensecstack/sdk auth path —
CyberPath delegates identity. The runbooks below are CyberPath-
specific.

### Locked accounts

```bash
# Check lock state
cyberpath-cli user inspect <user-id-or-email>

# Unlock (delegates to opensecstack/sdk auth)
cyberpath-cli user unlock <user-id-or-email>
```

Account lock decisions live in the SDK auth tier. CyberPath only
surfaces the state.

### Password reset

Delegated to opensecstack/sdk auth. Direct the user to the standard
ecosystem reset flow; CyberPath has no password reset path of its
own.

### MFA reset

Also delegated. CyberPath inherits MFA enforcement from the SDK
auth middleware. To reset, use the ecosystem auth admin path.

### Content access issues

Symptom: learner reports a lesson "won't load" or shows in the
wrong language.

```bash
# Verify the content_version is materialised on this replica
cyberpath-cli content show <track-id> <lesson-id> --version <semver>

# If missing: re-sync content
cyberpath-cli content sync --track <track-id>

# Check parity (sq + en both present)
cyberpath-cli content lint --check-parity content/<track-id>/
```

If content sync repeatedly fails to converge, this is likely a
content-hash mismatch and should escalate to P1.

## Tenant onboarding

> Briefly here; full details land in `docs/tenancy.md` with v1.0.0.

A tenant is a logical grouping of cohorts and learners with isolated
content/visibility. Onboarding checklist:

1. **Tenant id** — slug, `/^[a-z][a-z0-9-]{2,40}$/`. Used as a
   prefix in JWT claims and as a partitioning key.
2. **JWT provisioning** — request a tenant-scoped service token
   from the ecosystem auth admin. Token carries `tenant: <id>` and
   `scope: cyberpath.instructor`.
3. **Rate-limit profile** — pick from `small` (≤ 100 learners),
   `medium` (≤ 1000), `large` (> 1000). Determines per-tenant API
   quota and sandbox concurrency allotment.
4. **Content visibility** — default is tenant-internal. Cross-
   tenant content sharing is opt-in (PR-based at the content repo
   level).
5. **CITADEL project id** — each tenant maps to a CITADEL project
   for evidence segregation.

## Capacity planning

### Cohort-of-1000 sizing

For a single cohort of 1000 learners working through a 6-hour track
over 4 weeks:

| Resource | Required |
|---|---|
| API replicas | 3 (rolling burst headroom) |
| Postgres | 1 primary + 1 replica; `max_connections ≥ 200` |
| Sandbox pods (v1.0.0) | 4–8, depending on lab concurrency |
| CITADEL queue depth headroom | 10k (for end-of-cohort completion bursts) |

Empirically the load is *bursty*: most learners submit in the
final 72 hours of the cohort window. Plan headroom for that, not
for the average rate.

### Sandbox concurrency

Each wasmtime sandbox pod hosts up to `CYBERPATH_SANDBOX_MAX_SESSIONS`
(default 32) concurrent lab sessions, capped by the 512 MB memory
default per session. Scale pods linearly with concurrent active
labs; the platform's sandbox session router load-balances across
pods by lowest-active-session count.

### Postgres connection pool

```
CYBERPATH_DB_MAX_OPEN_CONNS × replicas ≤ Postgres max_connections − 10
```

Same rule as VertGuard. Reserve 10 connections for ad-hoc admin /
backup tooling.

## Routine cleanups

### Stale sandbox sessions

A lab session past its `time_limit_seconds` should already have been
torn down by the runtime. If not (sandbox host hung):

```bash
cyberpath-cli sandbox sessions list --state active --older-than 1h
cyberpath-cli sandbox sessions terminate <session-id>
```

The terminator records the session as `aborted` rather than
`failed` so the learner's attempt isn't counted as a failed
submission.

### Expired certifications

A certification past `expires_at` is *not* automatically revoked —
expiry and revocation are different events. The platform fires a
notification flow:

- 30 days before expiry: learner notified via email
- 7 days before: learner + their cohort instructor notified
- At expiry: certification flagged `expired` (still visible in
  audit; excluded from current `coverage` queries)

Operator action: monthly, verify the notification scheduler is
running:

```bash
cyberpath-cli scheduler status
```

### Abandoned cohorts

Cohorts past their `target_end + 90 days` with < 25% completion
are flagged in the operator dashboard as candidates for closure.
Closure is an instructor action, not an operator one — surface the
flag, do not auto-close.

## Incident response triggers

Page on-call for any of the following:

| Trigger | Severity | Why |
|---|:-:|---|
| Sandbox escape suspicion (host process anomaly correlated with a lab session) | **P1** | Sandbox-escape is the platform's headline threat; SECURITY.md SLA applies |
| Mass quiz-tampering signal (anomalous answer-pattern across many learners simultaneously) | **P1** | Possible coordinated attempt or data leak of question banks |
| Evidence-chain anchor failure (CITADEL `cyberpath.completion` emit failures > 1% over 30m) | **P1** | Completions happening without audit anchor |
| `cyberpath_content_hash_mismatch_total` > 0 | **P1** | Content integrity break |
| `/health` down 2+ min | **P1** | Platform unreachable |
| Sandbox crashloop > 3 in 10m | **P2** | Sandbox instability affecting multiple learners |
| Completion submission failure rate > 1% over 10m | **P2** | Learners losing work |
| NIS2 Compass coverage endpoint 5xx rate > 1% | **P3** | Compass cannot get coverage; affects gap analytics, not learner workflow |

Sandbox-escape disclosures from external researchers: see
[../SECURITY.md](../SECURITY.md) for the disclosure SLA. Internal
detection: isolate the affected sandbox pod (cordon, do not delete
— preserve memory for forensics), notify security lead, file a
`security.cyberpath.sandbox` event into CITADEL.

## Common operations

### Rotating CITADEL HMAC secret

Same procedure as VertGuard's:

1. Generate new secret: `openssl rand -base64 48`.
2. Add to secret manager as `cyberpath-citadel-key-secret-vN`.
3. Update CITADEL acceptance list (overlap window).
4. Update `CYBERPATH_CITADEL_KEY_SECRET` config.
5. Roll deployment.
6. After 48h, retire the old secret.

### Rotating the certification signing key (Ed25519)

1. Generate new keypair via the KMS reference.
2. Publish new public key to the deployment's published-keys
   endpoint *before* signing anything new with it (verifiers need
   it).
3. Update `CYBERPATH_CERT_SIGNING_KEY` to the new KMS reference.
4. Roll deployment.
5. Old public key remains published indefinitely — older
   certificates verify against it. **Do not** un-publish.

### Forcing a content re-sync after a content repo update

```bash
cyberpath-cli content sync --all
cyberpath-cli content lint --strict
```

A failing lint blocks publication; the previous content version
remains served until the lint passes.

## Scaling

CyberPath Go tier is stateless; add replicas behind the load
balancer. The wasmtime sandbox tier scales independently — sandbox
pods carry per-session state but no cross-session state, so they
scale horizontally with `kubectl scale`.

## Related

- [./architecture.md](./architecture.md)
- [./instructor-handbook.md](./instructor-handbook.md)
- [./track-content-guide.md](./track-content-guide.md)
- [./lab-content-guide.md](./lab-content-guide.md)
- [./citadel-integration.md](./citadel-integration.md)
- [./nis2-integration.md](./nis2-integration.md)
- [../SECURITY.md](../SECURITY.md)
- [../ROADMAP.md](../ROADMAP.md)
- [../../vertguard/docs/operator-handbook.md](../../vertguard/docs/operator-handbook.md) — sibling platform, same shape
