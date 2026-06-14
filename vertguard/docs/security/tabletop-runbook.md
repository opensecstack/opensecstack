## VertGuard Quarterly Tabletop Exercise Runbook

Closes security-checklist gap 10.6.

This runbook guides the quarterly tabletop exercise required before the
external audit (T-2 weeks) and once per quarter thereafter. The exercise
rehearses the five highest-risk attack scenarios drawn from
`docs/security/threat-model.md` and the operator playbooks in
`docs/operator-runbook.md`.

**Format:** 90-minute facilitated exercise (no live systems modified).
**Cadence:** Once per quarter. First run is the T-2 weeks dry-run
referenced in `docs/security/pre-audit-plan.md`.
**Owner:** Security lead (facilitator); Engineering lead (final authority
on accepted residual risk decisions made during the session).

---

### 1. Participants

| Role | Responsibility during exercise |
|---|---|
| **Security lead** (facilitator) | Presents each scenario, injects new injects, records decisions and action items, keeps time |
| **On-call engineer** | Walks through detection and initial response steps; owns the live-system runbook knowledge |
| **CISO / engineering lead** | Authority on policy decisions, escalation thresholds, and accepted risk calls |
| **DevOps** | Answers cluster, secret-rotation, and deployment questions; confirms runbook accuracy |
| **Optional: red-team observer** | Challenges assumptions; may add adversarial injects mid-scenario |

A quorum of at least the security lead, on-call engineer, and one of
CISO or DevOps is required to run the session. Reschedule rather than
proceed without quorum.

---

### 2. Session structure (90 minutes)

| Time | Activity |
|---|---|
| 00:00–00:10 | Welcome, ground rules, objectives. Confirm participants and roles. |
| 00:10–00:28 | Scenario 1 — JWT secret compromise |
| 00:28–00:44 | Scenario 2 — ML model poisoning |
| 00:44–00:58 | Scenario 3 — CITADEL WORM replay attack |
| 00:58–01:10 | Scenario 4 — Database credential leak |
| 01:10–01:22 | Scenario 5 — DDoS against scan endpoint |
| 01:22–01:30 | Hot debrief: gaps found, owners assigned, next exercise date confirmed |

Each scenario block is approximately 15 minutes. The facilitator reads the
scenario, the team works through the detection, containment, and recovery
questions aloud. No one is allowed to say "I would just look it up" — the
goal is to surface what is not in the runbooks yet.

---

### 3. Ground rules

- This is a no-blame exercise. The goal is to find gaps in documentation,
  tooling, and process — not to assign fault.
- Decisions made during the tabletop are recommendations only. Changes
  require a follow-up ticket and normal engineering review.
- No changes are made to live systems during the session.
- The facilitator may inject new conditions mid-scenario (e.g. "the on-call
  engineer's laptop is compromised — who is the backup?").
- All discovered gaps are recorded in the action items log at the end of
  this document template; the security lead copies them into GitHub Issues
  within 24 hours.

---

### 4. Scenarios

---

#### Scenario 1 — JWT Secret Compromise

**Narrative:**
An alert fires at 02:30 UTC: `IncSecretUsed{slot="prev"}` metric is
spiking — the previous JWT signing slot is being used at 400 req/s.
Intelligence arrives that a CI runner log from a failed deploy 6 hours
ago contained `VERTGUARD_AUTH_SECRET` in plaintext. Tokens minted with
the leaked key are currently being used for admin-role API calls.

**Detection signals**
- Prometheus alert: `vertguard_secret_slot_used{slot="prev"} > threshold`.
- Audit log: high volume of admin-role events from unusual IPs or service accounts.
- CITADEL WORM entries showing admin mutations not initiated by known operators.
- GitHub Actions log contains the secret (search for `VERTGUARD_AUTH_SECRET`).

**Immediate actions (first 15 minutes)**
1. Confirm the CI log leak by searching GitHub Actions run logs.
2. Determine when the log was exposed and whether external access is possible.
3. Begin secret rotation: generate a new `VERTGUARD_AUTH_SECRET`, update the
   K8s Secret (`kubectl patch secret vertguard-secrets ...`), and trigger a
   rolling restart. The dual-slot `NewVerifierMulti` keeps current tokens valid
   during the brief overlap.
4. Use the JTI denylist endpoint (`POST /api/v1/admin/denylist`) to revoke any
   JTIs observed in the suspicious audit trail. Confirm with `GET /api/v1/admin/denylist`.
5. Page on-call escalation path per `docs/operator-runbook.md § 5`.

**Discussion questions — immediate phase**
- Who has access to the K8s Secret rotation command right now, at 02:30?
- Do we have a pre-generated replacement secret stored securely (e.g. in Vault)?
- How long will the rolling restart take, and what is the impact on users?
- Is the denylist large enough to cover all suspicious JTIs, or do we burn all
  tokens for affected subjects?

**Containment (15–60 minutes)**
1. Rotate CITADEL HMAC secret and ThreatFlow webhook secret as a precaution —
   the same CI runner may have had access to both.
2. Audit all admin API calls made in the window since the log was exposed.
   Cross-reference against CITADEL WORM events for tamper-evident verification.
3. Revoke or suspend the CI runner's deploy credentials.
4. Review GitHub Actions log retention and secret masking configuration.
   Ensure `VERTGUARD_AUTH_SECRET` is listed as a masked variable in all
   relevant workflow scopes.
5. Confirm `secret.create=false` in the production Helm values — the OPA
   constraint (`deploy/helm/vertguard/templates/opa-constraint.yaml`) should
   have blocked chart-managed secrets; verify Gatekeeper audit log.

**Eradication and recovery**
1. Purge the offending CI log (GitHub: Settings → Actions → delete run log).
2. Rotate all secrets on the 90-day cadence schedule in `docs/secrets-management.md`,
   advancing the clock for all affected secrets.
3. Verify no active sessions remain on old secret: monitor
   `vertguard_secret_slot_used{slot="prev"}` dropping to zero after rotation
   completes.
4. Restore normal operations; lift any temporary access suspensions.
5. File a GitHub Security Advisory if the window suggests externally-minted
   tokens were used against customer data.

**Post-incident review questions**
- Did the on-call engineer have all the access they needed within 5 minutes?
- Was the dual-slot rotation fast enough, or did users experience 401s?
- Were CITADEL WORM events sufficient to reconstruct the blast radius?
- Should we add rate-capping specifically to admin denylist mutations (current gap
  in `threat-model.md § AT-1`)?
- What masking configuration change prevents this class of leak?

---

#### Scenario 2 — ML Model Poisoning

**Narrative:**
The ML side-car fails its SHA-256 model checksum validation on startup
after an overnight automated model update pull. The container logs show:
`model checksum mismatch: expected=abc123 got=def456`. Separately, a
researcher has privately disclosed that a popular open-weights model on
HuggingFace was found to contain an embedded backdoor that causes GAN
detectors to always return `clean` for images with a specific pixel
pattern in the bottom-right corner.

**Detection signals**
- Container restart loop with checksum mismatch log line (Prometheus:
  `kube_pod_container_restarts_total{container="vertguard-ml"}` spike).
- HuggingFace advisory or researcher private disclosure email to
  `security@opensecstack.org`.
- Anomalous `clean` classification rates in Grafana — confidence
  distribution shifts toward 1.0 for the detector in question.
- CITADEL WORM entries show `CLEAN` verdicts on inputs that would
  historically be flagged.

**Immediate actions (first 15 minutes)**
1. Disable the ML side-car gRPC endpoint at the Istio/Linkerd policy level —
   update the `PeerAuthentication` or `ServerAuthorization` to block all
   inbound until the model is validated.
2. Roll back the ML container to the last known-good image tag (the one
   matching the pinned SHA-256 in `models.yaml`).
3. Alert the on-call engineer and CISO. Determine if any production scans
   occurred during the poisoned window.

**Discussion questions — immediate phase**
- Do we have an out-of-band channel to disable the ML endpoint without
  restarting the whole API pod?
- How quickly can we roll back the ML container? Is the last known-good image
  still in the registry and not evicted?
- What is our SLA for notifying customers if their scans may have been
  affected by a detection bypass?

**Containment (15–60 minutes)**
1. Pin `models.yaml` to the last verified SHA-256. Commit the change and
   trigger a new image build via `make docker-build`.
2. Re-run the adversarial test corpus (`tests/adversarial/`) against the
   rolled-back model to confirm classification quality is restored.
3. Audit CITADEL WORM entries from the affected window. Flag all `CLEAN`
   verdicts for retroactive review — audit rows include `input_hash` for
   triage.
4. Confirm mTLS is STRICT between API and ML pod (gap 1.4, now closed):
   no unauthenticated path to the gRPC port.
5. Review the model update automation. Is the SHA-256 pinned before or
   after the pull? The pull should fetch, hash, compare, then accept.

**Eradication and recovery**
1. Update `models.yaml` with new pinned hash from a trusted source.
2. Verify the source model matches the hash from an independent download
   (use a different machine / network).
3. Re-enable the ML gRPC endpoint once the new image passes all checks.
4. Send a private advisory to affected tenants if the blast radius includes
   their data (per `SECURITY.md § Coordinated disclosure`).
5. File an issue in the HuggingFace model repository and notify the broader
   community if the upstream model is publicly available.

**Post-incident review questions**
- Did the checksum validation catch the issue before any poisoned scans?
  If not, why not? Is the validation on startup or per-inference?
- Is the adversarial test corpus broad enough to catch backdoor triggers?
- Should we add a second source of truth for model hashes (e.g. Sigstore
  cosign attestation on the model weights file)?
- What is the minimum time from "suspicious classification distribution"
  to "model rollback complete"?

---

#### Scenario 3 — CITADEL WORM Replay Attack

**Narrative:**
The CITADEL upstream team reports that they have received the same
correlation ID emitted twice within a 90-second window — a duplicate
WORM entry. Investigation reveals that an attacker who intercepted an
outbound HMAC-signed WORM emit (via a compromised network path inside
the cluster) is replaying the captured body. The attacker's goal is to
inject a fraudulent `CLEAN` verdict into the immutable audit record.

**Detection signals**
- CITADEL dedup log: `duplicate_correlation_id` counter increments.
- Timestamp gap between two identical correlation IDs is outside normal
  jitter (the legitimate emit and the replay are seconds apart).
- `vertguard_citadel_emit_total` metric is higher than `audit_events`
  count for the same time window.
- Network policy audit log (if enabled) shows unexpected pod-to-pod
  traffic on the CITADEL egress path.

**Immediate actions (first 15 minutes)**
1. Confirm the duplicate with CITADEL upstream — they should have flagged
   it automatically. Get the exact correlation IDs involved.
2. Identify the legitimate original emit by comparing timestamps and
   request IDs against the internal `audit_events` table.
3. Rotate the CITADEL HMAC secret immediately (90-day cadence, emergency
   advance): `kubectl patch secret vertguard-secrets --patch ...`.
4. Check NetworkPolicy: is the cluster-level policy restricting who can
   reach the CITADEL egress endpoint? If NetworkPolicy is disabled
   (`networkPolicy.enabled=false`), enable it now.

**Discussion questions — immediate phase**
- What is the CITADEL upstream replay window? Do they enforce a timestamp
  freshness check, and what is the tolerance (seconds? minutes)?
- Can we query CITADEL directly to confirm which entries are legitimate
  and which are replays?
- Who has access to rotate the CITADEL HMAC secret? Is it different from
  the JWT secret rotation process?

**Containment (15–60 minutes)**
1. Enable NetworkPolicy on the vertguard namespace if it is currently off:
   `helm upgrade vertguard ... --set networkPolicy.enabled=true`.
2. Review circuit-breaker state (`internal/breaker/breaker.go`): the
   attacker may be trying to exhaust the async buffer to drop legitimate
   events.
3. Cross-reference every WORM emit in the affected window against the
   internal `audit_events` table. Flag any correlation ID that appears
   in CITADEL but has no matching internal audit row.
4. Request CITADEL upstream to mark the duplicate entries as invalid
   (if their platform supports it) or attach a dispute annotation.

**Eradication and recovery**
1. Confirm HMAC rotation is complete and old secret is no longer accepted
   by CITADEL upstream.
2. Audit the network path: how did the attacker capture the signed payload?
   This implies a man-in-the-middle within the cluster. Review pod exec
   audit logs and check for unauthorized `kubectl exec` or `kubectl port-forward`.
3. If the attacker had cluster-admin access, treat as a full cluster
   compromise: rotate all secrets, re-provision nodes, re-deploy from
   known-good images.
4. Document the CITADEL upstream's dedup mechanism and ensure the replay
   window is short (< 30 seconds). File a joint advisory if needed.

**Post-incident review questions**
- Is the timestamp.body Stripe-style HMAC sufficient, or do we need a
  short-lived nonce per emit?
- Should the async buffer emit log timestamps be checked against wall-clock
  at the CITADEL receiver?
- Is the NetworkPolicy off-by-default the right production default?
  Consider changing to on-by-default with an opt-out for non-Kubernetes
  deployments.
- Does the CITADEL upstream's dedup work retroactively, or only in real time?

---

#### Scenario 4 — Database Credential Leak

**Narrative:**
A developer accidentally pushes a debug configuration file containing the
production Postgres password to a public GitHub repository. The file is
detected 4 hours later by a secret-scanning tool. During that window, the
repository was indexed by at least one search engine.

**Detection signals**
- GitHub secret scanning alert (push protection or post-push detection).
- Unusual Postgres connection count spike: `pg_stat_activity` shows
  connections from unexpected IP ranges.
- Failed authentication attempts logged by Postgres (`log_connections=on`).
- `audit_events` shows reads or writes by an unknown actor (no matching
  JWT sub in the audit row — possible direct DB access bypassing the API).

**Immediate actions (first 15 minutes)**
1. Rotate the Postgres password immediately: update the K8s Secret and
   trigger a rolling restart of the VertGuard API pod.
2. Revoke any existing connections to the database using the old credential:
   `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='vertguard';`
3. Check `pg_stat_activity` and Postgres logs for connections from unknown
   IPs. Capture and preserve for forensics.
4. Remove the file from the public repository using `git filter-repo` or
   BFG Repo Cleaner. Force-push if necessary after team notification.

**Discussion questions — immediate phase**
- Is the Postgres password the same as the one in the K8s Secret, or could
  it be a stale / dev password that no longer works in production?
- Does the Postgres instance have network-level access controls
  (security groups / firewall rules) that limit inbound connections to
  cluster IPs only? If so, the 4-hour window may have been unexploitable.
- Who has the authority to force-push the cleanup to the public repository?

**Containment (15–60 minutes)**
1. Confirm `ssl_mode=require` is enforced for the Postgres connection
   (check `config.db.ssl_mode` in the Helm values and K8s Secret).
2. Review the 4-hour window in Postgres logs for:
   - Any `SELECT` from `audit_events`, `prompt_scans`, or `denylist` tables.
   - Any `INSERT` or `UPDATE` that does not match an `audit_events` row
     (would indicate direct-DB tampering, not via the API).
3. Notify any tenant whose scan data may have been read (per
   `SECURITY.md § Coordinated disclosure` SLA: 24h acknowledgment).
4. Review the `.gitignore` and pre-commit hooks: why was the file not caught
   before push? Add a `gitleaks` or `detect-secrets` pre-commit hook if absent.

**Eradication and recovery**
1. Confirm the rotated password is working and all pods are healthy.
2. Enable `log_connections=on` and `log_disconnections=on` in Postgres
   permanently for forensic readiness.
3. File a GitHub Security Advisory if tenant data was confirmed accessed.
4. Update `docs/secrets-management.md` with a post-mortem entry.
5. Add a pre-push `gitleaks` hook to the repository and document it in
   the developer onboarding guide.

**Post-incident review questions**
- Why was `secret.create=false` not the default in all environments?
  The OPA constraint (gap 5.6, now closed) would block this pattern in prod,
  but the leak originated from a dev config. What is the dev-environment
  secret handling story?
- Is the Postgres instance network-isolated from the public internet?
  If not, this is an elevated-risk residual — document as accepted or fix.
- What is the 90-day rotation cadence compliance rate? Is it automated or
  manual?

---

#### Scenario 5 — DDoS Against Scan Endpoint

**Narrative:**
At peak business hours, `/api/v1/prompt/scan` starts receiving 50,000
requests per minute from ~200 distinct IPs (L7 DDoS, all requests are
valid JWTs from compromised service accounts). The per-key token bucket
limiter is firing, but the burst traffic is exhausting the goroutine pool.
API latency spikes to 45 seconds; the `/livez` probe starts failing;
the load balancer begins marking pods unhealthy.

**Detection signals**
- Prometheus: `vertguard_http_requests_total{endpoint="/api/v1/prompt/scan"}` > SLA threshold.
- `vertguard_ratelimit_rejected_total` spikes — limiter is working but
  the volume of rejected requests itself adds overhead.
- `vertguard_circuit_breaker_state{target="citadel"}` → `open` (CITADEL
  calls are timing out under load).
- Kubernetes pod liveness probe failures; HPA scaling but not fast enough.
- CITADEL async buffer: `dropped_buffer_full` metric increments.

**Immediate actions (first 15 minutes)**
1. Identify the attacking source IPs / JWT subjects. The audit log records
   `actor_ip` and `actor_sub` — pull the top-N subjects by request count.
2. Add the attacking JWT subjects to the denylist:
   `POST /api/v1/admin/denylist` with `kind=sub` for each.
   Set `burst=0` per-subject overrides via `POST /api/v1/admin/ratelimit/overrides`.
3. If attacks are coming from specific IPs, escalate to upstream WAF /
   cloud DDoS mitigation (this is out of VertGuard's direct control —
   `threat-model.md § 4.1 DoS` residual: "L7 DDoS still requires upstream WAF").
4. Scale the API horizontally: `kubectl scale deployment vertguard --replicas=10`
   or trigger HPA by patching `autoscaling.minReplicas`.

**Discussion questions — immediate phase**
- Do we have the upstream WAF / CDN contact details readily available?
  Is there an SLA on response time for blocking rules?
- Is the HPA scale-up fast enough to absorb the burst, or do we need a
  pre-provisioned warm pool?
- How many compromised service accounts are involved? Is this a credential
  leak scenario nested inside the DDoS?

**Containment (15–60 minutes)**
1. Confirm the circuit breaker has opened on CITADEL: this is expected and
   correct. The async buffer should be absorbing WORM emits; monitor
   `dropped_buffer_full` to confirm nothing critical is lost.
2. Enable aggressive rate-limiting globally by reducing `ratelimit.default_rps`
   in the Helm values and rolling it out:
   `helm upgrade vertguard ... --set config.ratelimit.default_rps=5`
3. Review whether the attacking JWT subjects correspond to real service
   accounts that should be revoked at the IdP level, not just the denylist.
4. Monitor `vertguard_goroutines` and memory metrics — if the pod is
   accumulating goroutines, a graceful restart under load is preferable to
   an OOM kill.

**Eradication and recovery**
1. Once attack traffic subsides, restore normal rate limits and remove
   temporary denylist entries that were legitimate accounts caught in the
   blast.
2. Rotate any JWT secrets associated with the compromised service accounts.
3. Review what rate limit is appropriate for scan endpoints per service
   account — the current 5-role coarse RBAC may need per-tenant quotas.
4. Document the upstream WAF escalation path in `docs/operator-runbook.md`.
5. File a post-mortem if any CITADEL events were dropped (`dropped_buffer_full`
   was non-zero). WORM coverage was incomplete during the incident.

**Post-incident review questions**
- Was the per-key token bucket granular enough? Should we gate scan
  endpoints at a lower RPS than admin endpoints?
- Does the runbook have the upstream WAF vendor's emergency contact?
  (`docs/operator-runbook.md § 5` — check and add if missing.)
- Should `networkPolicy.enabled` default to `true` to provide an additional
  layer of IP-range filtering even before the L7 rate limiter?
- Is the async CITADEL buffer large enough (default 1024) for sustained
  high-traffic legitimate use, or should it be increased to reduce
  `dropped_buffer_full` events during legitimate spikes?

---

### 5. Action items template

Facilitator records gaps found during the session. Copy into GitHub Issues
within 24 hours; label `tabletop`, `security`, and the relevant severity.

| # | Scenario | Gap found | Owner | GitHub Issue | Due |
|---|---|---|---|---|---|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |
| 4 | | | | | |
| 5 | | | | | |

---

### 6. Post-exercise checklist

After the session, the facilitator ensures:

- [ ] All action items have been transferred to GitHub Issues with `tabletop` label.
- [ ] `docs/security/pre-audit-plan.md § 3` checkbox "Operator runbook walked
      through in tabletop" is ticked.
- [ ] `docs/security/threat-model.md § 8` "Review cadence" entry is updated
      with the exercise date.
- [ ] The next exercise date is agreed and calendar invites are sent.
- [ ] Any runbook gaps found are fixed in `docs/operator-runbook.md` before
      the next exercise.

---

### 7. Related documents

- `docs/operator-runbook.md` — 10 operational playbooks
- `docs/security/threat-model.md` — STRIDE analysis and attack trees
- `docs/security/security-checklist.md` — control evidence matrix
- `docs/security/pre-audit-plan.md` — audit timeline and gap closure log
- `docs/security/disclosure.md` — researcher-facing coordinated disclosure terms
- `SECURITY.md` — public security policy and PGP contact
