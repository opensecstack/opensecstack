# Known Limitations

CITADEL v1.0.0 is production-capable for the deployments described in
[../../docs/security-maturity.md](../../docs/security-maturity.md),
but it is not everything it will eventually be. This document is the
honest inventory of what CITADEL does **not** yet do, so operators
can plan around the gaps and contributors know where the work is.

Sorted by severity: chain-impacting first, convenience last.

## Chain & cryptography

### Single-writer WORM chain

**Status:** v1.0.0 ships single-writer only. Horizontal scale is
active/passive (Consul leader lock or Kubernetes Lease); multi-writer
with sharded chains per `project_id` is a v2.0 feature.

**Impact:** write throughput scales vertically, not horizontally. A
large deployment (tens of millions of Kerkeses/day) may saturate one
Postgres instance. For most deployments the 200-300 appends/sec
ceiling is adequate.

**Workaround:** run a second CITADEL instance for a logically-separate
project_id with its own DB — you get two isolated chains that cannot
cross-reference but each scale to the per-instance ceiling.

### Anchor signatures not verified in `VerifyChain`

**Status:** `worm/verify` returns `AnchorVerified: false` in v1.0.0
when the anchor verification step is not yet wired into the verifier.
The linear chain walk (TripleHash + chain_hash + continuity) is what
guarantees integrity today.

**Impact:** tamper-*evidence* is intact, but tamper-*resistance*
against a DB-level attacker who can also rewrite chain_hashes is not
enforced at verification time. Anchor signatures are produced and
stored correctly — they just aren't cross-checked in the verify
endpoint.

**Roadmap:** v1.1 lands the in-API anchor verification; auditors today
run the check independently per [auditor-walkthrough.md § Step 3](./auditor-walkthrough.md#step-3--anchor-signatures).

### Anchor key lives in memory

**Status:** the Ed25519 master key is loaded from the config into
CITADEL's process memory and used there. HSM / KMS / PKCS#11 support
is planned for v2.0.

**Impact:** a process-memory attacker (debugger attach, core dump
exfil, compromised library) can read the key.

**Mitigation:** strict OS hardening (no ptrace, no core dumps in
prod), fast key rotation (quarterly), monitored secret-manager access.

## MARSHAL gates

### `rbacMap`/`roleGroupMap` coverage gap (Gate 2)

**Status:** `rbacMap`/`roleGroupMap` (`internal/marshal/types.go`)
currently define exactly 5 roles (`admin`, `operator`, `analyst`,
`viewer`, `auditor`) and exactly 10 action types (`API_SCAN_INITIATE`,
`API_SCAN_DELETE`, `INCIDENT_CREATE`, `INCIDENT_CLOSE`, `DATA_EXPORT`,
`CONFIG_CHANGE`, `USER_CREATE`, `USER_DELETE`, `PLAYBOOK_EXECUTE`,
`IOC_INGEST`). This is disclosed in the IEEE paper's limitations
section ("Gate 2/Gate 3 policy-map coverage"). 9 producer platforms
(apiguard, nis2compass, irflow, threatflow, openscrub, cyberpath,
securelab, opencsirt, vertguard) are wired with CITADEL clients today;
their actual `action.type`/`actor.role` strings were audited against
the map above (2026-08) and the result is **not** "some new platforms
aren't onboarded yet" — it is that most of the action-type strings
*already flowing in production* do not match the map's uppercase,
snake-free vocabulary at all, for several independent reasons (case
mismatch, an undocumented `group_sig_operator`/`group_sig_verifier`
role convention several platforms share, and action types the map
simply has no entry for). Exact findings, per platform:

| Platform | Real `action.type` sent | Real `actor.role` sent | In `rbacMap`? | Outcome at Gate 2 today |
|---|---|---|---|---|
| **apiguard** | `deploy_change` (scan initiation, `internal/api/handlers/scans.go`) | `group_sig_operator` | Neither the type nor the role exists in the map | **REFUSE**, unconditionally |
| **openscrub** | `deploy_change` (manual mitigation-rule creation, `internal/api/handlers/handlers.go`) | `group_sig_operator` | Neither the type nor the role exists in the map | **REFUSE**, unconditionally |
| **irflow** | Operator-supplied free text (e.g. `CONTAIN`/`contain`, `create_incident` — see [../../irflow/docs/governance-integration.md](../../irflow/docs/governance-integration.md)); no fixed enum | `admin`, `operator`, `verifier`, `viewer`, `service` (IRFlow's own 5-role model) | `verifier` and `service` are not keys in `rbacMap` or `roleGroupMap` at all; even `operator` + `CONTAIN` fails because `CONTAIN` isn't in `operator`'s allow-list, and lowercase `create_incident` doesn't string-match `INCIDENT_CREATE` | **REFUSE** for effectively every real IRFlow governed action; `verifier`/`service` additionally fall back to Gate 3's `roleGroup() == "unknown"` path (see below) |
| **threatflow** | `IOC_INGEST` (ingest), `STIX_BUNDLE_IMPORT`, `FEED_CREATE`, `FEED_TOGGLE`, `FEED_DELETE` (see [../../threatflow/docs/citadel-integration.md](../../threatflow/docs/citadel-integration.md)); `IOC_REVOKE` reserved but unwired | actor's real role | Only `IOC_INGEST` is in the map | `IOC_INGEST` **PASSes** (if actor role is `admin`/`operator`/`analyst`); the other 4 live, gated mutations **REFUSE** unconditionally |
| **opencsirt** | `ADVISORY_PUBLISH`, `INCIDENT_CLOSE` (self-documented gap in [../../opencsirt/docs/citadel-integration.md](../../opencsirt/docs/citadel-integration.md)) | `csirt_lead`, `operator` (its real roles); rbacMap only permits `admin` for `INCIDENT_CLOSE` | `ADVISORY_PUBLISH` not in the map at all; `INCIDENT_CLOSE` is in the map but only for `admin` | **REFUSE** for both, for any actor role OpenCSIRT actually uses |
| **cyberpath** | `CONFIG_CHANGE` (certification revocation only — issuance is not MARSHAL-gated) | `admin` | Yes — both the type and role match | **PASS** — this is the one governed call in the ecosystem today that is genuinely, correctly evaluated, not just refused-by-default |
| **nis2compass** | `ASSESSMENT_LOCK`, `ASSESSMENT_UNLOCK`, `ARTIFACT_SIGN` | actor's real role | None of the three types exist in the map | **REFUSE**, unconditionally, for all three |
| **securelab** | *(none — no `marshal/evaluate` call exists in the codebase; `securelab.run_completed` is a WORM-only audit append)* | — | N/A | Not gated at all — Gate 2 is never invoked for SecureLab |
| **vertguard** | *(none — no MARSHAL client, no Kerkese construction anywhere; see [../../vertguard/docs/citadel-integration.md](../../vertguard/docs/citadel-integration.md))* | — | N/A | Not gated at all — VertGuard's only CITADEL touchpoint is best-effort WORM evidence emission |

**Bottom line:** of the 9 wired platforms, only **cyberpath's
certification-revocation call** currently receives genuine,
intended Gate 2 evaluation. Two platforms (securelab, vertguard) never
call `evaluate()` at all — their CITADEL integration is WORM-only, so
Gate 2 coverage is not applicable to them. The remaining six
(apiguard, openscrub, irflow, threatflow, opencsirt, nis2compass) do
call `evaluate()` with real actor identities, but nearly all of their
real action types and/or roles are absent from `rbacMap`/
`roleGroupMap`, so those calls `REFUSE` at Gate 2 today — not because
the underlying action is unauthorized, but because CITADEL's policy
vocabulary was never extended to recognize the caller's action type or
role in the first place. Do not read "Gate 2 REFUSE" in these
platforms' logs as evidence of an attempted unauthorized action.

A second, independent gap the table surfaces: at least three platforms
(apiguard, openscrub, and community's GDPR-deletion flow) send
`group_sig_operator`/`group_sig_verifier` as `actor.role`/
`verifier.role` — a role-naming convention `rbacMap` and
`roleGroupMap` have no entries for at all, distinct from IRFlow's
separate `verifier`/`service` role gap above. Extending the map is not
a matter of adding one or two platforms' vocabularies; at least three
incompatible role-naming conventions are in live use simultaneously
(`admin`/`operator`/`analyst`/`viewer`/`auditor` the map itself uses,
IRFlow's `admin`/`operator`/`verifier`/`viewer`/`service`, and the
`group_sig_operator`/`group_sig_verifier` pair several platforms
share).

**Impact:** most real `evaluate()` calls whose `action.type` or
`actor.role` isn't in these maps currently `REFUSE` at Gate 2 (AuthZ),
which is a hard, unconditional check with no soft mode.

**Mitigation status:** a Permify-based mitigation now exists in
soft-launch form — Gate 2 also runs an optional check against a
periodically-refreshed local snapshot of Permify-derived role→action
policy (`internal/permifysync`, `EnforcePermifyAuthz` default
`false`). This does **not** yet close the gap: the synced snapshot is
currently expected to be empty, since sinauth's Permify schema doesn't
yet model CITADEL's action-type vocabulary. `rbacMap` remains the
permanent, unconditionally-enforced safety net either way. See
[ADR-007](../adrs/007-permify-gate2-snapshot.md).

**Roadmap:** extend the policy maps (and/or the Permify schema), or
move to a project-scoped, database-backed policy table, as each
additional platform's action vocabulary is onboarded to Gate 2/Gate 3.
This requires cross-platform coordination on the actual action-type
strings and role names each platform will send — deciding those
values here, without that coordination, risks either an
overly-permissive rule (a real security hole) or a rule that still
doesn't match what platforms actually send (still broken). Out of
scope for this documentation pass.

### `enforce_identity` / `enforce_signatures` default to `false` ("soft enforcement")

**Status:** both `CITADEL_CITADEL_ENFORCE_IDENTITY` and
`CITADEL_CITADEL_ENFORCE_SIGNATURES` default to `false`. In this
default configuration:

- Gate 1 (AuthN, on the Actor) and Gate 3 (NDS, on the Verifier) still
  **run** the sinauth bearer-token check and the Ed25519
  operator/verifier signature check on every Kerkese, and the outcome
  of each check (pass/fail/absent) is **recorded** in the Decision's
  `gates[]` array and persisted to the WORM chain — this part is
  unconditional and not affected by the flags.
- What the flags control is whether a *failing* identity/signature
  check actually blocks the decision. With both flags `false` (the
  shipped default), a missing, invalid, or mismatched `actor_token`/
  `verifier_token`/`sig_operator`/`sig_verifier` produces a `WARN` in
  `gates[]`, not a `REFUSE`/`HARD_STOP` — the request proceeds to the
  remaining gates as if identity/signature had passed.
- The gates that are genuinely hard, unconditional stops regardless of
  these flags are: Gate 2's `rbacMap` check (see above), Gate 3's
  operator≠verifier / different-role-group check (`NDS_SAME_IDENTITY`
  is a `HARD_STOP` even in soft mode), and Gate 4's three AUGUR rules.

**In practice, today:** because 6 of the 9 wired platforms mostly
`REFUSE` at Gate 2 before identity/signature enforcement would even
matter (see the table above), and the 2 platforms that never call
`evaluate()` (securelab, vertguard) never reach Gate 1/Gate 3 either,
the soft-enforcement behavior described here is currently most visible
in cyberpath's certification-revocation flow — the one call that
clears Gate 2 — where a missing `verifier_token`/`sig_verifier`
(cyberpath uses a fixed placeholder Verifier with no real second
approver, same pattern apiguard/openscrub use for their own REFUSEd
calls — see `cyberpath/docs/citadel-integration.md`) is logged as a
`WARN` and does not block the revocation.

**Why this matters for a production deployment decision:** a
deployer evaluating CITADEL by reading only the marketing/architecture
description ("every action flows through 5 gates") would reasonably
assume identity and signature checks are enforced. They are not, by
default, and turning them on today (`enforce_identity=true` and/or
`enforce_signatures=true`) would immediately `REFUSE` cyberpath's
certification-revocation flow too — the one governed call that
currently works — because none of the 9 platforms send a real,
independently-authenticated second-approver signature yet. See
[ADR-006](../adrs/006-split-enforce-identity-and-signatures.md) for
what has to be true (a genuine two-person-rule UI/flow on the producer
side) before either flag can be safely flipped.

**Roadmap:** flip each flag per-deployment once producer platforms
implement genuine second-approver flows; no CITADEL-side code change
required to turn them on, only operational readiness on the caller
side.

### AUGUR rule set is small

**Status:** three rules in v1.0.0 — off-hours, high-frequency,
DATA_EXPORT without incident. See [augur.md](./augur.md).

**Impact:** behavioural attacks outside these patterns are not
caught. Specifically: geographic anomalies, rare-action-type
detection, cross-actor collusion patterns, time-of-week patterns.

**Roadmap:** rule_04 (geographic) and rule_05 (rare action) in v1.2;
a rule-plugin system in v2.0.

### Gate 3 depends on correct role-group config

**Status:** Gate 3 derives role groups from the producer-asserted
`Actor.Role`/`Verifier.Role` on the Kerkese (not a local session
table — see [ADR-005](../adrs/005-sinauth-identity-bridge.md)). If
role groups are all `"unknown"` (default for unconfigured
deployments), Gate 3 falls back to same-identity check only.

**Impact:** on a misconfigured deployment, two operators with
different user_ids but semantically-same roles can pass Gate 3.

**Mitigation:** startup WARN log when role groups are empty; monthly
operator check ([operator-runbook.md § Monthly](./operator-runbook.md#monthly)).

### No dual-verifier rule

**Status:** Gate 3 requires exactly two distinct identities. Some
deployments want *three* — e.g. for wire-transfer authorisation
or nuclear-launch-style controls.

**Impact:** ecosystem cannot express "this action needs three
signatures".

**Roadmap:** v1.2 — configurable `n_of_m` schemes per action type.

## Operational

### No built-in identity provider

**Status:** CITADEL verifies JWTs signed with a shared secret.
Issuance is delegated to upstream IdPs.

**Impact:** deployers must run their own IdP (Keycloak, Auth0,
Okta, etc.) — CITADEL is not a turn-key solution for identity.

**Rationale:** IdPs are a mature market. Re-implementing badly would
be strictly worse than consuming.

### No overlapping-secret support for HMAC rotation

**Status:** HMAC secrets (used by downstream callers to sign their
Kerkeses) can only be rotated during a maintenance window. CITADEL
accepts exactly one secret at a time per caller.

**Impact:** rotation requires a coordinated cut-over. A window of
~30 seconds where old-secret signatures are rejected and new-secret
signatures are accepted.

**Roadmap:** v1.1 — accept N = old + new secrets concurrently for a
grace window.

### No Prometheus metrics exposed

**Status:** internal metrics exist (benchmarks prove this) but
`/metrics` is not exposed in v1.0.0.

**Impact:** operators must rely on log scraping and periodic API
polls for observability. Can't set Prometheus alerts on gate
outcomes.

**Roadmap:** v1.1 — full `/metrics` catalogue matching the pattern
of IRFlow and NIS2 Compass.

### No streaming chain verification

**Status:** `/worm/verify` over a large range buffers all entries in
memory before walking them.

**Impact:** verifying > ~100 k entries in a single call can consume
multi-GB of RAM.

**Workaround:** chunk the verification range client-side (e.g. one
day at a time).

**Roadmap:** v1.1 — streaming response body with incremental verify
state.

### No archival tier

**Status:** entries stay in Postgres forever.

**Impact:** cost scales linearly with retention. A decade of
evidence at 10 events/sec ≈ 3 TB of Postgres — workable but not
cost-optimal.

**Roadmap:** v2.0 — cold-tier to S3/equivalent with an on-demand
restore path. Anchors cover the boundary.

## VIGIL (planned feature)

### VIGIL does not exist in code

**Status:** documented in [vigil.md](./vigil.md) as a planned v2.0
feature. ARCHITECTURE.md references it as part of CITADEL's mission,
but no code implements it.

**Impact:** cross-platform health aggregation requires manual work
from Grafana dashboards today.

**Roadmap:** scrape infrastructure v1.1, colour logic v1.2, MARSHAL
integration v2.0.

## Testing & CI

### No fuzz testing

**Status:** unit tests cover the hash + chain math. No fuzz testing
of the Kerkese JSON parser or the API handlers.

**Impact:** a malformed Kerkese could hit a panic not observed in
tests. Not an integrity concern but an availability concern.

**Roadmap:** v1.1 — `go fuzz` harness on the API input path.

### Benchmark coverage is narrow

**Status:** benchmarks exist for TripleHash, chain step, WORM append,
MARSHAL evaluate. End-to-end latency benchmarks (HTTP → Evaluate →
chain return) are missing.

**Impact:** future regressions in non-hot-path code could sneak in.

**Roadmap:** v1.1 — full-stack bench suite invoked in CI.

## ERP layer

### ERP layer does not exist yet

**Status:** CITADEL is a Go service today. The planned ERP module
(see [ROADMAP.md § v1.2](../ROADMAP.md#v12--erp-layer-after-v11)) —
inspired by Odoo but not based on the Odoo framework — is not yet
started.

**Impact:** audit workflows that would benefit from a case-management
UI (reviewing pending appeals, submitting bulk evidence requests) are
driven by raw API calls today.

**Roadmap:** v1.2. Docs in [operator-runbook.md § ERP layer](./operator-runbook.md)
will expand when the layer lands.

## Non-goals

Some things that *could* be added but deliberately won't:

- **Dynamic gate reordering.** The 5 gates evaluate in a fixed order.
  Changing the order changes the semantics in ways downstream
  platforms cannot safely absorb.
- **Mutable WORM.** "Redaction" is always a compensating entry, never
  a delete. This is fundamental.
- **Integrated dashboards.** CITADEL produces evidence; visualisation
  is an orthogonal concern. Grafana + per-platform dashboards cover it.
- **Self-issued JWTs.** IdPs exist. Re-implementing badly is worse
  than consuming.

## How to contribute

If a limitation here matters to your deployment:

1. Open a GitHub issue with the `limitation` label.
2. If you are planning an implementation, draft an RFC under
   [../../rfcs/](../../rfcs/) before writing code — the governance
   surface is too load-bearing for PRs-first design.
3. Expect review cycles; the CITADEL maintainers are conservative
   about changes that affect decision semantics or chain format.

## Related

- [ROADMAP.md](../ROADMAP.md) — planned remediations
- [SECURITY.md](../SECURITY.md) — threat model this list is gapped against
- [../../docs/security-maturity.md](../../docs/security-maturity.md) — deployment tiers appropriate for v1.0.0
