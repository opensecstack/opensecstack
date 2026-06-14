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

### AUGUR rule set is small

**Status:** three rules in v1.0.0 — off-hours, high-frequency,
DATA_EXPORT without incident. See [augur.md](./augur.md).

**Impact:** behavioural attacks outside these patterns are not
caught. Specifically: geographic anomalies, rare-action-type
detection, cross-actor collusion patterns, time-of-week patterns.

**Roadmap:** rule_04 (geographic) and rule_05 (rare action) in v1.2;
a rule-plugin system in v2.0.

### Gate 3 depends on correct role-group config

**Status:** Gate 3 uses `sessions.role_group` to compare operator and
verifier. If role groups are all `"unknown"` (default for unconfigured
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
