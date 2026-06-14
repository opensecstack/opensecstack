# OpenCSIRT Pre-Audit Plan

> Timeline, owners, and gap-closure plan for engaging an external
> security audit firm against OpenCSIRT v1.0.0. Reads top-to-bottom
> in execution order. Mirrors the structure of
> [../../../openscrub/docs/security/pre-audit-plan.md](../../../openscrub/docs/security/pre-audit-plan.md);
> the gaps differ because the load-bearing surface differs (kernel
> there, federated CSIRT trust + TLP confidentiality here).
>
> The plan is anchored on **three priority gaps** — G1, G2, G3 —
> that must close before kick-off.

## 1. Priority gaps to close before kick-off

### G1 — Privilege-escalation tests for the 6-role hierarchy

**Why:** OpenCSIRT defines six roles —
`viewer · external_peer · analyst · operator · csirt_lead · admin`
— with a strict rank order in
[`internal/auth/auth.go`](../../internal/auth/auth.go) (the
`rank map[Role]int` table). Every privileged endpoint gates on
`auth.RequireRole(min Role)`. The single most damaging non-leak
finding here is a **role bypass** — for example, an `analyst`
publishing an advisory, or an `external_peer` reading TLP:AMBER
content. The integration test proves the controls hold end-to-end
across the API surface.

| Field | Value |
|---|---|
| Owner | API maintainer |
| Target date | T-21d |
| Current status | **Partial.** [`internal/auth/auth_test.go`](../../internal/auth/auth_test.go) covers the unit-level role rank table and `Verify` round-trip. End-to-end matrix tests against the running API are not yet present. |
| Exit criteria | (a) Integration test seeds users at every role; (b) for every privileged endpoint exposed in `api/openapi.yaml`, the test confirms each role's expected 200/403; (c) explicit assertion that `analyst` cannot `POST /api/v1/advisories/{id}/publish` (`csirt_lead+` only); (d) explicit assertion that `external_peer` cannot list TLP:AMBER/RED advisories; (e) test runs in CI on PR and on push to `main`. |
| Closing test path | `tests/integration/auth_role_matrix_test.go` (Go, build tag `//go:build integration`) |
| CI job | New `integration-auth-roles` job in `.github/workflows/ci.yml` |

### G2 — HMAC verification fuzz harness for the IRFlow webhook

**Why:** The IRFlow webhook is the largest inbound surface that
accepts adversary-controlled bytes. The signing scheme
(`ts || "." || body`, HMAC-SHA256, ±5-min replay window) has
several edge cases an attacker would probe:

- replay-window boundary off-by-one (4:59 vs 5:01),
- timing leak in `hmac.Equal` (already mitigated; need a
  regression),
- malformed timestamp shapes that should fail closed,
- truncated/over-padded hex signatures,
- Unicode in `X-Timestamp`,
- empty body with valid signature.

Any one of these accepting a forged message is a spoofing primitive
that creates incidents at will (threat-model row [S1.*](threat-model.md)).

| Field | Value |
|---|---|
| Owner | Go API maintainer |
| Target date | T-21d |
| Current status | **Partial.** [`internal/integrations/webhook_hmac_test.go`](../../internal/integrations/webhook_hmac_test.go) covers the canonical sign/verify happy path and a few replay-window cases. No `Fuzz*` target exists yet. |
| Exit criteria | (a) `go test -fuzz=FuzzVerifyHMAC -fuzztime=1h` runs on `internal/integrations/` without a crash or false accept; (b) seed corpus includes ≥ 50 examples — valid + invalid + adversarial (boundary timestamps at ±5min ±1s, hex with leading whitespace, mixed-case hex, Unicode in `X-Timestamp`, empty body, body > 1 MiB); (c) any false-accepts are fixed and the offending input added to the seed corpus |
| Closing test paths | `internal/integrations/fuzz_test.go` (`FuzzVerifyHMAC`, `FuzzIRFlowWebhook`); seed corpus under `internal/integrations/testdata/fuzz/` |
| CI job | New `fuzz-webhook-hmac` job in `.github/workflows/ci.yml` (120s on PR; 1h nightly cron) |

### G3 — TLP-leak tests

**Why:** The Traffic Light Protocol classifies advisories as
`CLEAR | GREEN | AMBER | RED`. The `peer_csirts` table records
each peer; the `advisories.tlp` column records the classification.
A misrouted TLP:RED advisory to a TLP:CLEAR-only peer is the
highest-tier finding OpenCSIRT can produce — equivalent in
severity to a kernel-tier finding in OpenScrub.

The runtime guard in the escalation handler must refuse the
combination, and the test must prove it across every (advisory.tlp,
peer.tlp_max) pair.

| Field | Value |
|---|---|
| Owner | API maintainer (federation) |
| Target date | T-14d |
| Current status | **Not started.** No TLP-leak test exists. The runtime guard is partially implemented (the escalation handler reads `peer.tlp_max` but does not yet refuse on mismatch in v1.0.0). |
| Exit criteria | (a) Integration test seeds advisories at every TLP level and peers at every `tlp_max`; (b) for every (advisory.tlp, peer.tlp_max) pair the test asserts allow / refuse per the matrix below; (c) refuse path also asserts an `audit_log` row with `action='escalation_blocked_tlp'`; (d) the runtime guard is shipped as part of v1.0.0 (or v1.0.1 if the gap closes after release) |
| Closing test path | `tests/integration/tlp_leak_test.go` |
| CI job | extends `integration-auth-roles` to gate on TLP matrix |

The TLP routing matrix:

| advisory.tlp ↓ \\ peer.tlp_max → | CLEAR | GREEN | AMBER | RED |
|---|:-:|:-:|:-:|:-:|
| CLEAR | allow | allow | allow | allow |
| GREEN | refuse | allow | allow | allow |
| AMBER | refuse | refuse | allow | allow |
| RED | refuse | refuse | refuse | allow |

## 2. Timeline

| Milestone | Date offset | Owner | Output |
|---|---|---|---|
| T-8 weeks | Contract signed | Engineering lead + procurement | SOW signed; [pentest-scope.md](pentest-scope.md) shared with firm |
| T-6 weeks | Gap-closure freeze | Maintainer rota | All gaps in [security-checklist.md](security-checklist.md) resolved or formally accepted |
| T-21d | **G1 closes** | API maintainer | Role-matrix integration test green |
| T-21d | **G2 closes** | Go API maintainer | HMAC fuzz harness clean |
| T-14d | **G3 closes** | API maintainer | TLP-leak matrix test green; runtime guard shipped |
| T-4 weeks | Clean instance ready | DevOps | Dedicated cluster / namespace; secrets rotated; auditor JWTs minted |
| T-3 weeks | Tooling sanity | Engineering | `gosec`, `govulncheck`, `staticcheck`, `pip-audit`, `npm audit`, `eslint`, `semgrep` all pass |
| T-2 weeks | Internal red-team dry-run | Maintainer rota | Rehearsal of attack-surface paths from [threat-model.md](threat-model.md) |
| T-1 week | Documentation handoff | Maintainer | Auditor receives `docs/security/` snapshot, OpenAPI, Helm chart, SBOMs, image digests |
| T-0 | Kick-off call | All | Scope walkthrough, credentials handoff |
| T+0 → T+2 | Engagement window | Auditor | 2-week box per [pentest-scope.md § 5](pentest-scope.md) |
| T+3 | Draft report | Auditor | Findings on private channel |
| T+4 weeks | Final report | Auditor | PDF + JSON; CVSS scored |
| T+5 | Triage + ticketing | Engineering | Each finding → GitHub issue |
| T+6-8 weeks | Remediation merged | Engineering | Critical + High closed; Medium ≥ 80% closed |
| T+10 weeks | Retest | Auditor | Reopen-or-close each finding; addendum |

## 3. Responsibilities

| Role | Responsibility |
|---|---|
| Engineering lead | Owns the engagement end-to-end; signs SOW |
| API maintainer | G1, G3; auth + federation ownership |
| Go API maintainer | G2; OpenAPI surface stability |
| Python advisory maintainer | abuse-mailbox parser review on every PR (CODEOWNERS) |
| DevOps | Test environment, credentials, cluster lifecycle |
| Procurement / legal | Contract, NDA, DPA |
| Auditor | Test execution, finding write-up, retest, replay scripts |

## 4. Pre-engagement checklist

Mark each item before T-1 week:

- [ ] G1 role-matrix integration test green in CI
- [ ] G2 HMAC fuzz harness — 1h fuzz runs clean; seed corpus committed
- [ ] G3 TLP-leak matrix test green; runtime guard shipped
- [ ] All other [security-checklist.md](security-checklist.md) gaps closed or accepted
- [ ] `gosec`, `govulncheck`, `staticcheck` clean on `main`
- [ ] `pip-audit` clean on the Python advisory subsystem
- [ ] `npm audit --audit-level=moderate` clean on `web/`
- [ ] `semgrep` clean (especially the `no raw sql` rule)
- [ ] Image SBOM published with the audit-target tag (CycloneDX, `cosign attest`)
- [ ] Cosign signature on every audit-target image
- [ ] Threat model reviewed in last 90 days
- [ ] Operator runbook walked through in tabletop including
      TLP:RED leak detection and CITADEL outbox saturation
- [ ] Dedicated test cluster up; namespaces isolated
- [ ] Auditor JWT mint script tested against the test cluster
- [ ] PGP key for `security@opensecstack.org` issued and published

## 5. Auditor scheduling status

**Pending engagement, prerequisites complete.** v1.0.0 ships
2026-05-10 with the documentation set required for SOW negotiation
([pentest-scope.md](pentest-scope.md), this plan,
[security-checklist.md](security-checklist.md), and
[threat-model.md](threat-model.md)). Recommended firm tier:
mid-size with web-app + Python application audit experience and
prior CSIRT-platform exposure (FIRST.org member firms preferred).

## 6. Out-of-scope cost reminders

These are explicitly **not** part of a typical pentest engagement
and need separate funding lines:

- Public bug bounty programme (post-v1.0).
- Continuous DAST against `:8088`.
- Hardware HSM procurement for the certification path.

## 7. Success criteria

The engagement is considered successful when:

1. Zero Critical findings remain open at T+10.
2. Zero TLP:RED-leak findings remain open at T+10.
3. All High findings have a merged fix or accepted-with-rationale on
   file at T+10.
4. Auditor produces a one-page executive summary suitable for
   sharing with NIS2-scope deployers under NDA.
5. Public disclosure (if any) is coordinated and on time.
6. Retrospective updates [threat-model.md](threat-model.md) and
   [security-checklist.md](security-checklist.md).

## 8. Gap-closure log

| Gap | Status | Closing artefact |
|---|---|---|
| G1 — role-matrix integration test | **Open** (target: `tests/integration/auth_role_matrix_test.go`); partially covered by [`internal/auth/auth_test.go`](../../internal/auth/auth_test.go) |
| G2 — HMAC fuzz harness | **Open** (target: `internal/integrations/fuzz_test.go`); partially covered by [`internal/integrations/webhook_hmac_test.go`](../../internal/integrations/webhook_hmac_test.go) |
| G3 — TLP-leak tests | **Open** (target: `tests/integration/tlp_leak_test.go`); runtime guard not yet implemented |

## 9. Related

- [security-checklist.md](security-checklist.md) — control evidence
- [pentest-scope.md](pentest-scope.md) — what we hand the auditor
- [threat-model.md](threat-model.md) — the surfaces the dry-run rehearses
- [compliance-map.md](compliance-map.md) — framework traceability
- [../../SECURITY.md](../../SECURITY.md) — disclosure tiers
- [../../../openscrub/docs/security/pre-audit-plan.md](../../../openscrub/docs/security/pre-audit-plan.md) — sibling plan
