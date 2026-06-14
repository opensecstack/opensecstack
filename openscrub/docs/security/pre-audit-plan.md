# OpenScrub Pre-Audit Plan

> Timeline, owners, and gap-closure plan for engaging an external
> security audit firm against OpenScrub v1.0.0. Reads top-to-bottom
> in execution order. Mirrors the structure of
> cyberpath/docs/security/pre-audit-plan.md (see `cyberpath/docs/security/pre-audit-plan.md`);
> the gaps differ because the load-bearing surface differs (Wasm
> sandbox there, kernel/BPF here).
>
> The plan is anchored on **three priority gaps** — G1, G2, G3 —
> that must close before kick-off. Everything else in
> [security-checklist.md](security-checklist.md) either ships with
> v1.0.0 by default or is formally accepted as a v1.1+ roadmap item.

## 1. Priority gaps to close before kick-off

### G1 — Sandbox-escape / kernel-escape integration tests for the BPF data plane

**Why:** A kernel-tier escape from the loader pod or a BPF
verifier-bypass leading to host kernel write is the highest-severity
finding OpenScrub can produce (Critical, kernel tier — see
[threat-model.md § High-tier kernel surface](threat-model.md)). An
auditor's first question is "what attempts at escape have you already
caught yourself?" — without a published negative-test corpus, the
engagement starts cold.

| Field | Value |
|---|---|
| Owner | Data-plane maintainer |
| Target date | T-30d (30 days before pentest kick-off) |
| Current status | **Partial.** [`rust/dataplane/tests/integration.rs`](../../rust/dataplane/tests/integration.rs) covers the happy path: map round-trip (v4 + v6), rate-limit overwrite semantics, snapshot independence, stats reader default, and a `#[ignore]`-gated live-kernel `attach_to_loopback` test. Negative tests for adversarial input are missing. |
| Exit criteria | (a) ≥ 20 negative tests covering: load-with-malformed-program (verifier should reject), map-overflow (LPM trie oversized prefix list, ratelimit map at capacity), control-socket fuzzed payloads, ABI-mismatch on map open, prefix-shorter-than-`/8` poisoning attempt; (b) every threat-model row #1, #2, #4, #5 has at least one regression test; (c) `make test-dataplane` passes in CI; (d) live-kernel suite (`sudo cargo test -- --ignored`) passes on kernel matrix 5.15 / 6.1 / 6.6 |
| Closing test path | New file `rust/dataplane/tests/escape_attempts.rs` (Rust integration tests with the negative cases) + `rust/dataplane/fuzz/fuzz_targets/control_proto.rs` (cargo-fuzz seed corpus for the Unix-socket control protocol). Existing [`rust/dataplane/tests/integration.rs`](../../rust/dataplane/tests/integration.rs) keeps the happy-path tests. |
| CI job | New `dataplane-escape-tests` job in `.github/workflows/ci.yml` running on the kernel matrix. Existing `cargo test` job keeps its scope. |

### G2 — Fuzz harness for rule input parser

**Why:** Three input parsers in OpenScrub take untrusted bytes:
(a) the CIDR parser in [`internal/rules/`](../../internal/rules/) on
the `POST /rules` path, (b) the JSON request decoder for the same,
and (c) the STIX 2.1 IOC bundle decoder in
[`internal/ioc/puller.go`](../../internal/ioc/puller.go) on the
ThreatFlow path. Any one of them crashing or accepting a malformed
input that bypasses validation is a privilege-escalation primitive
(rule poisoning → blackhole, threat-model row #2; IOC source
compromise, threat-model row #3).

| Field | Value |
|---|---|
| Owner | Go API maintainer |
| Target date | T-21d |
| Current status | **Not started.** Unit tests exist (`rule_test.go`, `service_test.go`, `puller_test.go`) but no `Fuzz*` targets. The puller already enforces a 16-MiB read cap (`io.LimitReader(resp.Body, 16<<20)` in `fetch`), which is a good baseline but not equivalent to a fuzz pass. |
| Exit criteria | (a) `go test -fuzz=FuzzCIDRParse -fuzztime=1h` runs on `internal/rules/` without crash or unhandled error; (b) `go test -fuzz=FuzzCreateRequest -fuzztime=1h` on the JSON decoder; (c) `go test -fuzz=FuzzSTIXBundle -fuzztime=1h` on the puller decode path; (d) seed corpus includes ≥ 50 examples per target — valid + invalid + adversarial (deeply nested JSON, oversized fields, dangerous CIDRs `0.0.0.0/0` and `/8`-prefix, billion-laughs-style YAML if any YAML is parsed, unicode-confusable hostnames); (e) any crashes found are fixed and the offending input added to the seed corpus |
| Closing test paths | `internal/rules/fuzz_test.go` (`FuzzCIDRParse`, `FuzzCreateRequest`); `internal/ioc/fuzz_test.go` (`FuzzSTIXBundle`); seed corpus under `internal/{rules,ioc}/testdata/fuzz/` |
| CI job | New `fuzz-rule-inputs` job in `.github/workflows/ci.yml` (120s on PR; 1h nightly cron) |

### G3 — Cross-API isolation test (single-tenant reframing)

**Why:** OpenScrub is **single-tenant in v1.0.0** — there is no
`tenant_id` column on the `rules` or `mitigations` tables, and
multi-tenancy is a Phase 2.1+ concern. The CyberPath analogue (G3,
multi-tenant integration test) does not directly apply. We reframe:
the most damaging non-kernel finding here is a **role-bypass** where
a non-admin JWT can perform admin-only mutations — for example,
deleting a rule authored by an admin, or forcing an IOC pull cycle
without operator-level scope. Today the controls are at the
`internal/auth/` middleware layer; the integration test proves they
hold end-to-end across the API surface.

| Field | Value |
|---|---|
| Owner | API maintainer |
| Target date | T-14d |
| Current status | **Not started.** Per-handler auth tests exist in handler unit tests, but no end-to-end integration test that exercises the whole role matrix against a running stack. |
| Exit criteria | (a) Integration test seeds the Postgres with rules created by an `admin` principal AND an `operator` principal; (b) for every mutating endpoint exposed in v1.0.0 (`POST /rules`, `DELETE /rules/{id}`), the test confirms a viewer JWT receives 403, an operator JWT can mutate own rules but cannot delete an admin-authored rule (NDS Gate-3 separation), and an admin JWT can do all of the above; (c) test runs in CI on PR and on push to main. Note: `POST /iocs/pull` is not exposed in v1.0.0 (puller runs internally) — when the admin endpoint lands in v1.1 the matrix gains a row for it. |
| Closing test path | `tests/integration/auth_role_matrix_test.go` (Go integration test against the docker-compose stack, build tag `//go:build integration`) |
| CI job | New `integration-auth-roles` job in `.github/workflows/ci.yml` |

When OpenScrub adds multi-tenancy in Phase 2.1, this test grows the
classic CyberPath-style cross-tenant assertions; the file path stays
the same.

## 2. Timeline

| Milestone | Date offset | Owner | Output |
|---|---|---|---|
| T-8 weeks | Contract signed | Engineering lead + procurement | SOW signed; [pentest-scope.md](pentest-scope.md) shared with firm |
| T-6 weeks | Gap-closure freeze | Maintainer rota | All gaps in [security-checklist.md](security-checklist.md) resolved or formally accepted |
| T-30d | **G1 closes** | Data-plane maintainer | Kernel/BPF escape negative tests green on kernel matrix |
| T-21d | **G2 closes** | Go API maintainer | Rule + IOC fuzz harnesses clean |
| T-14d | **G3 closes** | API maintainer | Cross-API role-isolation test green |
| T-4 weeks | Clean instance ready | DevOps | Dedicated cluster / namespace; secrets rotated; auditor JWTs minted; `audit-target` tag cut |
| T-3 weeks | Tooling sanity | Engineering | `gosec`, `govulncheck`, `staticcheck`, `cargo audit`, `cargo geiger`, `npm audit`, `eslint`, `semgrep` all pass on `audit-target` tag |
| T-2 weeks | Internal red-team dry-run | Maintainer rota + outsider | Rehearsal of attack-surface paths from [threat-model.md](threat-model.md); tabletop walkthrough of rule-poisoning detection and loader crash-loop |
| T-1 week | Documentation handoff | Maintainer | Auditor receives `docs/security/` snapshot, OpenAPI, Helm chart, SBOMs, image digests |
| T-0 | Kick-off call | All | Scope walkthrough, credentials handoff, comms channel agreed |
| T+0 → T+2 | Engagement window | Auditor | 2-week box per [pentest-scope.md § 5](pentest-scope.md); daily standup |
| T+3 | Draft report | Auditor | Findings shared on private channel |
| T+4 weeks | Final report | Auditor | PDF + JSON; CVSS scored; replay scripts archived |
| T+5 | Triage + ticketing | Engineering | Each finding → GitHub issue with severity label |
| T+6-8 weeks | Remediation merged | Engineering | Critical + High closed; Medium ≥ 80% closed |
| T+10 weeks | Retest | Auditor | Reopen-or-close each finding; addendum report |

## 3. Responsibilities

| Role | Responsibility |
|---|---|
| Engineering lead | Owns the engagement end-to-end; signs SOW; arbitrates scope disputes |
| Data-plane maintainer | G1; XDP / loader review on every PR (CODEOWNERS) |
| Go API maintainer | G2; OpenAPI surface stability |
| API maintainer | G3; auth middleware ownership |
| DevOps | Test environment, credentials, cluster lifecycle |
| Procurement / legal | Contract, NDA, data-protection addendum (DPA) |
| Auditor | Test execution, finding write-up, retest, replay scripts |

## 4. Pre-engagement checklist

Mark each item before T-1 week:

- [ ] G1 kernel/BPF escape negative tests — `make test-dataplane`
      green; live-kernel suite green on 5.15 / 6.1 / 6.6
- [ ] G2 rule + IOC fuzz harnesses — 1h fuzz runs clean per target;
      seed corpora committed
- [ ] G3 cross-API role-isolation test — green in CI on
      `audit-target` tag
- [ ] All other [security-checklist.md](security-checklist.md) gaps
      closed or accepted
- [ ] `gosec`, `govulncheck`, `staticcheck` clean on `main`
- [ ] `cargo audit`, `cargo geiger` clean on `rust/dataplane/`
- [ ] `npm audit --audit-level=moderate` clean on `web/`
- [ ] `semgrep` clean (especially the `no raw sql` rule)
- [ ] Image SBOM published with the audit-target tag (CycloneDX,
      `cosign attest`)
- [ ] Cosign signature on every audit-target image; verified per
      cyberpath/docs/security/image-signing.md (see `cyberpath/docs/security/image-signing.md`)
- [ ] Threat model reviewed in last 90 days
- [ ] Operator runbook walked through in tabletop, including
      rule-poisoning detection and loader crash-loop
- [ ] Dedicated test cluster up; namespaces isolated
- [ ] Auditor JWT mint script tested against the test cluster
- [ ] PGP key for `security@opensecstack.org` issued and published
- [ ] Disclosure policy public; SLA timers defined per
      [../../SECURITY.md](../../SECURITY.md)

## 5. Auditor scheduling status

**Pending engagement, prerequisites complete.** v1.0.0 shipped
2026-05-09 with the documentation set required for SOW negotiation
([pentest-scope.md](pentest-scope.md), this plan,
[security-checklist.md](security-checklist.md), and
[threat-model.md](threat-model.md)). Recommended firm tier: mid-size
with eBPF / kernel-runtime expertise — the load-bearing surface is
kernel-side and a kernel-aware auditor is non-negotiable.

The Phase 2 v1.0.0 deliverable was scoped to ship feature-complete
with a third-party kernel-attack-surface audit pending scheduling
([README.md § Development status](../../README.md)). This plan is
that schedule.

## 6. Out-of-scope cost reminders

These are explicitly **not** part of a typical pentest engagement
and need separate funding lines:

- Public bug bounty programme (post-v1.0).
- Continuous DAST against `:8087`.
- Kernel CVE response retainer (kernel.org subscription is free; an
  engineering retainer to apply patches within 7 days is not).
- Hardware HSM procurement for the certification path (no
  certifications in OpenScrub today; deferred indefinitely).

## 7. Success criteria

The engagement is considered successful when:

1. Zero Critical findings remain open at T+10.
2. Zero kernel-tier findings remain open at T+10 (any verified
   kernel-side write or container escape from the loader pod is
   treated as Critical).
3. All High findings have a merged fix or accepted-with-rationale on
   file at T+10.
4. Auditor produces a one-page executive summary suitable for
   sharing with NIS2-scope deployers under NDA.
5. Public disclosure (if any) is coordinated and on time.
6. Retrospective updates [threat-model.md](threat-model.md) and
   [security-checklist.md](security-checklist.md) with anything the
   engagement surfaced.

## 8. Gap-closure log

| Gap | Status | Closing artefact |
|---|---|---|
| G1 — kernel/BPF escape negative tests | **Open** (target: `rust/dataplane/tests/escape_attempts.rs` + live-kernel matrix CI) |
| G2 — rule + IOC fuzz harness | **Open** (target: `internal/rules/fuzz_test.go`, `internal/ioc/fuzz_test.go`) |
| G3 — cross-API role-isolation test | **Open** (target: `tests/integration/auth_role_matrix_test.go`) |

## 9. Related

- [security-checklist.md](security-checklist.md) — control evidence feeding the T-6 freeze
- [pentest-scope.md](pentest-scope.md) — what we hand the auditor at T-8
- [threat-model.md](threat-model.md) — the surfaces the dry-run rehearses
- [compliance-map.md](compliance-map.md) — framework traceability
- [../../SECURITY.md](../../SECURITY.md) — disclosure tiers
- cyberpath/docs/security/pre-audit-plan.md (see `cyberpath/docs/security/pre-audit-plan.md`) — the analogue for CyberPath
