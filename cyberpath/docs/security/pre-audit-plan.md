## CyberPath Pre-Audit Plan

Timeline, owners, and budget guidance for engaging an external
security audit firm before tagging v1.0.0. Reads top-to-bottom in
execution order.

The plan is anchored on **three priority gaps** (G1, G2, G3) that
must close before kick-off. Everything else in `security-checklist.md`
either ships with v1.0.0 by default or is formally accepted as a
v1.x roadmap item.

### 1. Priority gaps to close before kick-off

#### G1 — Sandbox-escape unit test suite

**Why:** Sandbox escape is the highest-severity threat in the
CyberPath model (`threat-model.md § AT-1`). An auditor's first
question is "what attempts at escape have you already caught
yourself?" — without a published test corpus, the engagement starts
from cold.

| Field | Value |
|---|---|
| Owner | Sandbox-host maintainer |
| Target date | T-30d (30 days before pentest kick-off) |
| Exit criteria | (a) ≥ 30 negative tests covering every host function in `rust/sandbox-host/src/host_func/`; (b) every known wasmtime CVE class (memory grow underflow, fuel overflow, table-grow, integer overflow in linear memory bounds) has at least one regression test; (c) `make test-sandbox` passes in CI; (d) coverage report shows ≥ 80% line coverage on `rust/sandbox-host/`. |
| Closing test/path | `rust/sandbox-host/tests/escape_attempts.rs` (Rust integration tests) + `rust/sandbox-host/fuzz/fuzz_targets/host_func.rs` (cargo-fuzz seed corpus). CI job: `rust-static` and a new `sandbox-fuzz-shortrun` (120s) in `.github/workflows/ci.yml`. |
| Status | Not started (placeholder; populate once sandbox-host work begins) |

#### G2 — Content-yaml fuzzing campaign

**Why:** Lab YAML and lesson markdown enter the platform from
content authors, including community contributors. A malformed
YAML that crashes the parser or bypasses the egress-allowlist
linter is a privilege-escalation primitive. A short fuzz pass before
audit demonstrates the parser is robust against adversarial input.

| Field | Value |
|---|---|
| Owner | Content-module maintainer |
| Target date | T-21d |
| Exit criteria | (a) `go test -fuzz=FuzzContentYAML -fuzztime=1h` runs without finding a crash or unhandled error; (b) corpus seeded with at least 50 examples (valid + invalid + adversarial — billion-laughs YAML, recursive anchors, oversized inputs); (c) any crashes found are fixed and the offending input added to the seed corpus; (d) `cmd/content-lint/` is fuzzed similarly with a 30-min budget. |
| Closing test/path | `internal/content/fuzz_test.go` (the `FuzzContentYAML` target), seed corpus at `internal/content/testdata/fuzz/FuzzContentYAML/`. CI job: `fuzz-content-yaml` in `.github/workflows/ci.yml` (120s on PR; 1h nightly cron). |
| Status | Not started |

#### G3 — Multi-tenant integration test

**Why:** The national-CSIRT deployment shape is multi-tenant by
design. The most damaging non-sandbox finding would be a
cross-tenant data leak — a learner in tenant A reading tenant B's
progress. Today the controls are at the query layer (every query
filters on `tenant_id`); the integration test proves they hold
end-to-end across the API surface.

| Field | Value |
|---|---|
| Owner | API maintainer |
| Target date | T-14d |
| Exit criteria | (a) Integration test seeds 3 tenants with overlapping user ids; (b) for each in-scope endpoint that takes a path/query parameter referencing user/track/lesson/completion/certification, the test confirms a tenant A token cannot read or mutate a tenant B object — by id, by enumeration, by `as_of` audit replay, by `include_expired`, and via the WebSocket lab stream; (c) test runs in CI on PR and on push to main. |
| Closing test/path | `tests/integration/multi_tenant_test.go` (Go integration test against the docker-compose stack). CI job: `integration-multitenant` in `.github/workflows/ci.yml`. |
| Status | Not started |

### 2. Timeline

| Milestone | Date offset | Owner | Output |
|---|---|---|---|
| T-8 weeks | Contract signed | Engineering lead + procurement | SOW signed; `pentest-scope.md` shared with firm |
| T-6 weeks | Gap closure freeze | Maintainer rota | All "Gap" rows in `security-checklist.md` resolved or formally accepted with rationale |
| T-30d | **G1 closes** | Sandbox-host maintainer | Sandbox-escape unit test suite green |
| T-21d | **G2 closes** | Content-module maintainer | Content-yaml fuzz campaign clean |
| T-14d | **G3 closes** | API maintainer | Multi-tenant integration test green |
| T-4 weeks | Clean instance ready | DevOps | Dedicated cluster / namespace; secrets rotated; auditor JWTs minted; `audit-target` tag cut |
| T-3 weeks | Tooling sanity | Engineering | `gosec`, `govulncheck`, `staticcheck`, `cargo audit`, `cargo geiger`, `npm audit`, `eslint`, `semgrep`, `content-lint` all pass on `audit-target` tag |
| T-2 weeks | Internal red-team dry-run | Maintainer rota + at least one outsider | Rehearsal of attack tree paths from `threat-model.md`; tabletop walkthrough of sandbox-escape playbook from operator handbook |
| T-1 week | Documentation handoff | Maintainer | Auditor receives `docs/security/` snapshot, OpenAPI, Helm chart, SBOMs, lab-image digests |
| T-0 | Kick-off call | All | Scope walkthrough, credentials handoff, comms channel agreed |
| T+0 → T+2 | Engagement window | Auditor | 2-week box per `pentest-scope.md § 5`; daily standup |
| T+3 | Draft report | Auditor | Findings shared on private channel |
| T+4 weeks | Final report | Auditor | PDF + JSON; CVSS scored; replay scripts archived |
| T+5 | Triage + ticketing | Engineering | Each finding → GitHub issue with severity label |
| T+6-8 weeks | Remediation merged | Engineering | Critical + High closed; Medium ≥ 80% closed |
| T+10 weeks | Retest | Auditor | Reopen-or-close each finding; addendum report |
| T+11 | Public summary (if any) | Maintainer + auditor | Coordinated blog post / advisory respecting `disclosure.md` |

### 3. Responsibilities

| Role | Responsibility |
|---|---|
| Engineering lead | Owns the engagement end-to-end; signs SOW; arbitrates scope disputes |
| Sandbox-host maintainer | G1; sandbox-touching review on every PR (CODEOWNERS) |
| Content-module maintainer | G2; content-lint maintenance |
| API maintainer | G3; OpenAPI surface stability |
| DevOps | Test environment, credentials, cluster lifecycle, Kyverno policy |
| Procurement / legal | Contract, NDA, data-protection addendum (DPA) |
| Comms | External communication if a finding warrants public disclosure |
| Auditor | Test execution, finding write-up, retest, replay scripts |

### 4. Pre-engagement checklist

Mark each item before T-1 week:

- [ ] G1 sandbox-escape unit test suite — `make test-sandbox` green; coverage report archived
- [ ] G2 content-yaml fuzz — 1h fuzz run clean; seed corpus committed
- [ ] G3 multi-tenant integration test — green in CI on `audit-target` tag
- [ ] All other `security-checklist.md` gaps closed or accepted
- [ ] `gosec`, `govulncheck`, `staticcheck` clean on `main`
- [ ] `cargo audit`, `cargo geiger` clean on `rust/`
- [ ] `npm audit --audit-level=moderate` clean on `web/`
- [ ] `semgrep` and `content-lint` clean on `content/tracks/`
- [ ] Image SBOM published with the audit-target tag (CycloneDX `cosign attest`)
- [ ] Cosign signature on the audit-target platform image AND at least one lab image; verified per `image-signing.md`
- [ ] Threat model reviewed in last 90 days
- [ ] Operator handbook walked through in tabletop, including sandbox-escape playbook
- [ ] Dedicated test cluster up; namespaces isolated; Kyverno verify-cyberpath-image policy applied
- [ ] Auditor JWT mint script tested against the test cluster
- [ ] PGP key for `security@opensecstack.org` issued and published
- [ ] Disclosure policy public; SLA timers defined

### 5. Budget guidance

CyberPath's audit scope (Go API, Rust sandbox host with wasmtime,
React frontend, Helm chart, ~25k LoC at v1.0, multi-tenant, with a
sandbox-escape surface that is intrinsically interesting) sits in
the mid tier — slightly larger than VertGuard's because the Wasm
sandbox specifically requires a wasm-runtime-aware reviewer.

| Tier | Cost (EUR equiv.) | Typically includes | What costs extra |
|---|---|---|---|
| **Boutique / single auditor** | €30-45k | 2-3 weeks effort, web app + auth deep-dive, report, one retest | Wasm sandbox deep-dive, multi-tenant, on-site |
| **Mid-size firm with wasm expertise** | €60-100k | 4 weeks, two auditors (one wasm-specialist), code review + DAST, sandbox-escape attempt, NIS2 mapping cross-check, two retests | Long-term retainer, SOC2 readiness, table-top facilitation |
| **Top-tier firm (NCC, Trail of Bits, Doyensec, …)** | €100-180k | 4-6 weeks, multi-discipline (web, crypto, wasm runtime, cluster), formal report, public summary support | Custom tool development, multi-week sandbox soak, model-quality assessment |

Recommended for v1.0.0 audit: **mid-size firm with wasm
expertise** — the sandbox is the load-bearing surface and a
wasm-aware auditor is non-negotiable.

| Line item | Budgeted |
|---|---|
| External audit fee | €80k |
| DPA / contract review | €5k (legal) |
| Internal effort (T-8 → T+10) | ~45 person-days across team |
| Test cluster cost | €0.7k (cloud, 6 weeks) |
| PGP / disclosure infra | negligible |
| Retest buffer (if scope expanded) | €15k contingency |
| **Total budgeted** | **€100-110k** |

### 6. Out-of-scope cost reminders

These are explicitly **not** part of a typical pentest engagement
and need separate funding lines:

- Public bug bounty programme (post-v1.0).
- Continuous DAST.
- SOC2 / ISO 27001 readiness.
- Red-team adversary emulation against a national-CSIRT-shaped
  deployment (multi-week, dedicated firm).
- Hardware HSM procurement for the certification signing key (v1.x
  if KMS-only proves insufficient).

### 7. Success criteria

The engagement is considered successful when:

1. Zero Critical findings remain open at T+10.
2. Zero sandbox-escape findings remain open at T+10 (these default
   to High and any escape demonstration is treated as Critical).
3. All High findings have a merged fix or accepted-with-rationale
   on file at T+10.
4. Auditor produces a one-page executive summary suitable for
   sharing with NIS2-scope customers under NDA.
5. Public disclosure (if any) is coordinated and on time.
6. Retrospective updates `threat-model.md` and `security-checklist.md`
   with anything the engagement surfaced.

### 8. Gap closure log

Tracks the priority gaps and T-6 freeze items as they close.

| Gap | Status | Closed by |
|---|---|---|
| G1 — sandbox-escape unit test suite | Open | (target: `rust/sandbox-host/tests/escape_attempts.rs` + `make test-sandbox`) |
| G2 — content-yaml fuzz | Open | (target: `internal/content/fuzz_test.go` + `tests/fuzz/content-yaml/` corpus) |
| G3 — multi-tenant integration test | Open | (target: `tests/integration/multi_tenant_test.go`) |

### 9. Related

- `security-checklist.md` — gap inventory feeding the T-6 freeze
- `pentest-scope.md` — what we hand the auditor at T-8
- `disclosure.md` — researcher-facing terms; mirrored for auditors
- `threat-model.md § 5` — attack trees the dry-run rehearses
- `image-signing.md` — verification smoke test at T-3 weeks
