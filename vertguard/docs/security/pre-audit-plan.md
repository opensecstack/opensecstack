## VertGuard Pre-Audit Plan

Timeline, owners, and budget guidance for engaging an external
security audit firm. Reads top-to-bottom in execution order.

### 1. Timeline

| Milestone | Date offset | Owner | Output |
|---|---|---|---|
| T-8 weeks | Contract signed | Engineering lead + procurement | SOW signed; `pentest-scope.md` shared with firm |
| T-6 weeks | Gap closure freeze | Maintainer rota | All "Gap" rows in `security-checklist.md` resolved or formally accepted with rationale |
| T-4 weeks | Clean instance ready | DevOps | Dedicated cluster / namespace; secrets rotated; auditor JWTs minted |
| T-3 weeks | Tooling sanity | Engineering | `gosec`, `govulncheck`, `staticcheck`, `cargo audit` pass on `main`; CI green |
| T-2 weeks | Internal red-team dry-run | Maintainer rota + at least one outsider | Rehearsal of attack tree paths from `threat-model.md`; one-pager of what we found ourselves |
| T-1 week | Documentation handoff | Maintainer | Auditor receives `docs/security/` snapshot, OpenAPI, Helm chart, SBOM |
| T-0 | Kick-off call | All | Scope walkthrough, credentials handoff, comms channel agreed |
| T+0 → T+4 | Engagement window | Auditor | Daily standup; Slack/Signal channel for blockers |
| T+5 | Draft report | Auditor | Findings shared on private channel |
| T+6 weeks | Final report | Auditor | PDF + JSON; CVSS scored |
| T+7 | Triage + ticketing | Engineering | Each finding → GitHub issue with severity label |
| T+8 weeks | Remediation merged | Engineering | Critical + High closed; Medium ≥80% closed |
| T+10 weeks | Retest | Auditor | Reopen-or-close each finding; addendum report |
| T+11 | Public summary (if any) | Maintainer + auditor | Coordinated blog post / advisory respecting `disclosure.md` |

### 2. Responsibilities

| Role | Responsibility |
|---|---|
| Engineering lead | Owns the engagement end-to-end; signs SOW; arbitrates scope disputes |
| Maintainer rota | Triage, fix, retest |
| DevOps | Test environment, credentials, cluster lifecycle |
| Procurement / legal | Contract, NDA, data-protection addendum (DPA) |
| Comms | External communication if a finding warrants public disclosure |
| Auditor | Test execution, finding write-up, retest |

### 3. Pre-engagement checklist

Mark each item before T-1 week:

- [ ] All `security-checklist.md` gaps closed or accepted
- [x] `gosec`, `govulncheck`, `staticcheck` clean on `main` — `govulncheck` wired in `.github/workflows/security.yml`
- [x] `cargo audit` clean on `rust/` — wired in `.github/workflows/security.yml` (initially `continue-on-error`)
- [x] `c2pa-rs` build path — Tracked: CI build green on Linux
      (`c2pa-verify` job in `.github/workflows/ci.yml` builds
      `rust/c2pa-verify` against `libssl-dev` on `ubuntu-latest`).
      MinGW-w64 / Windows-native build deferred until upstream ships
      a `rustls`-only path; see `rust/c2pa-verify/README.md`.
- [x] Image SBOM published with the audit-target tag — CycloneDX `cosign attest` in `release.yml`
- [x] Cosign signature on the audit-target image — keyless OIDC sign in `release.yml`; verify recipe in `docs/security/image-signing.md`
- [ ] Threat model reviewed in last 90 days
- [ ] Operator runbook walked through in tabletop
- [ ] Dedicated test cluster up; namespaces isolated
- [ ] Auditor JWT mint script tested against the test cluster
- [ ] PGP key for `security@opensecstack.org` issued and published
- [ ] Disclosure policy public; SLA timers defined

### 4. Budget guidance

VertGuard's audit scope (Go API, Rust crates, Helm chart, ~12k LoC,
no live ML inference yet) sits in the small-to-mid tier.

| Tier | Cost (EUR equiv.) | Typically includes | What costs extra |
|---|---|---|---|
| **Boutique / single auditor** | €25-40k | 2-3 weeks effort, web app + auth deep-dive, report, one retest | ML inference review, threat-model workshop, on-site time |
| **Mid-size firm** | €50-80k | 4 weeks, two auditors, code review + DAST, NIS2 mapping cross-check, two retests | Long-term retainer, SOC2 readiness, table-top facilitation |
| **Top-tier firm (NCC, Trail of Bits, Doyensec, …)** | €80-150k | 4-6 weeks, multi-discipline (web, crypto, cluster), formal report, public summary support | Custom tool development, multi-week soak, model-quality assessment |

Recommended for v0.1.0-alpha audit: **mid-size firm** — sufficient
depth for the current surface, NIS2-aware, retest included.
Re-evaluate at v1.0 with a top-tier firm focused on the ML surface.

| Line item | Budgeted |
|---|---|
| External audit fee | €60k |
| DPA / contract review | €5k (legal) |
| Internal effort (T-8 → T+10) | ~30 person-days across team |
| Test cluster cost | €0.5k (cloud, 6 weeks) |
| PGP / disclosure infra | negligible |
| Retest buffer (if scope expanded) | €10k contingency |
| **Total budgeted** | **€75-80k** |

### 5. Out-of-scope cost reminders

These are explicitly **not** part of a typical pentest engagement
and need separate funding lines:

- Public bug bounty programme (post-v1.0).
- Continuous DAST (e.g., paid Burp Enterprise).
- SOC2 / ISO 27001 readiness.
- Red-team adversary emulation (multi-week, dedicated firm).
- Hardware HSM procurement for JWT signing.

### 6. Success criteria

The engagement is considered successful when:

1. Zero Critical findings remain open at T+10.
2. All High findings have a merged fix or accepted-with-rationale
   on file at T+10.
3. Auditor produces a one-page executive summary suitable for
   sharing with NIS-scope customers under NDA.
4. Public disclosure (if any) is coordinated and on time.
5. Retrospective updates `threat-model.md` and `security-checklist.md`
   with anything the engagement surfaced.

### 7. Gap closure log

Tracks the T-6 freeze items as they close. One line per gap pointing
at the workflow / source path that proves it.

| Gap | Status | Closed by |
|---|---|---|
| 7.4 / 7.5 (and 7.6 seeded) — `govulncheck`, `cargo audit`, `pip-audit` in CI | Closed | `.github/workflows/security.yml` — three independent jobs on PR + push + weekly cron `0 6 * * 1` |
| 2.10 — Refuse-to-start in prod with dev-mode / insecure defaults | Closed | `internal/config/config.go` (`Config.EnforceProductionGate`); wired in `cmd/server/main.go`; covered by `internal/config/config_test.go` |
| 6.13 — Cosign image signing + SBOM attestation | Closed | `.github/workflows/release.yml` (keyless OIDC `cosign sign` + CycloneDX `cosign attest` for both `vertguard` and `vertguard-ml`); verification recipe in `docs/security/image-signing.md` |

### 8. Related

- `security-checklist.md` — gap inventory feeding the T-6 freeze
- `pentest-scope.md` — what we hand the auditor at T-8
- `disclosure.md` — researcher-facing terms; mirrored for auditors
