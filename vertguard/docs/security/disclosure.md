## VertGuard Coordinated Disclosure Policy

This document is the long-form companion to `SECURITY.md`. It tells
external researchers exactly how to report a vulnerability, what to
expect from the maintainers, and what we will not do.

### 1. Reporting channels

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | **Preferred.** Private, GitHub-coordinated, integrates with the CVE process. |
| Email | `security@opensecstack.org` | Alternative when GitHub advisory is not accessible. |
| PGP-encrypted email | Key fingerprint: **PLACEHOLDER — to be issued by maintainers before v0.1.0 stable** | Required for vulnerabilities whose details would be harmful in plaintext (e.g., in-flight 0-day exploit chains). |

PGP key publication: the canonical key will be served from
`https://opensecstack.org/.well-known/security.txt` and mirrored at
`keybase.io/opensecstack`. Until v0.1.0 stable, please use the
GitHub Security Advisory channel and request a PGP key in the
initial message — a maintainer will reply with one within 24 hours.

### 2. What to include

A high-quality report contains:

- Affected version (`vertguard --version` output, image digest, or
  commit SHA).
- Reproduction steps. A `curl` recipe is gold; a request/response
  pair is acceptable; a screenshot alone is not.
- Impact assessment: confidentiality / integrity / availability,
  with a CVSSv3.1 vector if you can compute one.
- Suggested fix or mitigation, if known.
- Whether you intend to publish a CVE / blog post; coordinate the
  date.

### 3. SLA

| Stage | Target |
|---|---|
| Acknowledgement of receipt | **24 hours** (business day; weekend/holiday: best effort, max 72 h) |
| Triage decision (in-scope / out-of-scope / duplicate) | **7 days** |
| Initial fix proposal or mitigation guidance | **14 days** for High+; **30 days** for Medium; **next minor** for Low |
| Coordinated public disclosure | **90 days** from first ack, extendable by mutual agreement when a fix is in flight |

If we miss an SLA, the reporter is entitled to escalate by replying
on-thread with `ESCALATE`. The next maintainer in the rota will
respond within 24 h.

### 4. Scope

Mirrors the public scope in `SECURITY.md`:

**In-scope:** the VertGuard Go API, Rust crates, Python ML service
(when shipped), Docker image, Helm chart, generated TypeScript
client, and integrations with CITADEL / ThreatFlow as published in
this repo.

**Out-of-scope:** third-party ML models from HuggingFace (report
upstream and tag us), the C2PA specification itself, MITRE ATLAS
content, and inherent ML-detection limitations documented in
`docs/false-positive-handling.md`.

### 5. Safe harbour

Researchers acting in good faith under this policy will not be
subject to legal action by the OpenSecStack project. Specifically:

- We will not pursue or support pursuit of legal action for
  research conducted on the public test instance, on a self-hosted
  copy, or via the documented sandbox.
- We will treat your report as confidential until we agree on a
  disclosure date.
- We will credit you in the advisory and `CHANGELOG.md` unless you
  request anonymity.

You must not, however:

- Access data that is not yours.
- Disrupt the service for other users (no DDoS, no destructive
  testing on shared infra).
- Pivot to systems or accounts outside scope.

### 6. Hall of fame & bounties

VertGuard is in v0.x. **No monetary bounty is offered** during the
v0.x line. Recognition is via:

- Named credit in the GitHub Security Advisory and the
  `CHANGELOG.md` entry for the fix release.
- Inclusion in the `docs/security/hall-of-fame.md` file
  (created when the first qualifying report lands).
- Public thanks on the project's release notes.

A monetary programme is planned for v1.0+ once the platform leaves
alpha. Sign up to the maintainer mailing list for the announcement.

### 7. What we will not do

- Sue, threaten, or report a good-faith researcher.
- Demand that you sign an NDA before triage.
- Withhold credit you are due.
- Disclose your identity without consent.

### 8. Non-vulnerabilities

The following are not security issues for the purpose of this
policy. We still appreciate bug reports — please open a normal
GitHub issue.

- Missing security headers on `/metrics` (firewalled in production
  per docs).
- Self-XSS in the dashboard.
- Verbose error messages on `4xx` responses (errors are structured
  and bounded).
- Detection bypasses (false-negatives) — these are tracked under
  the research roadmap, not the security advisory process. Open a
  PR against `tests/adversarial/`.

### 9. Related

- `SECURITY.md` — short-form public policy
- `docs/security/pentest-scope.md` — engagement-style scoping for
  paid auditors
- `docs/security/threat-model.md` — architectural context
- Root [`SECURITY.md`](../../../SECURITY.md) — ecosystem-wide policy
