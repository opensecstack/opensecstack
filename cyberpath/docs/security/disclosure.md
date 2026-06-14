## CyberPath Coordinated Disclosure Policy

This document is the long-form companion to `SECURITY.md`. It tells
external researchers exactly how to report a vulnerability, what to
expect from the maintainers, and what we will not do.

**Sandbox-escape findings are treated as high-severity by default**
and routed directly to the core security team.

### 1. Reporting channels

| Channel | Address | Use for |
|---|---|---|
| GitHub Security Advisory | `github.com/opensecstack/opensecstack/security/advisories/new` | **Preferred.** Private, GitHub-coordinated, integrates with the CVE process. |
| Email | `security@opensecstack.org` | Alternative when GitHub advisory is not accessible. |
| PGP-encrypted email | Key fingerprint: **PLACEHOLDER — to be issued by maintainers before v1.0.0 stable** | Required for sandbox-escape findings and any vulnerability whose details would be harmful in plaintext. |

PGP key publication: the canonical key will be served from
`https://opensecstack.org/.well-known/security.txt` and mirrored at
`keybase.io/opensecstack`. Until v1.0.0 stable, please use the
GitHub Security Advisory channel and request a PGP key in the
initial message — a maintainer will reply with one within 24 hours.

### 2. What to include

A high-quality report contains:

- Affected version (`cyberpath --version` output, image digest, or
  commit SHA).
- Reproduction steps. A `curl` recipe is gold; for sandbox-escape
  findings, the Wasm module + lab YAML that triggers the issue is
  required (do not embed it inline in plaintext email — encrypt it).
- Impact assessment: confidentiality / integrity / availability,
  with a CVSSv3.1 vector if you can compute one.
- Suggested fix or mitigation, if known.
- Whether you intend to publish a CVE / blog post; coordinate the
  date.

### 3. SLA

| Stage | Target |
|---|---|
| Acknowledgement of receipt | **24 hours** (business day; weekend/holiday: best effort, max 72 h) |
| Severity classification | **72 hours** (in-scope / out-of-scope / duplicate; severity assigned per CVSSv3.1) |
| Initial fix proposal or mitigation guidance | **Critical: 7 days. High: 30 days. Medium: 90 days. Low: next release.** |
| Coordinated public disclosure | **90 days** from first ack, extendable by mutual agreement when a fix is in flight |
| Expedited disclosure | When a vulnerability is **actively exploited** in the wild, the disclosure window collapses to whatever is needed to ship the fix and notify deployers; we coordinate with the reporter on day-of-fix communications |

If we miss an SLA, the reporter is entitled to escalate by replying
on-thread with `ESCALATE`. The next maintainer in the rota will
respond within 24 h.

### 4. Scope

Mirrors the public scope in `SECURITY.md`:

**In-scope:** the CyberPath Go API, Rust sandbox host (v1.0.0+),
React frontend, Docker images, Helm chart, generated TypeScript
client, lab images published from this repo, and integrations with
CITADEL / NIS2 Compass / IRFlow as published in this repo.

**Out-of-scope:**

- wasmtime upstream (report to the Bytecode Alliance; notify us so
  we can pin / patch).
- Third-party lab images contributed by the community (report
  upstream; notify us if a contributed image carries a CVE).
- Generic LMS feature requests.
- Issues in user-authored track content (raise as a content quality
  issue, not a security advisory).

### 5. Safe harbour

Researchers acting in good faith under this policy will not be
subject to legal action by the OpenSecStack project. Specifically,
no legal action will be taken against research that:

- Did not access user data that did not belong to the researcher.
- Did not disrupt service for other users (no DDoS, no destructive
  testing on shared infra).
- Did not exfiltrate PII.
- Was conducted on the public test instance, on a self-hosted copy,
  or via the documented sandbox.

We will treat your report as confidential until we agree on a
disclosure date, and we will credit you in the advisory and
`CHANGELOG.md` unless you request anonymity.

You must not, however:

- Access data that is not yours.
- Disrupt the service for other users.
- Pivot to systems or accounts outside scope (notably, do not
  attempt to pivot from CyberPath to CITADEL).
- Exfiltrate learner PII even if you can technically reach it —
  proof-of-vulnerability is sufficient; PII exfil voids safe
  harbour.

### 6. Hall of fame & bounties

CyberPath is in v0.x → v1.0. **No monetary bounty is offered**
during the v0.x line. Recognition is via:

- Named credit in the GitHub Security Advisory and the
  `CHANGELOG.md` entry for the fix release.
- Inclusion in the `docs/security/hall-of-fame.md` file (created
  when the first qualifying report lands).
- Public thanks on the project's release notes.

A monetary programme is planned for v1.x once the platform leaves
the initial v1.0 audit cycle. Sandbox-escape findings on a stable
release will be the first category eligible.

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
- Quality issues in track content (lessons that are out-of-date,
  exercises with ambiguous answers): open a content issue.
- A learner being able to retry a quiz they failed: that is the
  product working as designed.

### 9. Coordinated disclosure window

The standard window is **90 days from first ack**, with extensions
by mutual agreement when a fix is in flight. The window may be:

- **Extended** when a fix requires upstream coordination (e.g.,
  wasmtime CVE) or when the fix is in code review and the reporter
  agrees.
- **Expedited** when active exploitation is observed in the wild;
  in that case the maintainer team and the reporter agree on a
  collapsed timeline that prioritises shipping the fix and notifying
  deployers.

Public disclosure happens after a fix is shipped + a reasonable
upgrade window for deployers (≥ 14 days for High+, immediate for
Critical-with-active-exploit once a fix is available).

### 10. Related

- `SECURITY.md` — short-form public policy
- `docs/security/pentest-scope.md` — engagement-style scoping for
  paid auditors
- `docs/security/threat-model.md` — architectural context
- Root [`SECURITY.md`](../../SECURITY.md) — ecosystem-wide policy
