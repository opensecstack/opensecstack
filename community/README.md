# opensecstack Community

Welcome to the opensecstack community hub. This directory contains everything you need to participate — whether you're opening your first issue, presenting at a conference, or becoming a maintainer.

---

## Quick links

| What | Where |
|------|-------|
| Ask a question | [GitHub Discussions → Q&A](https://github.com/opensecstack/opensecstack/discussions/categories/q-a) |
| Propose a feature | [GitHub Discussions → Ideas](https://github.com/opensecstack/opensecstack/discussions/categories/ideas) |
| Report a bug | [GitHub Issues](https://github.com/opensecstack/opensecstack/issues/new/choose) |
| Report a vulnerability | [SECURITY.md](../SECURITY.md) — **never open a public issue** |
| Real-time chat | Discord `#general` — link in GitHub Discussions pinned post |
| Monthly community call | [MEETINGS.md](./MEETINGS.md) — open to everyone |
| Become a contributor | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Mentorship | [MENTORSHIP.md](./MENTORSHIP.md) |
| First contribution | [GOOD-FIRST-ISSUES.md](./GOOD-FIRST-ISSUES.md) |
| Ambassadors & advocacy | [AMBASSADORS.md](./AMBASSADORS.md) |
| Contributor recognition | [HALL-OF-FAME.md](./HALL-OF-FAME.md) |

---

## Who we are

opensecstack is an open-source security ecosystem built for European infrastructure operators, NIS2/GDPR-governed organisations, and security teams that need auditable, cryptographically verifiable governance. Every decision the platform takes is WORM-logged, chain-hashed, and anchored with Ed25519 signatures.

**Eight platforms, one governance layer:**

| Platform | Purpose | Status |
|----------|---------|--------|
| APIGuard | OWASP API Top 10 scanner with CVSS 3.1 scoring | Active |
| NIS2 Compass | NIS2 Article 21(2) compliance mapping | Active |
| CITADEL | Governance engine — MARSHAL · WORM · VIGIL · AUGUR | Active |
| IRFlow | Incident response orchestration | In development |
| ThreatFlow | Threat intelligence aggregation (STIX 2.1) | In development |
| OpenScrub | DDoS mitigation via XDP/eBPF | Planned |
| CyberPath | Security training and certification | Planned |
| SecureLab | Attack simulation and detection validation | Planned |
| OpenCSIRT | National/sector CSIRT operations | Planned |

---

## Ways to contribute

You do not need to write code to contribute. All of the following count:

- **Triage** — label and reproduce bug reports
- **Documentation** — improve or translate docs and runbooks
- **Testing** — write tests, run the test suite on new environments
- **Code review** — review open pull requests and leave constructive feedback
- **Security research** — responsible disclosure under [SECURITY.md](../SECURITY.md)
- **Translation** — localise user-facing strings (priority: Albanian, German, French, Dutch)
- **Advocacy** — present opensecstack at conferences, meetups, and university events
- **Regulatory feedback** — help align the platform with NIS2 transpositions across EU member states

---

## Community norms

We follow the [Contributor Covenant 2.1](../CODE_OF_CONDUCT.md). The short version:

- Be welcoming and patient — especially with new contributors
- Disagree on ideas, never on people
- Security disclosures go to the security team, not public issues
- All maintainer decisions are documented; disagreements follow the RFC process

Violations: [conduct@opensecstack.org](mailto:conduct@opensecstack.org)

---

## Getting oriented

New to the project? Start here:

1. Read [ARCHITECTURE.md](../ARCHITECTURE.md) for the overall design
2. Run `docker compose up` in the root — it starts APIGuard, NIS2 Compass, and CITADEL locally
3. Browse [GOOD-FIRST-ISSUES.md](./GOOD-FIRST-ISSUES.md) for your first contribution
4. Join the next community call — dates in [MEETINGS.md](./MEETINGS.md)
5. Say hello in Discord `#introductions`
