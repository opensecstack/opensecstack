# opensecstack Governance

## Overview

opensecstack is an open-source cybersecurity ecosystem maintained by a community of security professionals and developers. This document describes how the project is governed, how decisions are made, and how contributors can progress to maintainer status.

## Teams

### Core Maintainers
Responsible for the overall direction of the ecosystem, release management, security policy, and cross-platform architecture. Any change touching shared infrastructure, the SDK contracts, or CI/CD pipelines requires approval from a Core Maintainer.

### Platform Maintainers
Each platform (APIGuard, NIS2 Compass, etc.) has its own set of maintainers who are responsible for day-to-day development, issue triage, and code review within that platform. Changes to a platform require approval from at least one Platform Maintainer for that platform.

### Security Team
A subset of Core Maintainers with additional responsibilities for reviewing security-sensitive changes (authentication, cryptography, rate limiting, audit trails) and handling vulnerability disclosures.

## Decision Making

### Everyday decisions
Bug fixes, documentation improvements, minor enhancements, and dependency updates do not require special process — open a PR, get one approval from the relevant platform maintainer, pass CI, and merge.

### Significant changes
New features, API contract changes, new platform integrations, and changes to security primitives require:
- An issue or RFC describing the change and rationale
- Discussion period of at least 5 business days
- Approval from at least one Core Maintainer and one Platform Maintainer

### Architectural decisions
Changes that affect multiple platforms, introduce new technology choices, or modify the CITADEL governance integration require:
- A formal Architecture Decision Record (ADR) in `/adrs/`
- Review period of at least 10 business days
- Approval from two Core Maintainers

### New platforms
Adding a new platform to the ecosystem requires:
- An RFC in `/rfcs/` with architecture proposal, technology stack justification, and integration contract specification
- Community discussion period of at least 30 days
- Unanimous approval from Core Maintainers

## RFC Process

1. Open a PR adding an RFC document to `/rfcs/` using the RFC template
2. The community discusses the RFC in the PR comments
3. After the review period, Core Maintainers either accept, reject, or request revisions
4. Accepted RFCs become the basis for implementation issues

## Release Process

### Versioning
opensecstack uses semantic versioning (`MAJOR.MINOR.PATCH`):
- `PATCH` — backwards-compatible bug fixes
- `MINOR` — backwards-compatible new features
- `MAJOR` — breaking changes to SDK contracts or platform APIs

### Release approval
- `PATCH` releases: One Core Maintainer approval
- `MINOR` releases: Two Core Maintainer approvals + all platform CI passing
- `MAJOR` releases: All Core Maintainers + 2-week community notice

### Security releases
Security fixes follow an accelerated process:
- Vulnerability reported via SECURITY.md (private disclosure)
- Fix developed under 48-hour embargo
- Coordinated release with CVE assignment if applicable
- Public disclosure after patch is available

## Becoming a Maintainer

### Platform Maintainer
Contributors who have made significant, sustained contributions to a platform may be nominated by an existing Platform Maintainer. Requirements:
- At least 10 merged PRs to the platform
- Active in issue triage and code review
- Demonstrated understanding of the platform's security model
- Nomination approved by one Core Maintainer

### Core Maintainer
Platform Maintainers who demonstrate ecosystem-wide leadership may be invited to the Core Maintainers team. This requires unanimous approval from existing Core Maintainers.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md). Violations should be reported to the maintainers via the contact method in that document.

## Meetings

- **Community call**: Monthly, open to all contributors (schedule in GitHub Discussions)
- **Maintainer sync**: Biweekly, Core + Platform Maintainers (notes published in Discussions)
- **Security review**: Quarterly, Security Team only (summary published without sensitive details)

## Contact

- GitHub Discussions: For feature requests, questions, and community discussion
- GitHub Issues: For bug reports and tracked work
- Security disclosures: See [SECURITY.md](SECURITY.md)
