# ADR-004: Use Apache 2.0 Licence for APIGuard

## Status

Accepted

## Context

APIGuard needs a licence that:

- Permits commercial use and integration without requiring adopters to open-source their products
- Provides a patent grant protecting users from patent claims by contributors
- Is compatible with the licences of APIGuard's dependencies
- Aligns with the opensecstack ecosystem licence policy
- Is acceptable to enterprise security teams and legal departments

The licence choice affects who can adopt APIGuard, how it can be integrated into commercial products, and how contributors' patent rights are handled.

## Decision

Licence APIGuard under Apache License 2.0.

## Rationale

- **Patent grant**: Apache 2.0 includes an explicit patent grant — contributors licence all patents they hold that cover their contributions to any user of the software. This protects organisations that deploy APIGuard from surprise patent litigation by contributors. MIT does not include a patent grant.
- **Commercial use**: Apache 2.0 permits commercial use, distribution, and sublicensing without restriction, as long as the licence notice is retained. This is essential for enterprise adoption and for integrators who build APIGuard into their CI/CD products.
- **GPL compatibility**: Apache 2.0 is compatible with GPL 2.0+ in the direction GPL → Apache (GPL code can include Apache-licensed components). Not compatible in the reverse direction. This does not affect APIGuard since it has no GPL dependencies.
- **Dependency compatibility**: APIGuard's Go dependencies (chi, pgx, zerolog, golang-migrate) and Rust dependencies (serde, tokio, axum) are licensed under MIT, Apache 2.0, or MPL 2.0 — all compatible with Apache 2.0.
- **Ecosystem alignment**: All opensecstack security platforms use Apache 2.0. Only CITADEL uses AGPL v3, reflecting that CITADEL is governance infrastructure rather than a deployable security tool.

## Alternatives Considered

- **MIT**: Rejected. No patent grant. Simpler but provides less legal protection for users. The patent grant is the key reason to choose Apache 2.0 over MIT for a security-critical tool.
- **GPL v2**: Rejected. Would require all works that link or integrate APIGuard to be GPL-licensed. This would block enterprise integration and commercial tooling built on top of APIGuard.
- **GPL v3**: Rejected. Same integration restriction as GPL v2. Appropriate for software where copyleft is desired (e.g. CITADEL governance code), not for a scanning tool where broad adoption is the goal.
- **AGPL v3**: Rejected for APIGuard specifically. AGPL v3 requires source disclosure for network-facing services. For a tool that enterprises run in their own CI/CD pipelines, AGPL would create legal uncertainty. CITADEL uses AGPL v3 because it is governance infrastructure that opensecstack itself deploys and maintains.
- **BSL (Business Source License)**: Rejected. Not an OSI-approved open source licence. Would exclude APIGuard from open source package managers and security tools registries.

## Consequences

- All contributors must agree to the Contributor Licence Agreement (CLA) before their pull requests are merged. The CLA ensures the project has the right to distribute contributions under Apache 2.0 and confirms contributors have the right to make the contribution.
- Commercial integrations of APIGuard are permitted without restriction, provided the licence notice and attribution are retained.
- The SBOM (`SBOM.json`) must be updated with each release to confirm all dependency licences remain Apache 2.0-compatible.
