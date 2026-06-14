# OpenSecStack Release Process

How a release is cut, tested, and published. This process is meant to
scale from v1.0.0 through the roadmap horizon — it is the discipline
that keeps docs honest, CHANGELOG entries accurate, and compatibility
claims provable.

For the version-compatibility rules, see [compatibility-matrix.md](./compatibility-matrix.md).
For the deprecation schedule, see [deprecation-policy.md](./deprecation-policy.md).

## Release types

The ecosystem ships in two modes:

### Per-platform releases (default)

Each platform (APIGuard, NIS2 Compass, CITADEL, IRFlow, ThreatFlow, SDK)
carries its own version and release cadence. Tags follow a
module-scoped form:

- `citadel/v1.1.0`
- `irflow/v1.0.2`
- `sdk/v1.0.0`
- `apiguard/v1.3.0`

This lets a platform ship a fix without forcing every other platform
through the release cycle. It's the Go monorepo convention and aligns
with how `go get` resolves module versions.

### Ecosystem releases (coordination events)

Twice a year, we cut an **ecosystem release** that pins a
compatible-set across all platforms:

- `ecosystem/v1.0.0-2026-Q2` — pins specific platform versions known
  to work together for this quarter
- Accompanying [compatibility-matrix.md](./compatibility-matrix.md)
  update

Ecosystem releases are what deployers consume when they want "the
blessed configuration". They are never required — individual platform
upgrades between ecosystem releases are supported via the compat
matrix — but they are the low-risk path for conservative operators.

## Cadence

| Release type | Frequency |
|---|---|
| Per-platform patch (`1.0.1`, `1.0.2`) | As needed (bug fixes, security) |
| Per-platform minor (`1.1.0`, `1.2.0`) | Quarterly average |
| Per-platform major (`2.0.0`) | Annually at most |
| Ecosystem release | 2×/year — spring (Q2) and autumn (Q4) |

Emergency security patches bypass the cadence — see "Security
advisory process" below.

## The process

### 1. Cut an RC branch

```bash
git checkout main
git pull
git checkout -b release/citadel-v1.1.0-rc
```

The branch stays under `release/` so it's clearly not a feature
branch.

### 2. Update the version + CHANGELOG

- Bump the platform's `internal/version/version.go` (or equivalent).
- Move the `[Unreleased]` section in `CHANGELOG.md` under a new
  version heading with today's date.
- Write a **release-notes-ready summary** in the CHANGELOG section —
  assume a deployer will read it to decide whether to upgrade.

### 3. Run the full gate

Per platform:

```bash
make lint
make test
make test-integration   # if the platform has it
make bench              # for CITADEL; compare against baseline
make build              # ldflags inject the version
```

All must be green. If anything fails, fix in the branch — do not
cherry-pick onto main and re-cut.

### 4. Update cross-platform docs

- **compatibility-matrix.md**: add the new version to the matrix,
  list which versions of each other platform it is tested against.
- **SECURITY.md**: if the release fixes a security issue, update the
  advisory section with the CVE ID (if any), affected versions, and
  the fix commit.
- **ROADMAP.md**: check off completed items, adjust upcoming ones.

### 5. Publish a release candidate

Tag and push:

```bash
git tag citadel/v1.1.0-rc.1
git push origin citadel/v1.1.0-rc.1
```

The RC tag triggers CI to build and publish a pre-release container
(`ghcr.io/opensecstack/citadel:1.1.0-rc.1`) and a GitHub pre-release.

### 6. RC soak period

Minimum soak time:

- Patch: 24 hours
- Minor: 3 business days
- Major: 2 weeks
- Ecosystem release: 4 weeks

During soak, the RC is deployed to a staging environment that mirrors
a realistic production shape. Issues found in soak are fixed in the
release branch and produce a new RC (`rc.2`, `rc.3`, …). Never ship
without at least one successful soak run.

### 7. Cut the final tag

After soak:

```bash
git tag citadel/v1.1.0
git push origin citadel/v1.1.0
```

CI builds the final image and publishes the GitHub release, with
release notes generated from the CHANGELOG section.

### 8. Merge release branch back

```bash
git checkout main
git merge --no-ff release/citadel-v1.1.0-rc
git push origin main
```

Delete the release branch after merge.

### 9. Announce

- GitHub release populated with notes.
- Status page or release RSS feed updated.
- For ecosystem releases: long-form announcement on the website and
  in the community meeting (see [community/MEETINGS.md](../community/MEETINGS.md)).
- For security releases: follow the security advisory process below.

## Semantic versioning rules

Each platform follows [semver.org](https://semver.org):

| Change | Bump |
|---|---|
| Bug fix, docs only, internal refactor | patch (`1.0.0` → `1.0.1`) |
| New feature, backwards-compatible | minor (`1.0.0` → `1.1.0`) |
| Breaking API change, config rename, schema migration that drops data | major (`1.x.y` → `2.0.0`) |

Interpretation notes:

- **New migration** alone is not a breaking change. Migration that
  removes a column is.
- **New config knob** is not breaking. Renamed or removed knob is.
- **New HTTP endpoint** is not breaking. Changed or removed endpoint is.
- **New JSON field on response** is not breaking if consumers are
  tolerant. Removed or renamed field is.

When in doubt, bump the higher version — over-bumping is cheap,
under-bumping erodes trust.

## Security advisory process

Security fixes follow a compressed version of the above:

1. **Report arrives** via security@opensecstack.org or encrypted
   channel (see [SECURITY.md](../SECURITY.md)).
2. **Private branch** cut immediately (`security/citadel-cve-2026-...`).
3. **Fix + regression test**, reviewed by at least two security team
   members.
4. **Co-ordinated disclosure window** — 14 days default for critical,
   30 for non-critical.
5. **Release on disclosure day** — RC skipped, direct to tagged
   version with "security patch" note in CHANGELOG.
6. **CVE published** via GitHub Security Advisories after release.
7. **Affected-version matrix updated** in the advisory.

See [SECURITY.md § Reporting a vulnerability](../SECURITY.md) for the
full reporting workflow.

## Ecosystem release process (semi-annual)

Two additional steps on top of the per-platform process:

### Freeze

4 weeks before the target date, main branches freeze for non-critical
changes across all platforms. Critical fixes still land; minor
features defer to the next ecosystem release.

### Compat-matrix reconciliation

- Every platform cuts a minor or patch release before the cut-off
  date.
- compatibility-matrix.md lists the specific versions tested together
  for this ecosystem release.
- A **full ecosystem integration test** runs: every platform deployed
  together, a synthetic incident walked end-to-end through APIGuard
  → IRFlow → CITADEL → NIS2 Compass → ThreatFlow.

The ecosystem release tag (`ecosystem/v1.0.0-2026-Q2`) points at a
specific commit on each platform; deployers can reproduce the tested
stack exactly.

## PR checklist items that feed into this

Every contributing doc includes a release-facing checklist item. At
minimum:

- [ ] CHANGELOG.md `[Unreleased]` section updated.
- [ ] If this is a breaking change, note under "Breaking changes" in
      `[Unreleased]`.
- [ ] Migration path documented if config/schema changed.
- [ ] ADR filed if decision surface is new.

The release step #2 (CHANGELOG update) is a no-op rename from
`[Unreleased]` → `[1.1.0]` — the content is already correct because
every merged PR contributed to it.

## Rollback policy

A released version is immutable. If a bug is found post-release:

1. **Patch release** with the fix (`1.1.0` → `1.1.1`).
2. Deployers are advised to upgrade; they can choose not to.
3. The bad version stays in the registry — downgrade is valid.

We never yank a published release. Auditors and regulators may
reference a specific version, and retroactively removing it breaks
their citations.

## Ownership

Per [CODEOWNERS](../.github/CODEOWNERS):

- Platform releases: platform maintainer team + core maintainers
- Security releases: security team + core maintainers
- Ecosystem releases: core maintainers

All releases require an author + a reviewer; the author cannot be the
sole approver (SoD on the release process itself).

## Related

- [Compatibility matrix](./compatibility-matrix.md) — version pairing rules
- [Deprecation policy](./deprecation-policy.md) — how features retire
- [CODEOWNERS](../.github/CODEOWNERS) — who approves what
- [SECURITY.md](../SECURITY.md) — security-release details
- [GOVERNANCE.md](../GOVERNANCE.md) — who decides when releases happen
