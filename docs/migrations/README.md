# Migration Guides

Version-to-version migration guides for the OpenSecStack ecosystem.
Each major version cut produces one or more guides in this directory
— they are **written at release time**, never speculatively.

For the release process itself, see [../release-process.md](../release-process.md).
For version-pair compatibility, see [../compatibility-matrix.md](../compatibility-matrix.md).
For the deprecation process that leads to removal, see
[../deprecation-policy.md](../deprecation-policy.md).

## Directory conventions

### Ecosystem-wide migrations

`docs/migrations/vX-to-vY-ecosystem.md` — when a major bump affects
multiple platforms simultaneously (e.g. shared contract changes,
coordinated breaking changes in an ecosystem release).

### Per-platform migrations

`<platform>/docs/migrations/vX-to-vY.md` — when a major bump is
scoped to one platform. Example path: `citadel/docs/migrations/v1-to-v2.md`.

Most major bumps are per-platform; ecosystem-wide bumps are rare and
coordinated events.

## When a guide is written

A migration guide is a **required deliverable** of its corresponding
major version. A PR that cuts a v2.0.0 tag without a migration guide
is incomplete — CI fails the release-check workflow if the file is
missing.

The sequence during release:

1. Release branch cut (`release/citadel-v2.0.0-rc`).
2. Migration guide drafted **in the same branch** based on the
   accumulated `[Unreleased]` CHANGELOG entries marked **Breaking**.
3. RC soak period — deployers test the migration guide against a
   staging replica of their production.
4. Guide is iterated based on soak feedback until the tag is cut.
5. Final guide ships with the release.

Writing the guide before v2.0 exists produces fiction — the actual
removals, renames, and config changes are only known when the branch
is cut. Use [TEMPLATE.md](./TEMPLATE.md) at that point.

## What a guide contains

Every migration guide follows [TEMPLATE.md](./TEMPLATE.md) and covers:

- **Breaking changes** — itemised, with a one-line diff of what changed.
- **Migration path** — the specific steps to upgrade. Worked commands,
  not abstract advice.
- **Rollback plan** — can the operator go back to vX if vY bites?
- **Compatibility notes** — interaction with other platforms during
  the transition window.
- **Data migration** — schema changes, data rewrites, estimated
  downtime or zero-downtime pattern.
- **Testing checklist** — what to verify after the upgrade.

## Planned guides (not yet written)

These are stubs — they will be filled in when the corresponding
major version is cut. Linking to them from planning docs is fine;
reading them today returns an "empty — written at v2.0 cut" notice.

| Guide | Corresponds to | Status |
|---|---|---|
| [v1-to-v2-ecosystem.md](#planned) | Ecosystem v2.0 major | Not yet cut |
| `citadel/docs/migrations/v1-to-v2.md` | CITADEL multi-writer chain (v2.0) | Not yet cut |
| `irflow/docs/migrations/v1-to-v2.md` | IRFlow v2.0 | Not yet cut |
| `apiguard/docs/migrations/v1-to-v2.md` | APIGuard v2.0 | Not yet cut |

## Archival

Migration guides from past versions stay in this directory forever.
An auditor reconstructing "what did the deployer have to do to get
from 2028's v3.0 to 2029's v4.0?" should find the answer in this
directory, five years later, verbatim.

Do not delete old migration guides. Do not rewrite them. If an
error is found, add an erratum note at the bottom rather than
altering the original text — deployers may have followed the
original and their records should match.

## Related

- [Release process](../release-process.md)
- [Deprecation policy](../deprecation-policy.md)
- [Compatibility matrix](../compatibility-matrix.md)
- [TEMPLATE.md](./TEMPLATE.md) — skeleton every guide follows
