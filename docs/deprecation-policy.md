# Deprecation Policy

Features, APIs, config knobs, and schemas are introduced — and
eventually retired. This document describes how OpenSecStack handles
the retirement: the warning period, the semver treatment, the
docs-side bookkeeping. It applies to every platform in the ecosystem.

For release mechanics, see [release-process.md](./release-process.md).
For version-pair compatibility, see
[compatibility-matrix.md](./compatibility-matrix.md).

## The three phases

Any deprecated-then-removed feature passes through three phases:

```
┌────────────────┐   ┌─────────────────┐   ┌────────────────┐
│   Supported    │→→→│   Deprecated    │→→→│    Removed     │
│  (current)     │   │ (warn period)   │   │   (breaking)   │
└────────────────┘   └─────────────────┘   └────────────────┘
                        min 1 minor           major version
                        min 6 months          bump required
```

### Supported

Default state. No deprecation notice; no removal planned. Users can
build against the feature with confidence.

### Deprecated

The feature still works, but:

- Release notes flag it in the CHANGELOG under **Deprecations**.
- Running code emits a runtime warning on first use (log at `WARN`
  level, with a link to the migration path).
- Docs carry a `> **Deprecated in vX.Y.** <migration note>` banner.
- New code must not use it; PR checklist rejects additions.

Deprecation lasts a **minimum** of:

- 1 minor version (if the feature was minor)
- 6 calendar months
- whichever is **longer**

Longer deprecations are fine. Shorter ones are not permitted without
a security justification.

### Removed

The feature is gone. Code that used it breaks at compile time (Go
SDK), import time (Python SDK), or runtime (HTTP 404 / config error).

Removal always requires a **major version bump** per semver. A
feature cannot be removed in a minor release.

## What counts as a deprecation

Any of these trigger the deprecation process:

| Change | Example |
|---|---|
| HTTP endpoint | `DELETE /api/v1/incidents/archive` → replaced by `PATCH {status:"archived"}` |
| Request/response field | `incident.criticality` → `incident.severity` |
| Config env var | `IRFLOW_WEBHOOK_SECRET` → `IRFLOW_WEBHOOK_<SOURCE>_SECRET` |
| CLI flag | `--legacy-format` removed in favour of `--format=legacy` |
| SDK function | `NewClient(url)` → `NewClient(url, opts...)` |
| Schema column | `incidents.assignee` → moved to separate `incident_assignees` table |
| Event type | `citadel.marshal.refuse` → `citadel.marshal.decision` with outcome field |
| Behaviour change | Default webhook clock skew goes from 10m → 5m |

Internal-only changes (unexported Go functions, private modules,
undocumented behaviours) do not require deprecation. The contract
is with *documented* interfaces.

## Marking a deprecation

### In code

Every deprecation has three code-level markers:

**Go:**

```go
// Deprecated: use NewClient with WithBaseURL option instead. This
// function will be removed in v2.0.0 (scheduled 2027-01).
func NewClientLegacy(url string) *Client { ... }
```

**Python:**

```python
import warnings

class IRFlowClient:
    def __init__(self, ...):
        ...

    def submit_legacy(self, ...):
        """...
        .. deprecated:: 1.2
           Use :meth:`submit` instead. Will be removed in 2.0.
        """
        warnings.warn(
            "submit_legacy is deprecated; use submit(). "
            "Removal scheduled for v2.0.",
            DeprecationWarning, stacklevel=2,
        )
        return self.submit(...)
```

**TypeScript:**

```ts
/**
 * @deprecated Use `submit()` instead. Removal scheduled for v2.0.
 */
export function submitLegacy(...) { ... }
```

**Rust:**

```rust
#[deprecated(since = "1.2.0", note = "use `submit` instead; removal in 2.0")]
pub fn submit_legacy(...) { ... }
```

### In config

Deprecated env vars are still honoured but log a warning:

```
WARN: IRFLOW_WEBHOOK_SECRET is deprecated; set IRFLOW_WEBHOOK_<SOURCE>_SECRET instead. Removal scheduled for v2.0.
```

### In HTTP responses

```
HTTP/1.1 200 OK
Deprecation: Sun, 01 Jul 2026 00:00:00 GMT
Sunset: Sun, 01 Jan 2027 00:00:00 GMT
Link: <https://docs.opensecstack.org/migrations/v1-to-v2>; rel="deprecation"
```

The `Sunset` header gives clients a machine-readable removal date.

### In docs

A banner at the top of the affected doc section:

```markdown
> **Deprecated in v1.2.** This endpoint will be removed in v2.0.
> Migrate to [PATCH /api/v1/incidents/{id}](./api.md#patch-apiv1incidentsid)
> which accepts `{"status": "archived"}`.
```

### In CHANGELOG

```markdown
## [1.2.0] - 2026-Q3

### Deprecations
- `DELETE /api/v1/incidents/archive` — use `PATCH {status:"archived"}` instead.
  Scheduled removal: v2.0.0.
- `IRFLOW_WEBHOOK_SECRET` — set per-source secrets instead.
  Scheduled removal: v2.0.0.
```

Each entry names the **replacement** and the **planned removal version**.

## Timeline template

For a typical deprecation:

| Phase | Version | Action |
|---|---|---|
| Introduced as deprecated | v1.2.0 | All markers added; docs banner; WARN log |
| Soak period | v1.2.0 → v1.5.0 | Users migrate off at their pace |
| Removal announced | v1.5.0 | CHANGELOG: "will be removed in v2.0.0" |
| Removal | v2.0.0 | Code deleted; docs updated to remove references |
| Migration guide available | before v2.0.0 | `docs/migrations/v1.x-to-v2.0.md` |

## Exceptions

### Security removals

A feature that is actively unsafe can be removed on security
grounds without the full deprecation window:

- Published as a **security advisory** first (GitHub Security
  Advisory + CVE if applicable).
- Removal in a patch release (`1.5.0` → `1.5.1`).
- Replacement feature must exist in the same or prior version.

Example: if `IRFLOW_AUTH_DEV_MODE=true` turned out to be exploitable
in a way that silent-warn couldn't mitigate, we could remove it in a
patch. This is rare — almost every case admits a deprecation path.

### Experimental features

Features marked `// Experimental` at introduction carry no
deprecation obligation. They can change shape or disappear in any
minor release. The `Experimental` marker must be documented and
user-visible (API docs, banner on the page, warning on SDK
function).

We use `Experimental` sparingly — it is not a loophole for
insufficient design. Production docs should treat experimental
features as "do not rely on".

### Non-goals → goals flips

Occasionally, a documented non-goal becomes a goal (e.g. "CITADEL
will never support multi-writer chains" → "CITADEL 2.0 adds sharded
multi-writer chains"). This is not a deprecation; it's an expansion.
No removal window applies.

## How to migrate — the user view

When you see a deprecation warning:

1. **Don't panic.** The feature still works during the deprecation
   window.
2. **Read the release notes** for the version that introduced the
   deprecation — the `Deprecations` section names the replacement.
3. **Test the replacement** in a non-production environment.
4. **Schedule the migration** for your own pace, bounded by the
   announced removal date.
5. **Subscribe to the platform's release feed** (GitHub releases
   page) so removal versions don't surprise you.

Every migration that removes surface produces a `docs/migrations/vX-to-vY.md`
document with:

- List of removed items.
- The new equivalents.
- Worked migration examples.
- A decision tree for edge cases.

The migration guide is a **required deliverable** of any major
version cut — a PR that introduces a v2.0.0 without a migration
guide is incomplete.

## How we track deprecations — the maintainer view

Per-platform:

- Every deprecation entry in CHANGELOG.md is grep-able. Before each
  major release, grep for `Deprecations` across the full CHANGELOG
  history and produce the "items to remove" list.
- Once removed, the CHANGELOG entry stays (history is history) but
  is cross-referenced to the removal version.

Ecosystem-wide:

- [compatibility-matrix.md](./compatibility-matrix.md) tracks "the
  oldest supported version" for each platform. When a version with
  deprecations drops out of support, those deprecations become
  unreachable and can be removed faster than the window minimum
  suggests. This is rare — consumers of old versions still see the
  deprecation warnings and have a right to migrate.

## Related

- [Release process](./release-process.md) — where the CHANGELOG entries land
- [Compatibility matrix](./compatibility-matrix.md) — oldest supported versions
- [SECURITY.md](../SECURITY.md) — security-driven removals
- `docs/migrations/` — per-major-version migration guides (added at each major release)
