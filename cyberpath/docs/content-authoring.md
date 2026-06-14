# Content Authoring Guide

This guide covers how to write and publish a new learning path in CyberPath. Content lives under `content/paths/` and is versioned in the repository alongside the platform code.

## Directory Layout

Each learning path occupies a subdirectory:

```
content/paths/
  owasp-api-top10/
    path.yaml
    modules/
      01-broken-object-level-auth/
        module.yaml
        theory.md
        lab.yaml          # optional, if module has a lab
        assessment.yaml   # optional
```

## path.yaml Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique slug, e.g. `owasp-api-top10` |
| `title` | string | yes | Display name shown on the path card |
| `description` | string | yes | 1-3 sentence summary, shown in the catalogue |
| `version` | semver | yes | Increment on breaking changes to module order |
| `tags` | list | no | e.g. `[api-security, owasp, beginner]` |
| `prerequisites` | list | no | List of path `id` values that must be completed first |
| `modules` | list | yes | Ordered list of module directory names |
| `certificate` | bool | no | Defaults to `true`; set `false` for preview paths |
| `nis2_measures` | list | no | NIS2 Article 21 measure codes this path satisfies |

```yaml
id: owasp-api-top10
title: "OWASP API Security Top 10"
description: "Hands-on coverage of all ten OWASP API risks with live vulnerable API labs."
version: "1.2.0"
tags: [api-security, owasp, intermediate]
prerequisites: [http-fundamentals]
modules:
  - 01-broken-object-level-auth
  - 02-broken-authentication
  - 03-broken-object-property-level-auth
certificate: true
nis2_measures: [risk-management, incident-handling]
```

## module.yaml Fields

See `module-spec.md` for the full specification. Minimum required fields:

```yaml
id: broken-object-level-auth
title: "API1:2023 Broken Object Level Authorization"
duration_minutes: 45
theory: theory.md
lab: lab.yaml        # omit if no lab
assessment: assessment.yaml  # omit if no assessment
```

## theory.md Conventions

- Use standard ATX headers (`##` for sections, `###` for subsections).
- Callout blocks use the `> [!NOTE]`, `> [!WARNING]`, `> [!TIP]` convention supported by the CyberPath renderer.
- Code blocks must specify the language: ` ```http `, ` ```python `, ` ```bash `.
- Keep paragraphs under 80 words. Prefer bullet points for lists of three or more items.
- Link to external references with `[text](url)` — do not embed images from external CDNs.
- Internal cross-references use relative paths: `[module name](../content/paths/owasp-api-top10/02-broken-auth/theory.md)`.

Example callout:

```markdown
> [!WARNING]
> Never test these techniques against systems you do not own or have explicit written permission to test.
```

## Referencing Lab Environments

Inside `module.yaml`, set the `lab` field to the relative path of `lab.yaml`:

```yaml
lab: lab.yaml
```

The platform resolves the lab type (docker or wasm) from `lab.yaml` at runtime. Modules can reference a shared lab by pointing to a path outside their directory:

```yaml
lab: ../../shared-labs/vampi/lab.yaml
```

See `lab-definition-spec.md` for full `lab.yaml` field documentation.

## Validation

All paths are validated by `tests/validate_all_paths_test.go`. Run before opening a PR:

```bash
go test ./tests/... -run TestValidateAllPaths -v
```

The test checks:

- All required YAML fields are present and correctly typed.
- Module order has no duplicates.
- Referenced `lab.yaml` and `assessment.yaml` files exist.
- `prerequisites` reference valid path IDs.
- `theory.md` exists for every module.

Fix all failures before submission. The CI pipeline will block merge on any validation error.

## PR Checklist for Content Contributions

Before opening a pull request:

- [ ] `go test ./tests/... -run TestValidateAllPaths` passes locally.
- [ ] Theory content reviewed for accuracy and completeness.
- [ ] Lab tested end-to-end: starts, flag is capturable, cleanup runs.
- [ ] Assessment questions reviewed — no ambiguous distractors in multiple-choice.
- [ ] `path.yaml` version bumped if module order changed.
- [ ] No external image embeds in `theory.md`.
- [ ] NIS2 measure codes added if the path supports compliance evidence.
- [ ] PR description states the target audience and estimated completion time.
