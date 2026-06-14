# ADR-001: Use YAML + Markdown for all learning content definitions

## Status
Accepted

## Context
CyberPath organizes learning content into paths, modules, labs, and assessments. This content must be version-controlled alongside the application code, easily diffable in pull requests, writable by instructors without engineering support, and validatable at build time to catch schema errors before they reach users.

Four options were evaluated:

- **CMS database** (e.g., Strapi, Contentful): good editing UX but requires a running service, complicates local development, and splits content history from code history.
- **JSON**: machine-friendly but poor authoring ergonomics — no comments, verbose for nested structures, painful to diff in large files.
- **TOML**: readable for flat configs but grows awkward for deeply nested structures like multi-step labs with hints and assessment rubrics.
- **YAML + Markdown**: human-readable, supports comments, handles nested data cleanly, and separates structured metadata from long-form prose naturally.

CyberPath is built for a small authoring team that is comfortable with Git but should not be required to operate a CMS or write JSON by hand.

## Decision
All structured metadata — paths, modules, labs, and assessments — is stored as YAML files under `content/`. Long-form prose (instructions, hints, explanations) lives in companion Markdown files. Content is loaded at application startup by `internal/curriculum/loader.go`, which parses and assembles the full content graph. Schema correctness is enforced by `validate_all_paths_test.go`, which runs in CI on every pull request.

## Consequences
- No GUI content editor is needed for v1.0.0; the authoring workflow is text editor + Git.
- Authors must understand basic YAML syntax; invalid indentation or missing required fields surface as CI failures, not runtime panics.
- All content changes go through standard pull request review, giving maintainers a clear audit trail and the ability to enforce content standards via review policy.
- YAML files diff and merge cleanly in GitHub, making collaborative authoring straightforward.
- The schema validation step in CI catches structural errors early; malformed content never reaches a deployed environment.
- If a GUI editor is added in a future version, it can generate and commit YAML files directly, keeping the same storage format.
