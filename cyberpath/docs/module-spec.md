# Module Specification

A module is the smallest unit of structured learning in CyberPath. Each module has theory content, an optional lab, and an optional assessment. Module state per user is tracked in the database and drives the progression unlock logic in `internal/curriculum/progression.go`.

## Full module.yaml Field Reference

```yaml
id: broken-object-level-auth          # unique within the path, used in URLs and DB
title: "API1:2023 Broken Object Level Authorization"
version: "1.1.0"
duration_minutes: 45                  # estimated completion time shown in UI
difficulty: intermediate              # beginner | intermediate | advanced

theory: theory.md                     # relative path to theory content file

prerequisites:
  - path: http-fundamentals           # another path that must be completed first
  - module: intro-to-apis             # sibling module in this path that must be completed first

lab: lab.yaml                         # optional; relative path to lab.yaml
assessment: assessment.yaml           # optional; relative path to assessment.yaml

unlock_policy: sequential             # sequential | parallel
# sequential: user must complete the previous module first
# parallel: module is available as soon as path prerequisites are met
```

## Field Details

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `id` | string | yes | — | Slug; must be unique within the path |
| `title` | string | yes | — | Display name |
| `version` | semver | yes | — | Increment on content changes |
| `duration_minutes` | int | yes | — | Shown in UI; does not enforce a time limit |
| `difficulty` | enum | no | `intermediate` | `beginner`, `intermediate`, `advanced` |
| `theory` | path | yes | — | Relative path to `theory.md` |
| `prerequisites` | list | no | `[]` | Path-level or module-level prerequisites |
| `lab` | path | no | — | Relative path to `lab.yaml` |
| `assessment` | path | no | — | Relative path to `assessment.yaml` |
| `unlock_policy` | enum | no | `sequential` | Controls when the module becomes available |

## Progression Unlock Logic

Progression is evaluated in `internal/curriculum/progression.go` whenever a user completes a module or a lab. The engine checks:

1. All `prerequisites.path` entries are in state `completed` for this user.
2. All `prerequisites.module` entries are in state `completed` for this user.
3. If `unlock_policy: sequential`, the immediately preceding module in `path.yaml`'s `modules` list is `completed`.

When all conditions pass, the module transitions from `locked` to `available`. The engine emits a `module.unlocked` event consumed by the notification service and the frontend progress bar.

## Module States

```
locked → available → in_progress → completed
```

| State | Description |
|---|---|
| `locked` | Prerequisites not yet met; module is visible but not accessible |
| `available` | Prerequisites met; user can start the theory and lab |
| `in_progress` | User has opened theory or started the lab at least once |
| `completed` | Assessment passed (if present) or theory read and lab passed (if no assessment) |

State is stored per user in the `user_module_progress` table. The completion condition depends on what the module contains:

- Theory only: completed when the user marks it read.
- Theory + lab: completed when the lab's pass threshold is reached.
- Theory + assessment: completed when the assessment pass threshold is reached.
- Theory + lab + assessment: completed when both lab and assessment pass thresholds are reached.

## Linking Labs and Assessments

The `lab` and `assessment` fields are relative file paths resolved at build time by the validator (`tests/validate_all_paths_test.go`). At runtime, the module API endpoint returns resolved lab and assessment IDs so the frontend can call the labs and assessment services independently.

Lab scoring feeds into assessment practical questions via `internal/labs/scoring.go`. When a user submits a flag inside the browser terminal, the scoring engine updates the user's objective completion state, which the assessment service reads when grading a practical question. This linkage requires that the lab `id` in `lab.yaml` matches the `lab_id` referenced in `assessment.yaml` for practical questions.
