# Assessment Specification

Assessments validate that a learner understood the module content. They are defined in `assessment.yaml` and graded by the assessment service (`internal/assessment/`). Results feed into module completion, path certificate eligibility, and leaderboard scores.

## Full assessment.yaml Field Reference

```yaml
id: bola-assessment
title: "API1 Assessment: Broken Object Level Authorization"
version: "1.0.0"

pass_threshold: 70          # minimum score percentage to pass
max_attempts: 3             # number of allowed attempts before lockout
retry_cooldown_minutes: 60  # time between attempts after the first failure
show_answers_after_pass: true

questions:
  - id: q1
    type: multiple_choice
    text: "Which HTTP method is most commonly abused in BOLA attacks?"
    points: 10
    options:
      - id: a
        text: "POST"
      - id: b
        text: "GET"
        correct: true
      - id: c
        text: "DELETE"
      - id: d
        text: "PATCH"

  - id: q2
    type: free_text
    text: "Describe in one sentence how object-level authorization should be enforced server-side."
    points: 20
    rubric: rubric.yaml     # relative path to rubric definition

  - id: q3
    type: practical
    text: "Retrieve the order belonging to user ID 2 using the BOLA vulnerability in the running lab."
    points: 30
    lab_id: vampi-bola      # must match the lab id in lab.yaml
    flag_id: flag-bola-1    # must match a flag id in lab.yaml
```

## Question Types

### multiple_choice

Standard single-correct-answer question. The `options` list must have exactly one entry with `correct: true`. The grader in `internal/assessment/grader.go` awards full `points` for the correct answer and zero for any other.

### free_text

Freeform text answer. Grading is rule-based via a rubric file. Rubric rules are evaluated in order in `internal/assessment/rubric.go`:

```yaml
# rubric.yaml
rules:
  - match: "server.side"          # keyword or regex
    weight: 0.5                   # fraction of points awarded if matched
  - match: "object.id"
    weight: 0.5
```

Total score is the sum of matched weights multiplied by the question's `points` value. Rubrics are approximate; use multiple_choice or practical for objective pass/fail grading.

### practical

Practical questions are linked to a running lab by `lab_id` and `flag_id`. The grader calls `internal/labs/scoring.go` to check whether the user has already submitted the correct flag for that lab session. If the flag is captured, full points are awarded. Partial credit for practical questions is not supported — it is all or nothing.

Practical questions require the user to have an active lab session. The assessment UI shows a warning if no active session is found.

## Scoring Rubrics

Rubric files (`rubric.yaml`) live alongside `assessment.yaml`. They are only required for `free_text` questions. The rubric engine (`internal/assessment/rubric.go`) treats each `match` as a case-insensitive regular expression. Award weights must sum to at most 1.0; exceeding 1.0 is clamped to full points.

## Pass Threshold

`pass_threshold` is a percentage (0-100). After grading, the engine computes:

```
score_percent = (total_points_awarded / total_points_possible) * 100
passed = score_percent >= pass_threshold
```

On pass: module state transitions to `completed`, certificate eligibility is re-evaluated.
On fail: attempt count increments. If `max_attempts` is reached, the assessment is locked for the user until an operator resets it via the admin API.

## Retry Policy

- Attempt 1: immediate.
- Attempts 2+: user must wait `retry_cooldown_minutes` since the last failed attempt.
- After `max_attempts` failures: locked; operator reset required via `PUT /admin/assessments/{id}/reset`.

## Interface with Lab Scoring

Practical questions read flag submission state from `internal/labs/scoring.go` at grading time. The scoring engine stores flag capture events in the `flag_submissions` table with `(user_id, lab_session_id, flag_id, captured_at)`. The assessment grader queries this table to determine whether the flag was captured in the current or any recent lab session for that module.

Flag submissions are immutable. Restarting a lab creates a new session but prior captures from the same module attempt remain valid for assessment grading.
