# Module 2: Quiz & Assessment Engine

> Status: scaffold. Implementation lives in `internal/quiz/` and the
> React quiz UI lives in `web/src/quiz/`. This document covers design
> intent for v1.0.0. Concrete code references land as the directories
> populate.

## Overview

The Quiz & Assessment Engine delivers in-lesson assessments, scores
attempts, enforces attempt limits and time budgets, and reports
pass/fail back to Module 1 (Learning Path Engine) so the lesson
completion gate can be evaluated. Results are persisted as evidence
records; passing results contribute to the `completions` row written
by Module 1.

Quizzes are optional per lesson (`lessons.has_quiz`). When present,
a passing quiz attempt is a prerequisite for `mark_complete`.

## Question types

Three question types are supported in v1.0.0. All types are stored
in question bank YAML files under `content/<track-slug>/quizzes/`.

### MCQ (multiple-choice question)

Single correct answer from a list of options. Distractors are
plausible and reviewed by a subject-matter peer. The `randomise` flag
in the quiz manifest controls whether option order is shuffled per
attempt.

```yaml
# content/nis2-awareness/quizzes/01-scope.yaml
questions:
  - id: q1
    type: mcq
    stem: "Which NIS2 Article 21(2) measure covers incident handling?"
    options:
      - id: a
        text: "(a) Risk analysis and information system security policies"
      - id: b
        text: "(b) Incident handling"
        correct: true
      - id: c
        text: "(c) Business continuity"
      - id: d
        text: "(g) Cyber hygiene practices and cybersecurity training"
    explanation: >
      Article 21(2)(b) explicitly names incident handling. (g) covers
      training — the primary CyberPath driver — but not incident handling
      directly.
```

### Code-answer

The learner submits a short code fragment or command. The backend
evaluates correctness against a checker function embedded in the
question bank. The checker is a Go function registered by slug; no
arbitrary code execution on the host.

```yaml
  - id: q2
    type: code-answer
    stem: "Write the curl flag that disables certificate verification (do not use this in production)."
    checker: curl_insecure_flag
    answer_language: shell
    max_length: 64
```

The `checker` value is a key in the registered checker registry
(`internal/quiz/checkers.go`). Checkers are pure Go functions:

```go
// internal/quiz/checkers.go (design intent)
var Checkers = map[string]CheckerFunc{
    "curl_insecure_flag": func(answer string) bool {
        answer = strings.TrimSpace(answer)
        return answer == "-k" || answer == "--insecure"
    },
}
```

New checkers require a Go change + code review; they cannot be
injected via YAML alone. This prevents content-supplied code
execution.

### Scenario

A longer-form question that presents a scenario description (can
include a code block, log excerpt, or PCAP summary) and expects one
of: MCQ selection, a free-text short answer scored by keyword
matching, or a ranked ordering of steps.

```yaml
  - id: q3
    type: scenario
    stem: |
      A learner receives the following email header snippet.
      Identify the most likely phishing indicator.

        Return-Path: <noreply@micros0ft-support.com>
        From: "Microsoft Support" <support@microsoft.com>

    subtype: mcq
    options:
      - id: a
        text: "The From display name is generic"
      - id: b
        text: "The Return-Path domain does not match the From domain"
        correct: true
      - id: c
        text: "The email uses TLS"
      - id: d
        text: "The sender claims to be Microsoft"
    explanation: >
      The Return-Path domain (micros0ft-support.com, note the zero)
      differs from the visible From domain. This is a common spoofing
      indicator. The display name being generic is weak evidence on its own.
```

Scenario questions with `subtype: free-text` use keyword lists for
scoring; at least N of M keywords must be present (configurable per
question). Free-text scoring is not AI-assisted in v1.0.0 — keyword
matching only.

## Question bank format

Each quiz manifest (`quizzes/*.yaml`) has:

```yaml
id: 01-scope
lesson_id: scope          # maps to lesson slug
pass_threshold: 0.70      # 70% correct to pass
randomise: true           # shuffle question order per attempt
time_limit_seconds: 600   # 10 minutes; 0 = no limit
attempt_limit: 3          # 0 = unlimited
questions:
  - ...
```

`pass_threshold` is a ratio (0.0–1.0). MCQ and code-answer questions
are binary (correct/incorrect). Scenario-free-text questions earn
partial credit (fraction of keywords matched).

## Grading logic

Score calculation (all question types weighted equally in v1.0.0):

```
raw_score = sum(question_scores) / question_count
pass      = raw_score >= pass_threshold
```

Individual question scores:
- MCQ: 1.0 if correct, 0.0 if not
- Code-answer: 1.0 if checker returns true, 0.0 otherwise
- Scenario-MCQ: 1.0 if correct, 0.0 otherwise
- Scenario-free-text: keywords_matched / keywords_required (capped at 1.0)

The graded result is stored immediately in `quiz_attempts` regardless
of pass/fail. Partial credit from free-text questions is reflected in
`attempt_score`.

## Attempt limits

When `attempt_limit > 0`, the engine rejects a new attempt if the
learner has already made `attempt_limit` attempts for this quiz in the
current enrolment context.

If the learner exhausts attempts without passing, the lesson remains
in the `progress` state and they cannot call `mark_complete`. An
instructor can grant additional attempts via the instructor review
endpoint (see below). The learner sees a `attempts_exhausted` error
with a link to request review.

## Randomisation

When `randomise: true`, the engine computes a per-attempt seed from
`sha256(quiz_id || user_id || attempt_number)` and uses it to
deterministically shuffle question order and MCQ option order. This
means:

- Two learners see different orderings.
- The same learner retrying sees a different ordering each attempt.
- The ordering is reproducible from the attempt record (no need to
  store the shuffled sequence — the seed reconstructs it).

## Time limits

The time limit is enforced server-side. The attempt start timestamp
is recorded in `quiz_attempts.started_at`. On answer submission, the
engine checks `now() - started_at > time_limit_seconds`. If exceeded,
the submission is rejected with `time_limit_exceeded` and the attempt
is marked failed (score 0.0).

The frontend starts a countdown from `time_limit_seconds` and submits
automatically when it hits zero. This is belt-and-suspenders; the
server check is authoritative.

## Anti-cheat hooks

v1.0.0 anti-cheat measures are proportional to the threat model
(online self-paced professional training, not high-stakes
certification examinations):

1. **Server-side time enforcement.** Answer submission after the time
   limit is rejected; the clock is the server clock, not the client's.
2. **Seed-based randomisation.** Copy-pasting a fixed answer set from
   one attempt does not help if question or option order changed.
3. **Attempt logging.** Every attempt is logged with `started_at`,
   `submitted_at`, `ip_hash` (SHA-256 of the source IP; not the raw
   IP, for privacy), and `user_agent_hash`. Anomalously fast
   completions (< 10% of `time_limit_seconds`) are flagged in the
   `quiz_attempts.anomaly_flags` JSONB column for instructor review.
4. **Question bank size.** Tracks with ≥3 quiz questions per lesson
   are recommended to have ≥2× the minimum question count, so
   randomisation draws a question subset (v1.1 candidate; not in
   v1.0.0).

No webcam, no browser lockdown. These are out of scope for v1.0.0 and
would require explicit operator opt-in given the professional training
context.

## Database schema

### `quiz_definitions`

```sql
CREATE TABLE quiz_definitions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lesson_id        UUID NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    bank_ref         TEXT NOT NULL,           -- path to quizzes/*.yaml relative to content root
    pass_threshold   NUMERIC(3, 2) NOT NULL,
    randomise        BOOLEAN NOT NULL DEFAULT true,
    time_limit_s     INTEGER NOT NULL DEFAULT 0,
    attempt_limit    INTEGER NOT NULL DEFAULT 3,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (lesson_id)
);
```

### `quiz_attempts`

```sql
CREATE TABLE quiz_attempts (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    quiz_id          UUID NOT NULL REFERENCES quiz_definitions(id),
    attempt_number   INTEGER NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    submitted_at     TIMESTAMPTZ,
    attempt_score    NUMERIC(5, 4),           -- 0.0000–1.0000
    passed           BOOLEAN,
    time_exceeded    BOOLEAN NOT NULL DEFAULT false,
    ip_hash          TEXT,
    user_agent_hash  TEXT,
    anomaly_flags    JSONB NOT NULL DEFAULT '{}',
    answers          JSONB NOT NULL DEFAULT '[]', -- ordered list of {question_id, answer}
    UNIQUE (user_id, quiz_id, attempt_number)
);
```

`answers` is stored for audit and instructor review. It contains the
learner's submitted answers verbatim; the graded per-question scores
are in `quiz_attempt_details` (one row per question per attempt) to
support granular review without parsing JSONB at query time.

### `quiz_attempt_details`

```sql
CREATE TABLE quiz_attempt_details (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_id    UUID NOT NULL REFERENCES quiz_attempts(id) ON DELETE CASCADE,
    question_id   TEXT NOT NULL,             -- from the YAML bank
    question_type TEXT NOT NULL,
    answer_given  TEXT,
    score         NUMERIC(5, 4) NOT NULL,    -- per-question score
    correct       BOOLEAN NOT NULL
);
```

## API contract

### Start a quiz attempt

```
POST /api/v1/quizzes/{quiz_id}/attempt
Authorization: Bearer <token>

200 OK
{
  "attempt_id":           "uuid",
  "attempt_number":       1,
  "question_count":       5,
  "time_limit_seconds":   600,
  "started_at":           "2025-05-06T10:00:00Z",
  "questions": [
    {
      "id":      "q1",
      "type":    "mcq",
      "stem":    "...",
      "options": [{"id": "b", "text": "..."}, ...]
    }
  ]
}

409 Conflict — attempts_exhausted
{
  "error":           "attempts_exhausted",
  "attempt_limit":   3,
  "attempts_used":   3
}
```

The response includes the (possibly shuffled) question list. Correct
answers are never included in the response body.

### Submit answers

```
POST /api/v1/quizzes/attempts/{attempt_id}/submit
Authorization: Bearer <token>
Content-Type: application/json

{
  "answers": [
    {"question_id": "q1", "answer": "b"},
    {"question_id": "q2", "answer": "-k"},
    {"question_id": "q3", "answer": "b"}
  ]
}

200 OK
{
  "attempt_id":     "uuid",
  "score":          0.8667,
  "passed":         true,
  "pass_threshold": 0.70,
  "question_results": [
    {"question_id": "q1", "correct": true,  "score": 1.0},
    {"question_id": "q2", "correct": true,  "score": 1.0},
    {"question_id": "q3", "correct": false, "score": 0.6}
  ]
}

409 Conflict — time_limit_exceeded
{
  "error": "time_limit_exceeded"
}
```

### Get attempt history for a quiz

```
GET /api/v1/quizzes/{quiz_id}/attempts
Authorization: Bearer <token>

200 OK
{
  "quiz_id": "uuid",
  "attempts": [
    {
      "attempt_id":     "uuid",
      "attempt_number": 1,
      "score":          0.60,
      "passed":         false,
      "submitted_at":   "2025-05-06T10:02:15Z"
    }
  ]
}
```

## Instructor review flow

Instructors have the `role: instructor` claim in their session token.
Instructor-specific endpoints:

### Grant additional attempt

```
POST /api/v1/admin/quiz-attempts/grant
Authorization: Bearer <instructor-token>
Content-Type: application/json

{
  "user_id":  "uuid",
  "quiz_id":  "uuid",
  "reason":   "Technical issue prevented normal submission"
}

200 OK
{
  "new_attempt_limit": 4,
  "granted_by":        "instructor-uuid",
  "granted_at":        "2025-05-06T11:00:00Z"
}
```

The grant is recorded in `quiz_attempt_grants` for audit. Grants do
not modify `quiz_definitions.attempt_limit` — they are per-learner
overrides.

### Review flagged attempts

```
GET /api/v1/admin/quiz-attempts/anomalies?quiz_id={uuid}
Authorization: Bearer <instructor-token>

200 OK
{
  "attempts": [
    {
      "attempt_id":     "uuid",
      "user_id":        "uuid",
      "anomaly_flags":  {"fast_submit": true, "elapsed_seconds": 12},
      "score":          1.0,
      "submitted_at":   "..."
    }
  ]
}
```

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `quiz_not_found` | 404 | Quiz UUID does not exist |
| `attempt_not_found` | 404 | Attempt UUID does not exist |
| `attempts_exhausted` | 409 | Attempt limit reached; instructor grant required |
| `time_limit_exceeded` | 409 | Submission arrived after the server-side deadline |
| `attempt_already_submitted` | 409 | Double-submit on the same attempt UUID |
| `answer_too_long` | 422 | Code-answer exceeded `max_length` |

## Observability

- `cyberpath_quiz_attempts_total` — counter, labels: `track_slug`, `passed`
- `cyberpath_quiz_pass_rate` — gauge, labels: `quiz_id`
- `cyberpath_quiz_time_exceeded_total` — counter, labels: `quiz_id`
- `cyberpath_quiz_anomaly_flags_total` — counter, labels: `flag_type`

## See also

- [module-1-learning-path.md](module-1-learning-path.md) — lesson completion gate
- [module-5-certification.md](module-5-certification.md) — quiz scores used in certification eligibility
- [architecture.md](architecture.md) — system topology
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
