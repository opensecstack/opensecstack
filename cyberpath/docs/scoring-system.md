# Scoring System

CyberPath uses a flag-based scoring system for practical labs and an objective-based model for structured progress tracking. All scoring logic lives in `internal/labs/scoring.go`.

## How Flags Work

Flags are tokens that prove a learner achieved a specific objective inside a lab. They are defined in `lab.yaml` under the `flags` key and submitted by the learner via the browser terminal or the flag submission input in the UI.

### Static Flags

A static flag has a fixed string value defined in `lab.yaml`:

```yaml
flags:
  - id: flag-bola-1
    type: static
    value: "CYBERPATH{b0la_unauthenticated_access}"
    points: 50
```

Every learner submits the same string. Static flags are simple but susceptible to flag sharing between learners. Mitigate with per-user salting (see below) or use dynamic flags for high-stakes assessments.

### Dynamic Flags

Dynamic flags are generated at lab-start time by the scoring engine. The value is not stored in `lab.yaml`; instead, the engine computes:

```
flag_value = HMAC-SHA256(key=user_id + lab_session_id + flag_id, data=base_value)
```

The result is base64url-encoded and wrapped: `CYBERPATH{<hash>}`. The correct value is stored in the `flag_submissions` table at session creation and used for comparison when the learner submits.

Dynamic flags cannot be shared between learners because each learner's flag is unique to their session.

## Objective-Based Scoring

Objectives in `lab.yaml` link a human-readable task description to a flag:

```yaml
objectives:
  - id: obj-1
    description: "Retrieve another user's orders via IDOR"
    flag: flag-bola-1
```

The UI displays objectives as a checklist. When the learner submits the correct flag, `scoring.go` marks the objective as completed and updates the session score. This gives structured progress feedback without revealing which specific flag value to submit.

## Partial Credit

If `scoring.partial_credit: true` in `lab.yaml`, learners receive points for each flag they capture even if they do not capture all flags. The session score is the sum of points from captured flags. The pass threshold is evaluated against this sum.

If `partial_credit: false`, the session is pass/fail: all flags must be captured to pass. Partial completion awards zero points for the session (though objective completion is still recorded for progress display).

## internal/labs/scoring.go Walk-Through

Key functions:

- `SubmitFlag(ctx, userID, sessionID, submittedValue)`: Normalizes the submission (trim whitespace, case-fold if the lab is configured for case-insensitive matching), compares against the expected value for each flag in the session, records a `flag_submission` row on match, and calls `UpdateSessionScore`.
- `UpdateSessionScore(ctx, sessionID)`: Recalculates total points from all captured flags and writes to `lab_sessions.score`. Emits a `lab.score_updated` event.
- `GenerateDynamicFlags(ctx, sessionID, userID, flags)`: Called at session start for dynamic flags. Writes expected values to `flag_submissions` with `captured_at = NULL`.
- `GetSessionScore(ctx, sessionID)`: Returns current score, max possible score, and per-objective completion state.

## Leaderboard Integration — not yet implemented

This section describes a planned design, not shipped functionality: there
is no `leaderboard` table, no service subscribing to `lab.score_updated`,
and no `internal/labs/scoring.go`. Session scores are computed and stored
(see above), but nothing yet aggregates or ranks them. The intended
design, once built:

The leaderboard service subscribes to `lab.score_updated` events. It maintains a `leaderboard` table indexed by path and module. Points from practical assessments (via `internal/assessment/`) are also included. The leaderboard is read-only from the scoring engine's perspective.

Leaderboard rankings would be computed as:

```
total_score = sum(lab session scores) + sum(assessment scores)
rank = dense_rank() over (partition by path_id order by total_score desc)
```

## Anti-Cheat: Per-User Flag Salting

Dynamic flags provide inherent anti-cheat protection. For static flags, CyberPath optionally applies per-user salting controlled by the `salt_static_flags` platform configuration option. When enabled:

- At lab session creation, the scoring engine appends a per-user salt to the static flag value before hashing.
- The expected submission value is stored in `flag_submissions` per session, not derived from `lab.yaml` directly.
- Learners who share flag strings with each other cannot use them across different sessions.

Enable in platform config:

```yaml
labs:
  salt_static_flags: true
```

This is recommended for any deployment where leaderboard integrity matters.
