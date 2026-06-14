# Module 3: Docker-Based Labs

> Status: scaffold. Implementation lives in `internal/lab/docker/`
> and the xterm.js terminal UI lives in `web/src/terminal/`. This
> document covers design intent for v1.0.0. Docker labs are the
> bridge runtime; they are superseded by Module 4 (Wasm Sandbox Labs)
> for all lab classes that do not require a full Linux userspace.
> See `docs/wasm-sandbox.md` for the rationale.

## Overview

Docker-based labs run a per-session Docker container that the learner
reaches through an xterm.js browser terminal relayed over WebSocket by
the CyberPath API. The lab lifecycle is: start, interact (WebSocket
relay), reset (optional), expire (timeout) or stop (learner action).
Challenge validation runs a check script inside the container;
pass/fail is reported back to Module 1.

Docker labs are intentionally out of scope for the v1.0.0 security
audit (per `docs/security/pentest-scope.md`). They remain for Track 7
(Linux hardening) where a genuine Linux userspace is required. All
other tracks migrate to Wasm labs in v1.0.0.

## Lab lifecycle

```
        ┌──────────┐
        │  created │  (lab_sessions row inserted, container not yet running)
        └────┬─────┘
             │ POST /api/v1/labs/start
             ▼
        ┌──────────┐
        │  running │  (container up, WebSocket relay active)
        └────┬─────┘
         ┌───┼──────────────┬──────────────┐
         │   │              │              │
   reset │   │ stop         │ expire       │ challenge-pass
         ▼   ▼              ▼              ▼
    ┌──────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │reset │ │ stopped  │ │ expired  │ │ validated│
    └──┬───┘ └──────────┘ └──────────┘ └──────────┘
       │ back to running
       ▼
    ┌──────────┐
    │  running │
    └──────────┘

  Terminal states: stopped, expired, validated
  All terminal states trigger container teardown and cleanup.
```

State is stored in `lab_sessions.status`. Transitions are enforced
server-side.

## Lab definition

Each lab is defined in `content/<track-slug>/labs/<lab-id>.yaml`:

```yaml
id: linux-hardening-cis-1
runtime: docker
image: ghcr.io/opensecstack/cyberpath-labs/linux-hardening-cis-1:2.1.0
image_digest: sha256:a3f7e2d9...    # pinned; pulled by digest only
title_en: "CIS Benchmark Hardening Exercise"
title_sq: "Ushtrimi i forcimit sipas CIS Benchmark"
track: linux-hardening
session_timeout_seconds: 3600       # 60 minutes
reset_allowed: true
max_resets: 3
challenge_script: /lab/check.sh    # path inside the container
resource_limits:
  cpu_quota: 100000                 # 100% of one core (Docker cpu-quota)
  cpu_period: 100000
  memory: 512m
  pids: 256
ports: []                           # no ports exposed to learner in v1.0.0
```

`image_digest` is the load-bearing field. The API pulls by digest; the
tag is informational only. Images are pushed to the GHCR registry and
pulled on demand (with local daemon caching).

## Container isolation

Each lab session runs in its own container. Network isolation:

- Containers are attached to a dedicated `cyberpath-labs` bridge
  network — no default bridge.
- Internet egress is blocked at the network level by default
  (`--network` references a bridge with no external routing unless
  the lab manifest explicitly lists required egress).
- No host bind-mounts. Lab fixtures are baked into the image.
- No privileged mode. Labs that need elevated capabilities list them
  explicitly in the manifest:

```yaml
resource_limits:
  cap_add: ["NET_ADMIN"]  # only for labs that specifically require it
  cap_drop: ["ALL"]        # always drop all first, then add back only what is needed
```

- Seccomp default profile applied (Docker default). Labs that need
  additional syscalls document them and go through extra review
  (SECURITY.md).

## Resource limits

Applied via Docker's `HostConfig` at container start. The manifest
defaults above apply if not overridden per-lab. Hard enforcement at
the daemon level — not guest-cooperative.

| Limit | Default | Purpose |
|---|---|---|
| CPU quota | 100% of 1 core | Prevent CPU starvation of other sessions |
| Memory | 512 MB | Prevent OOM cascade |
| PIDs | 256 | Prevent fork bombs |
| Session wall-clock | 60 minutes | Container killed at expiry |
| Resets | 3 | Learner can reset to clean state up to 3 times |

Resource metrics (CPU, memory, net I/O) are sampled every 30 seconds
from the Docker stats API and stored in `lab_sessions.resource_metrics`
as JSONB. This populates the resource metrics view in the instructor
dashboard.

## Port mapping strategy

v1.0.0 does not expose per-container ports to learners. The learner
interacts only through the WebSocket-relayed terminal (xterm.js).

Labs that need a web UI (e.g. a vulnerable web application the learner
scans) use a container-internal HTTP server; the API acts as a reverse
proxy at a fixed subpath (`/lab-proxy/{session_id}/`) authenticated by
session token. This avoids ephemeral port allocation on the host and
keeps the perimeter clean.

Port-proxy support is a v0.5.0 milestone; v1.0.0 is terminal-only.

## Health checks

Two health check layers:

1. **Docker health check** (defined in the lab image `Dockerfile`):
   runs every 30 s. If the container health state becomes `unhealthy`,
   the session is moved to `error` state and the learner is offered a
   reset or a new session.

2. **API-side ping**: the WebSocket relay pings the container every 60 s
   by sending a no-op command to the lab shell. If the container does
   not respond within 10 s, the session is marked `error`.

Health state is surfaced to the frontend via a `session_health` field
on the WebSocket metadata channel (a separate JSON channel multiplexed
over the same connection, not raw terminal output).

## Cleanup jobs

A background goroutine in `internal/lab/docker/cleanup.go` runs every
60 seconds and:

1. Queries `lab_sessions WHERE status = 'running' AND started_at <
   now() - interval '...'` to find expired sessions.
2. Calls `docker stop --time=10 <container_id>` for each.
3. Calls `docker rm <container_id>` after stop.
4. Updates `lab_sessions.status` to `expired` and records `ended_at`.

Sessions in `stopped` or `validated` state that still have a live
container (crash-recovery scenario) are also cleaned up on the same
pass.

The cleanup goroutine drains within 10 s on API shutdown (same
pattern as the CITADEL emitter in `internal/citadel/`).

## Lab state persistence

The container filesystem is ephemeral — it is lost on stop or reset.
Persistence is intentional: labs are designed to be completable in a
single session.

If a learner needs to resume (browser closed, session expired), they
start a fresh session. Long-form labs (Track 3 Secure coding is 8
hours) break the work into short checkpoint lessons; each lesson is
a separate short lab rather than one long container session. This
sidesteps the resume problem and also reduces the blast radius of a
session crash.

The learner's quiz answers and lesson progress (Module 1) are
persisted in PostgreSQL and are unaffected by container teardown.

## Challenge validation

When the learner clicks "Check my work", the API runs the challenge
script inside the running container:

```go
// internal/lab/docker/validate.go (design intent)
func RunChallengeScript(ctx context.Context, containerID string, scriptPath string) (bool, error)
// Executes scriptPath inside the container via docker exec.
// Returns (passed, err). Stdout/stderr of the script are logged.
// Script exit code 0 = pass; non-zero = fail.
```

The challenge script is baked into the lab image at `/lab/check.sh`.
Its stdout is returned to the learner as feedback (kept to ≤2 KB to
avoid leaking excessive solution hints).

On pass:
1. `lab_sessions.status` → `validated`
2. `lab_sessions.ended_at` → now()
3. `POST /api/v1/lessons/{lesson_id}/lab-complete` called internally
   to update the lesson sub-item state (Module 1 gate).
4. Container teardown scheduled (10 s grace for the WebSocket to drain).

On fail:
- Status remains `running`.
- Learner sees the script feedback and may continue working.

## Database schema

### `lab_definitions`

```sql
CREATE TABLE lab_definitions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lab_slug        TEXT NOT NULL UNIQUE,
    runtime         TEXT NOT NULL CHECK (runtime IN ('docker', 'wasmtime')),
    image_ref       TEXT NOT NULL,
    image_digest    TEXT NOT NULL,
    title_en        TEXT NOT NULL,
    title_sq        TEXT NOT NULL,
    session_timeout INTEGER NOT NULL DEFAULT 3600,
    reset_allowed   BOOLEAN NOT NULL DEFAULT true,
    max_resets      INTEGER NOT NULL DEFAULT 3,
    manifest        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### `lab_sessions`

```sql
CREATE TABLE lab_sessions (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id        UUID NOT NULL REFERENCES lessons(id),
    lab_id           UUID NOT NULL REFERENCES lab_definitions(id),
    runtime          TEXT NOT NULL CHECK (runtime IN ('docker', 'wasmtime')),
    container_id     TEXT,                    -- Docker container ID (docker runtime only)
    status           TEXT NOT NULL DEFAULT 'created'
                         CHECK (status IN ('created','running','stopped','expired','validated','error')),
    reset_count      INTEGER NOT NULL DEFAULT 0,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at         TIMESTAMPTZ,
    resource_metrics JSONB NOT NULL DEFAULT '[]'
);
```

## API contract

### Start a lab session

```
POST /api/v1/labs/start
Authorization: Bearer <token>
Content-Type: application/json

{
  "lesson_id": "uuid"
}

200 OK
{
  "session_id":           "uuid",
  "ws_url":               "wss://cyberpath.example.org/api/v1/labs/sessions/{session_id}/terminal",
  "session_timeout_at":   "2025-05-06T11:00:00Z",
  "reset_allowed":        true,
  "resets_remaining":     3
}

409 Conflict — active_session_exists
{
  "error":      "active_session_exists",
  "session_id": "uuid"
}
```

### Reset a session

```
POST /api/v1/labs/sessions/{session_id}/reset
Authorization: Bearer <token>

200 OK
{
  "session_id":       "uuid",
  "resets_remaining": 2,
  "new_ws_url":       "wss://..."
}

409 Conflict — reset_limit_reached
{
  "error":         "reset_limit_reached",
  "max_resets":    3
}
```

### Stop a session

```
POST /api/v1/labs/sessions/{session_id}/stop
Authorization: Bearer <token>

204 No Content
```

### Validate (check work)

```
POST /api/v1/labs/sessions/{session_id}/validate
Authorization: Bearer <token>

200 OK
{
  "passed":   true,
  "feedback": "All CIS Level 1 checks passed (42/42)."
}

200 OK (fail)
{
  "passed":   false,
  "feedback": "SSH root login is still enabled. Check /etc/ssh/sshd_config."
}
```

### Get session status

```
GET /api/v1/labs/sessions/{session_id}
Authorization: Bearer <token>

200 OK
{
  "session_id":   "uuid",
  "status":       "running",
  "reset_count":  1,
  "started_at":   "2025-05-06T10:00:00Z",
  "timeout_at":   "2025-05-06T11:00:00Z",
  "health":       "healthy"
}
```

## Error codes reference

| Code | HTTP status | Meaning |
|---|---|---|
| `lab_not_found` | 404 | No lab defined for this lesson |
| `session_not_found` | 404 | Session UUID does not exist |
| `active_session_exists` | 409 | Learner already has a running session for this lesson |
| `reset_limit_reached` | 409 | All resets used |
| `session_expired` | 409 | Session wall-clock exceeded |
| `session_not_running` | 409 | Validate or reset called on a non-running session |
| `image_pull_failed` | 502 | Docker daemon could not pull the lab image |

## Observability

- `cyberpath_lab_sessions_started_total` — counter, labels: `runtime`, `track_slug`
- `cyberpath_lab_sessions_validated_total` — counter, labels: `runtime`, `track_slug`
- `cyberpath_lab_sessions_expired_total` — counter, labels: `runtime`
- `cyberpath_lab_session_duration_seconds` — histogram, labels: `runtime`, `status`
- `cyberpath_lab_active_sessions` — gauge, labels: `runtime`

## See also

- [wasm-sandbox.md](wasm-sandbox.md) — why Wasm supersedes Docker for most labs
- [module-4-wasm-labs.md](module-4-wasm-labs.md) — Wasm lab module
- [module-1-learning-path.md](module-1-learning-path.md) — lab as lesson sub-item
- [architecture.md](architecture.md) — runtime topology
- [../../adrs/ADR-012-cyberpath-platform-strategy.md](../../adrs/ADR-012-cyberpath-platform-strategy.md)
