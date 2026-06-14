# CyberPath Quick Start

Get CyberPath running locally against the v1.0.0 scope (Modules 1–3:
learning path engine, quiz engine, Docker-based labs) in under ten
minutes. No Wasm runtime required; Module 4 (`wasmtime` sandbox)
ships at v1.0.0 and is documented separately.

For full configuration reference, see
[configuration.md](configuration.md). For production deployment, see
[deployment.md](deployment.md).

## What you'll get

By the end of this guide:

- CyberPath Go API on `:8086`
- React + Vite learner UI on `:3006`
- PostgreSQL 16 on `:5439`
- One seeded track (NIS2 Article 21 awareness) with one lesson + one
  quiz
- A learner account, a completion row in Postgres, and (if CITADEL
  is running) a `cyberpath.completion` event in the WORM ledger
- Bilingual UI demo (shqip / anglisht) togglable in-browser

## Prerequisites

- Docker + Docker Compose
- `curl` and `jq` for testing
- (Optional) A running CITADEL instance for WORM evidence emission
- (Optional) A running NIS2 Compass for the coverage demo

## Install

```bash
git clone https://github.com/opensecstack/opensecstack
cd opensecstack/cyberpath

cp .env.example .env
# Minimum: replace CYBERPATH_AUTH_SECRET (≥32 bytes).
# CITADEL is optional — empty CYBERPATH_CITADEL_API_URL starts in
# standalone mode with a loud WARN.

docker compose up -d
```

Wait ~30 seconds for migrations and seed data to apply, then verify:

```bash
curl -sf http://localhost:8086/api/v1/health | jq .
# {
#   "status":  "ok",
#   "db":      "ok",
#   "version": "1.0.0",
#   "modules": {
#     "path":   "active",
#     "quiz":   "active",
#     "lab":    "active (docker)",
#     "cert":   "inactive (v1.0.0)",
#     "wasm":   "inactive (v1.0.0)"
#   },
#   "integrations": {
#     "citadel":     "standalone",
#     "nis2compass": "standalone",
#     "irflow":      "standalone"
#   }
# }
```

## Seed the first track

The bundled seed data ships three tracks (NIS2 Article 21 awareness,
phishing recognition, secure coding). To re-seed from source:

```bash
docker compose exec api cyberpath-cli track import \
  /content/tracks/nis2-art21-awareness/track.yaml
```

`cyberpath-cli track import` validates `track.yaml`, hashes every
lesson revision into `content_versions`, and inserts the track,
modules, lessons, and quizzes. Re-running is idempotent — only new
or changed lesson revisions create new `content_versions` rows.

List the seeded tracks:

```bash
curl -sf http://localhost:8086/api/v1/tracks | jq '.tracks[] | {id, slug, title_en}'
```

Expected:

```json
{ "id": "01HXXX...", "slug": "nis2-art21-awareness", "title_en": "NIS2 Article 21 awareness" }
{ "id": "01HYYY...", "slug": "phishing-recognition", "title_en": "Phishing recognition" }
{ "id": "01HZZZ...", "slug": "secure-coding-owasp",  "title_en": "Secure coding (OWASP Top 10)" }
```

## Sign up as a learner

```bash
curl -sf -X POST http://localhost:8086/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email":        "alice@example.test",
    "password":     "correct horse battery staple",
    "display_name": "Alice",
    "locale":       "sq"
  }' | jq .
```

Then log in to receive a JWT:

```bash
TOKEN=$(curl -sf -X POST http://localhost:8086/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@example.test","password":"correct horse battery staple"}' \
  | jq -r .access_token)

echo "$TOKEN" | cut -c1-40   # sanity check
```

The token is HS256, signed with `CYBERPATH_AUTH_SECRET`, valid for
`CYBERPATH_AUTH_TOKEN_TTL` (default 8h). Pass it as
`Authorization: Bearer $TOKEN` for every subsequent call.

## Complete a lesson

Pull the first lesson of the NIS2 Article 21 awareness track:

```bash
LESSON_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/tracks/nis2-art21-awareness/modules \
  | jq -r '.modules[0].lessons[0].id')

curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/lessons/$LESSON_ID | jq '{id, title_sq, title_en, content_version_id}'
```

Mark it complete:

```bash
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/lessons/$LESSON_ID/complete \
  -H "Content-Type: application/json" \
  -d '{"time_spent_seconds": 412}' | jq .
```

Expected:

```json
{
  "completion_id":      "01J0...",
  "lesson_id":          "01HX...",
  "content_version_id": "01HX...",
  "score":              1.0,
  "completed_at":       "2026-04-26T11:02:14Z",
  "evidence_hash":      "blake3:8a72...",
  "citadel_emitted":    "queued"
}
```

If CITADEL is configured, the emitter has queued a
`cyberpath.completion` event. Inspect the queue depth:

```bash
curl -sf http://localhost:8086/metrics | grep cyberpath_citadel_queue_depth
```

## Submit a quiz

```bash
QUIZ_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/lessons/$LESSON_ID | jq -r .quiz_id)

curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/quizzes/$QUIZ_ID/submit \
  -H "Content-Type: application/json" \
  -d '{
    "answers": [
      {"question_id": "q1", "choice_ids": ["c2"]},
      {"question_id": "q2", "choice_ids": ["c1","c4"]}
    ]
  }' | jq .
```

Response includes `score`, `passed` (against the quiz's
`pass_threshold`), and a per-question breakdown. A passing quiz
also issues a `completions` row for the lesson.

## Start a Docker lab (Module 3)

Phishing recognition includes a sample-classification lab.

```bash
LAB_ID=$(curl -sf -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/tracks/phishing-recognition \
  | jq -r '.labs[0].id')

curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/labs/$LAB_ID/start | jq .
```

Expected:

```json
{
  "session_id":    "01J0...",
  "runtime":       "docker",
  "ws_url":        "ws://localhost:8086/api/v1/labs/01J0.../terminal",
  "expires_at":    "2026-04-26T13:02:14Z",
  "image":         "opensecstack/cyberpath-lab-phish:1.0.0@sha256:..."
}
```

The browser UI connects to `ws_url` over xterm.js; for CLI-only
testing, any WebSocket client works (e.g. `websocat`).

Stop the session when done:

```bash
curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:8086/api/v1/labs/$LAB_ID/stop | jq .
```

## See the CITADEL event (optional)

If CITADEL is configured, every passing lesson, quiz, or lab
completion produces an async `cyberpath.completion` event. Verify
on the CITADEL side:

```bash
curl -sf "http://citadel.internal:8099/api/v1/events?event_type=cyberpath.completion&subject=user:$(jq -r .sub <<<"$(echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null)")" | jq .
```

The full schema lives in [citadel-integration.md](citadel-integration.md).

## Bilingual UI swap

Open `http://localhost:3006` in your browser. The locale toggle in
the top-right swaps between `sq` (shqip — source language) and `en`
(English — maintained translation). Track titles, lesson markdown,
quiz prompts, and validation messages all swap. Source language is
shqip; English is authored alongside, not machine-translated.

To force a locale via the API:

```bash
curl -sf -H "Authorization: Bearer $TOKEN" -H "Accept-Language: sq" \
  http://localhost:8086/api/v1/tracks/nis2-art21-awareness | jq .title
# "Vetëdija për Nenin 21 të NIS2"

curl -sf -H "Authorization: Bearer $TOKEN" -H "Accept-Language: en" \
  http://localhost:8086/api/v1/tracks/nis2-art21-awareness | jq .title
# "NIS2 Article 21 awareness"
```

## Troubleshooting

### `503 Service Unavailable` from `/api/v1/health`

DB not reachable. Check `docker compose logs db` and confirm
`CYBERPATH_DB_URL` in `.env`.

### Lab `start` returns `runtime_unavailable`

The Docker socket is not mounted into the API container. The
shipped `docker-compose.yml` mounts `/var/run/docker.sock` read-only
on the API; verify it hasn't been edited out.

### `track import` says `content_version mismatch`

Lesson markdown changed but the track's semver in `track.yaml` did
not bump. Either revert the markdown or bump the track version. See
[troubleshooting.md § Content version mismatch](troubleshooting.md).

## Next steps

- Configure for your environment: [configuration.md](configuration.md)
- Deploy single-host: [deployment.md](deployment.md)
- Deploy on Kubernetes: [deployment-helm.md](deployment-helm.md)
- Full API reference: [api.md](api.md)
- Operator FAQ: [faq.md](faq.md)

## See also

- [architecture.md](architecture.md)
- [module-list.md](module-list.md)
- [citadel-integration.md](citadel-integration.md)
- [nis2-integration.md](nis2-integration.md)
- [../README.md](../README.md)
- [../ROADMAP.md](../ROADMAP.md)
