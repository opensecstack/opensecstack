# ADR-014: CyberPath ↔ NIS2 Compass Integration Direction

**Status:** Accepted — implemented
**Date:** 2026-07-27
**Deciders:** core-maintainers, cyberpath-platform-team, nis2compass-platform-team
**Supersedes:** —
**Related:** [ADR-012 CyberPath Platform Strategy](./ADR-012-cyberpath-platform-strategy.md), [cyberpath/docs/api.md](../cyberpath/docs/api.md), [cyberpath/internal/nis2/client.go](../cyberpath/internal/nis2/client.go), [nis2compass/docs/integrations.md](../nis2compass/docs/integrations.md)

> **Note on provenance:** this ADR was written by an investigation
> agent, not by a human decision-maker. It documents a contradiction
> found in the repository and lays out options and a recommendation.
> It intentionally does **not** resolve the question — see "Decision"
> below. It is filed in the root `adrs/` directory rather than
> `cyberpath/adrs/` or `nis2compass/adrs/` because it is a
> cross-platform architectural question, and `adrs/` is where ADR-012
> (CyberPath's own platform strategy) already lives; no precedent was
> found for cross-platform integration ADRs being filed under a
> single platform's `adrs/` directory instead.

## Context

CyberPath (security training, Article 21(2)(g) evidence) and NIS2
Compass (Article 21/23 compliance tracking) are documented as
integrating around two concepts: **coverage** (which NIS2 measures a
user's completed training addresses) and **recommend** (which tracks
close a documented gap). The repository currently contains two
mutually incompatible descriptions of how that integration works.

### Version A — NIS2 Compass pulls from CyberPath (documented, and matches CyberPath's own committed decision)

- **[`adrs/ADR-012-cyberpath-platform-strategy.md`](./ADR-012-cyberpath-platform-strategy.md) lines 107–108** (Status: Accepted, Implemented), under "Integrations":
  > NIS2 Compass — `GET /api/v1/cyberpath/coverage/{user_id}` and
  > `GET /api/v1/cyberpath/recommend?gap=<measure>`.

  i.e. NIS2 Compass is the caller; CyberPath exposes read-only `GET`
  endpoints.

- **[`cyberpath/docs/api.md`](../cyberpath/docs/api.md) line 22**:
  > `NIS2 Compass coverage / recommend` — `JWT with service role
  > from NIS2 Compass`

  — an auth row that only makes sense if NIS2 Compass is presenting
  credentials *to* CyberPath, i.e. NIS2 Compass is the caller.

- **`cyberpath/docs/api.md` lines 391–434**, under "NIS2 Compass
  integration (v1.0.0)":
  - `GET /api/v1/coverage/{user_id}` — "Caller is NIS2 Compass."
    (line 397, explicit)
  - `GET /api/v1/cyberpath/recommend?gap=art21_g` — same section,
    same caller.

  Both are `GET` endpoints **served by CyberPath**. This is a pull
  model: NIS2 Compass reaches into CyberPath on demand.

- **`cyberpath/docs/api.md` lines 55–58** (the `/readyz` payload)
  lists `nis2compass` as one of CyberPath's inbound `integrations`
  health checks, consistent with CyberPath being the callee.

### Version B — CyberPath pushes to NIS2 Compass (the actual code)

- **[`cyberpath/internal/nis2/client.go`](../cyberpath/internal/nis2/client.go)** is an *outbound* HTTP
  client. Per its own package doc comment (lines 1–18):
  > Package nis2 — outbound HTTP client. […] Wire in
  > `cmd/server/main.go` via `Options.NIS2Client`.

  It implements two calls, both with **CyberPath as the caller**:
  - `RecommendTracks` (lines 77–101): `POST {baseURL}/api/v1/recommend`
    against NIS2 Compass, signed with a bespoke
    `X-CyberPath-Signature` / `X-CyberPath-Timestamp` HMAC scheme
    (lines 161–167, `sign()` at lines 194–201).
  - `ReportCoverage` (lines 103–123): `POST {baseURL}/api/v1/coverage`
    against NIS2 Compass — the doc comment on `CoverageReport` in
    [`cyberpath/internal/nis2/types.go`](../cyberpath/internal/nis2/types.go) lines 38–39 says this is
    "the body shape pushed to Compass when CyberPath proactively
    reports a user's accumulated coverage."

  This is the reverse of Version A on **every axis**: reverse
  direction (CyberPath calls out, instead of NIS2 Compass calling
  in), reverse HTTP semantics (`POST`/push instead of `GET`/pull),
  reverse path namespace (`/api/v1/recommend` and `/api/v1/coverage`
  on the *NIS2 Compass* host, instead of
  `/api/v1/cyberpath/recommend` and `/api/v1/coverage/{user_id}` on
  the *CyberPath* host), and a different auth/signing scheme
  (`X-CyberPath-*` HMAC headers CyberPath invents and signs, versus
  the "JWT with service role from NIS2 Compass" that `api.md` line 22
  describes).

- These target endpoints **do not exist on the NIS2 Compass side**.
  `nis2compass/app/api/__init__.py` lines 18–27 registers exactly ten
  blueprints — `auth`, `organisations`, `control_templates`,
  `assessments`, `controls`, `artifacts`, `audit_api`, `api_keys`,
  `openapi`, `compliance` — none of which is `recommend` or
  `coverage`.

- **[`nis2compass/docs/integrations.md`](../nis2compass/docs/integrations.md)** is NIS2 Compass's
  canonical, actively-maintained integration guide. It documents
  SIEM, ticketing, BI/dashboard, CI/CD, webhook, and — in detail,
  with a full request/response shape — the sibling **APIGuard**
  integration (lines 283–320). It contains **zero references to
  CyberPath**, confirmed by a full-text grep of `nis2compass/` for
  `cyberpath`/`CyberPath` returning no hits outside
  `client.go`-adjacent test fixtures inside `cyberpath/` itself. If
  `client.go`'s push model were the intended design, this is exactly
  the document where NIS2 Compass would need to describe the
  inbound `/api/v1/recommend` and `/api/v1/coverage` routes it
  would have to expose to receive CyberPath's pushes — and it does
  not.

### Why this matters

These are not two phrasings of the same design — they are opposite
control-flow architectures with different security postures (whose
auth scheme applies, who trusts whom), different failure/backpressure
characteristics (pull lets NIS2 Compass control its own load; push
puts CyberPath in charge of retry/backoff into a partner service —
which `client.go`'s `doSigned` at lines 143–185 does implement, exponential
backoff included, entirely one-sidedly), and different data-ownership
implications (does CyberPath treat coverage as something it reports
proactively, or something Compass queries on demand?). Root
`CLAUDE.md`'s SDK contract table adds a third data point: it lists
`Training Record | JSON v1 | CyberPath → NIS2 Compass, CITADEL` as a
sanctioned contract — a push-shaped description — but no
`TrainingRecord` schema exists anywhere under `sdk/` (confirmed by
search), and `client.go`'s `CoverageReport`/`TrackCompletion` types
are ad hoc Go structs with a hand-rolled HMAC scheme, not an SDK
typed-client contract as `CLAUDE.md`'s own "SDK contracts (the only
sanctioned integration path)" section requires for inter-platform
communication. So even the aspirational description in `CLAUDE.md`
does not match what `client.go` actually implements.

The earlier investigation into `cyberpath/internal/nis2/client.go`
correctly identified this as "an architectural fork" and declined to
write code or guess which side is authoritative — that determination
requires a product decision, not an inference from source code.

## Decision

**Not decided here.** This ADR documents the contradiction and the
options; it is filed as **Proposed**, not **Accepted**, because
resolving it requires a product-level call — most likely by whoever
owns the NIS2 Compass ↔ CyberPath compliance-evidence story
end-to-end — that this investigation is not positioned to make.

## Options

### Option 1 — Adopt the pull model (Version A); delete/rewrite `client.go`

Treat `adrs/ADR-012` and `cyberpath/docs/api.md` as authoritative.
NIS2 Compass calls `GET /api/v1/cyberpath/coverage/{user_id}` and
`GET /api/v1/cyberpath/recommend?gap=<measure>` on CyberPath, using a
service-role JWT it already has the machinery to mint (per `sinauth`
OIDC across the ecosystem). `cyberpath/internal/nis2/client.go`
becomes dead code and should be removed or reduced to a `Health`-only
readiness check (since `/readyz` already reports on `nis2compass`
connectivity, per `cyberpath/docs/api.md` lines 55–58).

- **Pro:** Matches the only two documents that actually describe an
  agreed design (`ADR-012`, `api.md`), both authored specifically for
  CyberPath and both already shipped/Accepted. Lowest-risk change:
  CyberPath's `GET` endpoints presumably already exist (they're
  documented as "live" per `api.md` line 7) and just need an NIS2
  Compass-side caller implemented — which does not yet exist in this
  codebase either (no evidence found of nis2compass code calling out
  to cyberpath).
- **Con:** Someone has to write the NIS2 Compass → CyberPath caller
  (currently missing entirely on that side), which is arguably a
  larger, unbuilt piece of work than deleting `client.go`.

### Option 2 — Adopt the push model (Version B); add the missing NIS2 Compass endpoints and rewrite CyberPath's docs/ADR

Treat `client.go` as authoritative — CyberPath proactively reports
coverage and asks for recommendations by calling *out* to NIS2
Compass. This requires: (a) building `POST /api/v1/recommend` and
`POST /api/v1/coverage` blueprints in `nis2compass/app/api/`,
registering them in `nis2compass/app/api/__init__.py`; (b) deciding
whether NIS2 Compass verifies the `X-CyberPath-Signature` HMAC
scheme `client.go` already signs with, or whether that scheme is
retired in favour of the ecosystem-standard JWT/service-role pattern
used everywhere else; (c) rewriting `ADR-012` §Integrations and
`cyberpath/docs/api.md` §"NIS2 Compass integration" (and
`nis2-integration.md`, referenced but not audited in this pass) to
match; (d) adding CyberPath to `nis2compass/docs/integrations.md`,
following the APIGuard section (lines 283–320) as a template.

- **Pro:** No changes needed to `client.go` itself — it's fully
  implemented, tested (`client_test.go` exists), and includes retry/
  backoff. Reuses the already-written code.
- **Con:** Contradicts the currently-Accepted, Implemented ADR-012 —
  reopening an already-shipped decision. Requires new NIS2 Compass
  server-side work and a bespoke signing scheme that duplicates
  `sinauth`'s JWT machinery, which `CLAUDE.md`'s "Governance & Audit"
  and identity sections treat as the mandatory path
  ("End-user and operator authentication is delegated to sinauth...
  do not... hand-roll an OAuth flow").

### Option 3 — Both directions, for different purposes (hybrid)

Keep the pull model (Version A) for the interactive/read paths
(`recommend` — a learner-facing UI needs synchronous "what should I
take next" answers, which fit a pull/query shape) and adopt a
push model only for asynchronous, eventual-consistency signals
(`coverage`/completion events — arguably a better fit for
CITADEL's existing async evidence-emission pattern, which `ADR-012`
line 75 already describes CyberPath using for
`cyberpath.completion` events to CITADEL). Concretely: NIS2 Compass
pulls `GET /api/v1/cyberpath/recommend`; CyberPath pushes completion/
coverage events via the same CITADEL Kerkese-style async queue it
already builds for CITADEL, rather than a bespoke synchronous POST
client to NIS2 Compass with its own HMAC scheme.

- **Pro:** Each direction is used where its properties genuinely fit
  (query semantics for recommendations, event semantics for
  completions) rather than forcing one shape onto both. Reuses the
  CITADEL emitter pattern CyberPath already has, instead of a third,
  novel signing scheme.
- **Con:** Most design work of the three options — needs a
  genuinely new integration shape (event-based coverage reporting)
  that doesn't fully exist as either documented version today. Highest
  short-term cost, but arguably the most defensible long-term
  architecture given the "Training Record" SDK contract this repo's
  `CLAUDE.md` already aspires to.

## Recommendation

**Option 1**, with Option 3 flagged as the better long-term target if
there is appetite to also formalize the `Training Record` SDK
contract that `CLAUDE.md` already lists but that does not exist yet
under `sdk/`.

Reasoning: Option 1 requires deleting/shrinking unshipped-in-spirit
code (`client.go` is wired per its own doc comment but its target
endpoints have never existed on the NIS2 Compass side, so nothing in
production can be relying on the push path today) rather than
reopening an Accepted, Implemented ADR (ADR-012) and inventing new
server-side surface plus a bespoke HMAC scheme that duplicates
`sinauth`. It is also the option best supported by the weight of
evidence: two independent, already-shipped documents (`ADR-012`,
`cyberpath/docs/api.md`) agree with each other and describe a design
that is at least partially live (CyberPath's `GET` endpoints are
documented as "live" in `api.md` line 7), whereas `client.go`'s
target endpoints are corroborated by nothing on the NIS2 Compass
side. That said, this recommendation should not be treated as final —
whoever owns the compliance-evidence roadmap should confirm whether
the async/event-based shape in Option 3 was already the intended
direction before `client.go` gets deleted, since deleting working,
tested code is itself a cost.

## Consequences if left undecided

`cyberpath/internal/nis2/client.go` continues to exist, tested, and
wired into `cmd/server/main.go`, calling endpoints that return 404 (or
worse, whatever NIS2 Compass's default/catch-all route does) against
a real NIS2 Compass instance in any environment where
`NIS2_BASE_URL`-equivalent config points at a real deployment. Per the
package doc comment (lines 13–16), failures are logged but swallowed
("NIS2 Compass is a best-effort dependency... Callers receive an
error and can degrade gracefully"), so this fails silently rather
than loudly — the exact failure mode that makes contradictions like
this dangerous to leave undocumented in a compliance-evidence path.

## Open questions

1. Does `cyberpath/docs/nis2-integration.md` (referenced from
   `api.md` line 393 as "Full schema") contain a third, more detailed
   description that resolves or deepens this contradiction? Not
   audited in this pass — worth checking before finalizing a
   decision.
2. Is there NIS2 Compass-side code (Python) anywhere that *does* call
   out to CyberPath, which this investigation's grep of
   `nis2compass/` for `cyberpath` (case-insensitive, whole tree)
   failed to surface because of a naming mismatch? Worth a second,
   independent pass before treating "no caller exists" as certain.
3. Does the `Training Record` SDK contract in root `CLAUDE.md`'s
   table reflect a real decision made elsewhere (e.g. in an RFC under
   `rfcs/` not reviewed in this pass), or is it aspirational
   documentation that itself needs to be reconciled once this ADR is
   resolved?

## Implementation note (2026-07-28)

**Option 1 was adopted.** What changed:

### CyberPath (`cyberpath/`)

- **`internal/nis2/client.go`** shrunk to a health-check-only client:
  `RecommendTracks`/`ReportCoverage`, `doSigned`'s retry/backoff, and
  the `X-CyberPath-Signature`/`X-CyberPath-Timestamp` HMAC scheme
  (`sign()`, `canonicalJSON()`) are all removed. Only `New()` and
  `Health(ctx)` (probes NIS2 Compass's `/healthz`) remain.
  `internal/nis2/types.go` (the push-only `GapID`,
  `TrackRecommendation`, `TrackCompletion`, `CoverageReport`,
  `recommendRequest`/`recommendResponse` types) was deleted outright —
  nothing referenced them once the push methods were gone.
  `internal/nis2/client_test.go` was rewritten to cover `Health` only
  (happy path, non-2xx, unconfigured base URL, transport error); the
  old HMAC-signing/retry/4xx-vs-5xx tests for the push methods were
  removed since that code no longer exists.
- The retained `Health` client is not dead code: it is now wired into
  `/readyz`'s `integrations.nis2compass` field (`internal/api/handlers/health.go`'s
  `Readyz` gained a `NIS2HealthChecker` parameter; `cmd/server/main.go`
  only passes a real checker when `CYBERPATH_NIS2COMPASS_API_URL` is
  configured, to avoid permanently reporting "unreachable" in dev).
- **`GET /api/v1/coverage/{user_id}`** already existed as a real,
  DB-backed, tested handler (`internal/api/handlers/coverage.go`'s
  `CoverageHandler.Coverage()`) — it was not a stub needing to be
  built. No changes were needed there beyond removing its now-dead
  `Client *nis2.Client` field.
- **`GET /api/v1/cyberpath/recommend?gap=<measure>`** existed as a
  route but its handler (`CoverageHandler.Recommend()`) was calling
  the push client's `RecommendTracks` against NIS2 Compass — the
  exact broken path this ADR documents. It was rewritten to compute
  recommendations from CyberPath's own published-track catalogue
  (`TrackReader.List`), matching a track's NIS2 measure against the
  requested gap and reporting `"primary"`/`"secondary"` priority based
  on whether the match is the track's content-authored primary NIS2
  mapping (index 0 of `NIS2Refs`, per `internal/content/loader.go`'s
  `flattenNIS2`) or a secondary one. Added `400 unknown_gap` for gaps
  that don't normalise to the `art21.a`..`art21.j` allowlist already
  enforced on track import (`internal/content/validator.go`).
  `audience`/`estimated_minutes`/`lab_required`/`certification` —
  present in `docs/api.md`'s and `docs/nis2-integration.md`'s
  documented response shape — are intentionally **not** returned:
  `db.Track` has no such fields, and fabricating values for them was
  out of scope ("don't invent new business logic"). `docs/api.md` and
  `docs/nis2-integration.md` were updated to describe the shape that
  is actually returned, and to flag which parts of the narrative spec
  remain aspirational (service-role JWT enforcement, `as_of`/
  `audience`/`max_duration_min` query params).
- Tests added/updated in `internal/api/handlers/coverage_test.go`:
  `TestRecommend_NoTracks_ReturnsEmpty`, `TestRecommend_UnknownGap_Returns400`,
  `TestRecommend_MatchesPublishedTracks` (primary vs. secondary
  priority, unrelated tracks excluded). The old `TestRecommend_NoClient`
  (asserted push-client-absent behaviour) was replaced.
- `internal/config/config.go`'s `NIS2Config` dropped the unused
  `APIKey` field (no HMAC secret is signed with anymore).
  `cyberpath/docs/configuration.md`'s NIS2 Compass env-var table was
  corrected to match: `CYBERPATH_NIS2COMPASS_API_URL` is now
  documented as health-check-only; the `CYBERPATH_NIS2COMPASS_TOKEN`
  row (for the removed outbound push auth) was removed.

### NIS2 Compass (`nis2compass/`)

No changes needed. A verification pass confirmed no code, config, or
docs anywhere under `nis2compass/` reference CyberPath, the
`X-CyberPath-*` headers, or the old `/api/v1/recommend`/`/api/v1/coverage`
push paths — consistent with this ADR's original finding that the
receiving routes never existed.

### Root `CLAUDE.md`

The `Training Record | JSON v1 | CyberPath → NIS2 Compass, CITADEL`
row in the SDK contracts table was removed (not "fixed") — see the
table's surrounding note. No `TrainingRecord` schema exists under
`sdk/`, CyberPath's real WORM evidence to CITADEL already flows
through the existing `CITADEL Kerkese` contract row, and CyberPath ↔
NIS2 Compass is plain REST, not an SDK-mediated contract at all.

### Verification

`go build ./...`, `go vet ./...`, and `go test ./...` all pass clean
in `cyberpath/` after these changes. `nis2compass/`'s test suite was
run as a no-op-confirmation (no files changed there).

### Known gaps intentionally left open (out of scope for this ADR)

- `GET /api/v1/coverage/{user_id}` and `GET /api/v1/cyberpath/recommend`
  are reachable by any authenticated JWT, not restricted to a
  `service` role as `docs/api.md` describes (and as would be
  appropriate for a cross-platform pull endpoint exposing another
  user's training/coverage data — a real IDOR-shaped gap, not
  introduced by this change but not fixed by it either). Flagged in
  `docs/api.md`'s auth table; needs its own follow-up.
- `Coverage()`'s response shape (`{user_id, coverage, gaps, generated}`,
  per-track) differs from `docs/nis2-integration.md`'s narrative spec
  (`{user_id, as_of, coverage: [{measure, covered, tracks}]}`,
  per-measure). `Coverage()` is real, live, and tested — reshaping it
  was judged out of scope for an ADR about push-vs-pull direction, and
  is flagged in `docs/nis2-integration.md`'s implementation-status
  note for separate follow-up.

## Review

Resolved: Option 1 adopted and implemented on 2026-07-28 (see
"Implementation note" above). The two known gaps listed there
(service-role enforcement, `Coverage()` response shape vs. the
narrative spec) are explicitly out of scope for this ADR and should be
tracked as separate follow-up work rather than reopening this
decision.
