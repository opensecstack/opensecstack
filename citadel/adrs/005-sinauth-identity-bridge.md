---
status: Accepted
date: 2026-07-26
---
# ADR-005: sinauth↔CITADEL identity bridge (Gate 1/Gate 3 AuthN)

## Context

While wiring apiguard to the Ed25519 signature mechanism (ADR-004), a
deeper pre-existing gap surfaced: Gate 1 (`gate1AuthN`) authenticated by
looking up a row in a local `sessions` table (`user_id BIGINT`) — but
nothing in the entire monorepo ever inserted a row into that table
(confirmed by a repo-wide grep). Gate 1 could never pass for a real
request; it only passed in tests because they used a mock `Store`.
Separately, `sessions.user_id` was `BIGINT` while sinauth's real user
identity (`users.id`) is `UUID` — even a functioning session table
couldn't have held a real sinauth identity without a type change.

Research confirmed the fix was straightforward, not speculative: apiguard,
irflow, and threatflow already have working dual-mode auth middleware that
calls `sdk/go/sinauth.Client.VerifyToken` for real, cryptographically
verifying RS256 bearer tokens issued by sinauth (alongside a fallback
HS256 path for their own service tokens). The raw bearer token was not
forwarded past the parsed claims, but is trivially recoverable from the
same request (`r.Header.Get("Authorization")`).

## Decision

### UserID is a string (sinauth UUID) everywhere in the Kerkese contract

`Kerkese.Actor.UserID`, `Verifier.UserID`, `SoD.OperatorUserID`/`VerifierUserID`
changed from `int64` to `string` in `citadel/internal/marshal/types.go` and
`sdk/go/citadel/types.go` (kept byte-identical, enforced by
`TestCanonicalPayloadMatchesSDKFixture` / `sdk/go/citadel/sign_test.go`
sharing the same fixture values). `CanonicalPayload` in both packages uses
the raw string directly instead of `strconv.FormatInt`.

### Gate 1/Gate 3 verify a sinauth token directly — no session table

New `marshal.TokenVerifier` interface, deliberately separate from `Store`
(a crypto/HTTP concern against sinauth, not a database concern):

```go
type TokenVerifier interface {
    Verify(ctx context.Context, token string) (userID, role string, err error)
}
```

Implemented by `internal/auth.SinauthVerifier`, wrapping
`sdk/go/sinauth.Client.VerifyToken` (the same library apiguard/irflow/
threatflow already use in their own middleware). `Engine` takes a
`TokenVerifier` alongside `Store`: `New(store, verifier)`.

`Kerkese` gained `ActorToken`/`VerifierToken` (raw bearer JWT strings).
These are verified then discarded — `gate5WORM` redacts both fields before
archiving the Kerkese into the WORM/`marshal_decisions` payload, since a
bearer token is a short-lived secret, unlike `SigOperator`/`SigVerifier`
(long-term non-repudiation evidence, which are persisted).

`gate1AuthN` verifies `ActorToken` authenticates `Actor.UserID`, and
`gate3NDS` verifies `ActorToken`/`VerifierToken` authenticate
`SoD.OperatorUserID`/`VerifierUserID`. The prior `Actor.Role` /
session-role consistency check was dropped: sinauth's role claim is scoped
per sinauth *client*, not to CITADEL's 5-role taxonomy, so it was never a
meaningful comparison. Gate 2 (`gate2AuthZ`) continues to independently
trust the producer-asserted `Actor.Role` against `rbacMap`, unchanged.

### Both identity and signature checks share one rollout flag

Gate 1/Gate 3 combine the token-verification result and the Ed25519
signature-verification result (ADR-004) into one pass/fail decision, both
gated by the same `EnforceSignatures` flag: in soft mode (default), a
missing/invalid token or signature produces a `WARN` that does not block;
in enforced mode, either failure `REFUSE`s. This was a correction made
during implementation — the original draft made token checks unconditional
hard failures, which would have made every real (unsigned, unauthenticated
verifier) apiguard request REFUSE even in "soft" mode, defeating the
rollout flag's purpose.

The structural SoD invariants — `NDS_SAME_IDENTITY` (operator == verifier)
and `NDS_SAME_GROUP` (same role privilege group) — remain unconditional
`HARD_STOP`s, run *before* the soft-gated identity/signature block: these
are logic bugs if violated, not a rollout concern.

### Schema

`migrations/004_sinauth_identity.sql`: drops the dead `sessions` table;
widens `rate_counters.user_id` and `signing_keys.user_id` (introduced this
session, migration 002, not yet deployed anywhere real) from `BIGINT` to
`TEXT`. `internal/db.ActionCount`'s query drops the `::bigint` cast on
`kerkese->'actor'->>'user_id'` (naturally `TEXT` now).

### Key registration re-anchored to sinauth tokens

`POST /api/v1/keys/register` drops the ADR-004 `session_id` field
(meaningless post-`sessions`-removal) for a `token` field, verified the
same way Gate 1 verifies `ActorToken`: the registrant proves who they are
with a live sinauth token, and the key is bound to that token's `sub`.

### Config

`CitadelConfig.SinauthIssuerURL` (env `CITADEL_SINAUTH_ISSUER_URL`)
constructs the `sinauth.Client` once at startup. `NewServer` now returns an
error and fails fast if the sinauth issuer is unreachable/misconfigured —
an AuthN gate with no way to verify tokens is a worse failure mode than
refusing to start.

### Producer wiring — apiguard only in this pass

`apiguard/internal/api/handlers/scans.go`: `Actor.UserID` now comes from
`middleware.ClaimsFromContext(ctx).Sub` (the real authenticated caller,
same source already used by the existing audit log), and `ActorToken`
forwards the caller's actual `Authorization` header bearer token.

**Explicit scope boundary, not silently glossed over:** apiguard's
scan-initiate flow has no real second-person approval step — `Verifier` is
set to a fixed placeholder identity (`"apiguard-system-verifier"`, distinct
from any real user so it doesn't trip `NDS_SAME_IDENTITY`), not a genuine
second person. `VerifierToken` is left empty. Building a real two-person
approval UX for scan initiation is a product change, out of scope here, and
is safe to defer because `citadel.enforce_signatures` stays at its ADR-004
default (`false`) — the gap is now visible in Gate 1/Gate 3 WARN reasons
instead of being invisible.

irflow's and threatflow's own wiring (real Verifier identity, replacing
irflow's lossy `hashUserID` string→int64 fold, which this ADR's UserID
string type also happens to make unnecessary) is deferred to the same
ADR-004 rollout order — prove the pattern once (apiguard), repeat.

## Testing

- `internal/marshal/marshal_test.go`: `mockTokenVerifier` (token → userID,
  role map) replaces `mockStore.SessionExists`; soft/enforced-mode pairs
  for missing token, invalid token, subject mismatch, matching the existing
  signature-test shape.
- `internal/auth/sinauth_verifier_test.go`: `httptest.Server` serving a
  real OIDC discovery document + JWKS, RSA keypair generated per test,
  hand-built JWTs (`golang-jwt/jwt/v5`) — verifies valid, expired,
  wrong-signing-key, and malformed tokens, entirely offline (no live
  sinauth instance or network access required).
- `internal/api/handlers/keys_test.go`: `fakeVerifier` replaces the
  session-map fake.
- `apiguard/internal/citadel/client_test.go`: `UserID` fixtures updated to
  strings.
- All existing apiguard test suites pass unchanged otherwise.

## Consequences

- Second SDK contract bump on top of ADR-004's, expected: this is what
  grounding identity in a real (string/UUID) source instead of a
  fabricated `int64` space requires.
- CITADEL still has no HTTP-level auth middleware in front of
  `/marshal/evaluate` itself — Gate 1's token check plays that role for the
  Kerkese body's claimed identity, same as before.
- `sessions` and the `SessionExists`/`SessionUserID` code paths are
  deleted, not deprecated — nothing depended on them being live (they never
  worked), so there is nothing to migrate off of.
- irflow's own `hashUserID` lossy int64-folding function becomes
  unnecessary once irflow migrates (its own follow-up work, not done here)
  — a straightforward side benefit of UserID becoming a string.
