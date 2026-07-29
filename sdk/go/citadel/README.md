# CITADEL Go SDK

Go SDK for submitting governance requests ("Kerkese") to a CITADEL instance's
MARSHAL evaluation engine, and for Ed25519-signing them as the Operator
and/or Verifier before submission.

This package is the canonical Go contract for the Kerkese shape. Field names
and JSON tags mirror `citadel/internal/marshal/types.go` exactly — that file
is the server-side source of truth this package tracks.

> **Status:** new — built for direct MARSHAL integration. It is Go-only
> today (no Python/TypeScript/Rust equivalent yet) and has not shipped in a
> tagged SDK release. It has a unit test suite (`client_test.go`,
> `sign_test.go`) covering the EXECUTE/REFUSE/HARD_STOP response paths and
> canonical-payload signing determinism.
>
> This is a different client from the CITADEL **event/WORM connector**
> (`SendEvent`/`GetEvents`/`VerifyChain`) shipped in
> [`sdk/go/opensecstack`](../opensecstack) — that one delivers arbitrary
> security events to the WORM audit chain. This package instead submits a
> structured Kerkese to MARSHAL for a governance **decision** (gate
> evaluation) before a privileged action proceeds.

## Installation

```bash
go get github.com/opensecstack/sdk/go/citadel
```

## Quick Start: Evaluate

```go
import (
    "context"
    "log"

    "github.com/google/uuid"
    "github.com/opensecstack/sdk/go/citadel"
)

client := citadel.NewClient("https://citadel.internal", nil) // nil httpClient -> 30s timeout default

k := citadel.Kerkese{
    KerkeseVersion: "v2.0",
    TsUTC:          time.Now().UTC(),
    ProjectID:      "apiguard",
    ExecutionID:    uuid.New(),
    Action: citadel.KerkeseAction{
        Type:        "deploy_change",
        Description: "roll out WAF rule update",
        ChangeID:    "CHG-1234",
    },
    Actor:    citadel.KerkeseActor{UserID: operatorSub, Role: "operator"},
    Verifier: citadel.KerkeseVerifier{UserID: verifierSub, Role: "verifier"},
    SoD: citadel.KerkeseSoD{
        OperatorUserID: operatorSub,
        VerifierUserID: verifierSub,
    },
}

decision, err := client.Evaluate(context.Background(), k)
if err != nil {
    // A genuine transport/server failure (network error, 5xx with a
    // non-Decision body, malformed JSON) — NOT a REFUSE/HARD_STOP outcome.
    log.Fatalf("citadel evaluate: %v", err)
}

switch decision.Outcome {
case citadel.OutcomeExecute:
    // proceed with the action
case citadel.OutcomeRefuse, citadel.OutcomeHardStop:
    // MARSHAL blocked the action — decision.Reasons explains why
    log.Printf("blocked: %v", decision.Reasons)
}
```

### Important: HTTP 403 is not an error

MARSHAL returns **HTTP 403** for both `REFUSE` and `HARD_STOP` outcomes.
`Evaluate` treats that as a well-formed `*Decision`, not a Go `error` — a
403 with a body that parses as a `Decision` (non-empty `Outcome`) always
returns `(decision, nil)`. Only a response body that fails to parse as a
`Decision` at all — e.g. a 5xx with a plain-text body, a proxy error page,
or an error envelope like `{"error": "..."}` with no `outcome` field — is
returned as a Go `error`.

In other words: **always check `err` first, then branch on
`decision.Outcome`** — do not treat a non-nil error as "MARSHAL refused"
and a nil error as "MARSHAL executed."

## Signing (Ed25519)

If the target CITADEL instance enforces signature verification (see citadel
ADR-004), populate `Kerkese.SigOperator` and `Kerkese.SigVerifier` with
`Sign` before calling `Evaluate`. `Kerkese.TsUTC` must already be set, since
the timestamp is part of the signed payload:

```go
k.TsUTC = time.Now().UTC()

if err := citadel.Sign(&k, operatorPrivKey, verifierPrivKey); err != nil {
    log.Fatalf("sign kerkese: %v", err)
}

decision, err := client.Evaluate(ctx, k)
```

`Sign` computes `CanonicalPayload(k)` — a deterministic, pipe-joined string
over a fixed, enumerable set of fields (execution ID, action type/change ID,
actor/verifier identities, SoD identities, and the RFC3339 timestamp) — and
signs it with both the operator's and verifier's Ed25519 private keys.
`citadel/internal/marshal/sig.go` produces byte-identical output for the
same `Kerkese`, so signatures created here verify correctly on the server.

### Registering a public key

Before a user's Ed25519 key can be used to sign Kerkese requests, it must be
registered against their CITADEL session:

```go
reg, err := client.RegisterKey(ctx, citadel.KeyRegistration{
    UserID:    userID,
    SessionID: sessionID, // must belong to UserID, or the server returns 403
    KeyID:     "my-device-key-1",
    PublicKey: hex.EncodeToString(pubKey), // 32-byte Ed25519 public key, hex-encoded
})
if err != nil {
    log.Fatalf("register key: %v", err)
}
fmt.Printf("registered %s at %s\n", reg.KeyID, reg.RegisteredAt)
```

## Types

| Type | Description |
|---|---|
| `Kerkese` | The governance payload submitted to MARSHAL for evaluation |
| `KerkeseAction` | The privileged action being requested (type, description, change/incident IDs) |
| `KerkeseActor` | The Operator principal (sinauth `user_id`, role, optional email) |
| `KerkeseVerifier` | The distinct Verifier principal approving the action |
| `KerkeseEvidence` | Supporting artefacts for the request (deliberately excluded from the signed payload — WORM's TripleHash already covers full-payload integrity) |
| `KerkeseSoD` | Separation-of-Duties identifiers (operator/verifier sinauth UUIDs) |
| `Decision` | MARSHAL's evaluation outcome: `Outcome`, `ExecutionID`, `WORMEntryID`, per-gate `Gates`, `Reasons` |
| `GateResult` | A single MARSHAL gate's result (AuthN / AuthZ / NDS / AUGUR / WORM) |
| `KeyRegistration` / `KeyRegistrationResponse` | Request/response for `RegisterKey` |

### Outcome constants

| Constant | Value |
|---|---|
| `citadel.OutcomeExecute` | `"EXECUTE"` |
| `citadel.OutcomeRefuse` | `"REFUSE"` |
| `citadel.OutcomeHardStop` | `"HARD_STOP"` |

## Licence

Apache 2.0
