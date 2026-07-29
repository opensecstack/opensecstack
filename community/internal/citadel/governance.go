package citadel

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	sdkcitadel "github.com/opensecstack/sdk/go/citadel"
)

// GovernanceClient submits Kerkese governance requests to CITADEL's MARSHAL
// engine (POST /api/v1/marshal/evaluate) and honours its EXECUTE/REFUSE/
// HARD_STOP verdict. This is distinct from Client above, which only Emits
// WORM audit events and makes no authorization decision — community had no
// MARSHAL integration at all before this file (see design notes on
// scheduler.go's processDeletions for why GDPR deletion needed one).
//
// It is a thin wrapper around the shared sdk/go/citadel.Client: community
// carried no citadel-client functionality worth preserving beyond WORM
// emit (unlike apiguard/irflow, which hand-roll HMAC-signed variants for
// historical reasons), so importing the SDK type directly is the right
// call here.
type GovernanceClient struct {
	sdk *sdkcitadel.Client
}

// NewGovernanceClient creates a GovernanceClient targeting the CITADEL
// instance at apiURL. An empty apiURL is valid — EvaluateDeletion fails
// open (proceed=true, non-nil err) in that case, same as an unreachable
// CITADEL, so callers should log the error rather than treat it as fatal.
func NewGovernanceClient(apiURL string) *GovernanceClient {
	return &GovernanceClient{sdk: sdkcitadel.NewClient(apiURL, nil)}
}

// ResolveIdentity returns the sinauth UUID for a user when known (citadel
// adrs/005-sinauth-identity-bridge.md), falling back to a clearly-marked
// non-sinauth identifier when the user has no linked sinauth account (e.g.
// registered via community's native email/password signup rather than SIN
// SSO — see internal/api/handlers/oauth_sinauth.go). The fallback is a
// real, durable, community-internal identity — not a fabricated
// placeholder — but it will not verify against sinauth's JWKS the way a
// genuine sinauth UUID does. That is an accepted, documented gap: CITADEL's
// Gate 1/Gate 3 AuthN checks WARN rather than block when they cannot
// resolve a non-sinauth actor identity, because citadel.enforce_identity is
// false today (soft mode, ADR-006).
func ResolveIdentity(sinauthID sql.NullString, userID string) string {
	if sinauthID.Valid && sinauthID.String != "" {
		return sinauthID.String
	}
	return "community-user:" + userID
}

// DeletionKerkese builds the Kerkese submitted to MARSHAL before a GDPR
// account deletion actually executes. actorUserID identifies the user
// being deleted — the Operator/Actor, since a GDPR erasure request is
// always initiated by (or on behalf of) the person whose data it is (see
// RequestDeletion in internal/api/handlers/gdpr.go). verifierUserID
// identifies the admin who approved the deletion (internal/api/handlers/
// gdpr.go's AdminApproveDeletion) — always a distinct identity, enforced by
// an explicit separation-of-duties check at both call sites before this
// Kerkese is ever built.
//
// SigOperator/SigVerifier are left empty: no per-user Ed25519 key custody
// UX exists anywhere in the ecosystem yet (citadel adrs/004-operator-
// verifier-ed25519-signatures.md — "currently unused by any producer").
// ActorToken/VerifierToken are also left empty: community authenticates
// its own API with a locally-minted HMAC JWT issued after sinauth login
// completes (see internal/api/handlers/oauth_sinauth.go's issueOAuthJWT),
// not by forwarding the caller's raw sinauth-issued RS256 bearer token on
// every request the way apiguard does — so there is no live sinauth
// bearer token available anywhere in community to forward here. This is a
// known, documented gap, soft-gated by citadel.enforce_signatures=false
// (ADR-006), not a fabricated token standing in for a real one.
func DeletionKerkese(projectID string, deletionRequestID uuid.UUID, actorUserID, verifierUserID string) sdkcitadel.Kerkese {
	return sdkcitadel.Kerkese{
		KerkeseVersion: "1.0",
		TsUTC:          time.Now().UTC(),
		ProjectID:      projectID,
		ExecutionID:    deletionRequestID,
		Action: sdkcitadel.KerkeseAction{
			Type:        "user_data_deletion",
			Description: "GDPR account erasure",
			ChangeID:    deletionRequestID.String(),
		},
		Actor:    sdkcitadel.KerkeseActor{UserID: actorUserID, Role: "group_sig_operator"},
		Verifier: sdkcitadel.KerkeseVerifier{UserID: verifierUserID, Role: "group_sig_verifier"},
		Evidence: sdkcitadel.KerkeseEvidence{ChangeID: deletionRequestID.String()},
		SoD:      sdkcitadel.KerkeseSoD{OperatorUserID: actorUserID, VerifierUserID: verifierUserID},
	}
}

// EvaluateDeletion submits k to MARSHAL and reports whether the deletion may
// proceed.
//
// A REFUSE or HARD_STOP decision blocks execution (proceed=false, with
// human-readable reasons) — this is the one outcome callers must never
// paper over, since it gates an irreversible destructive action.
//
// A transport/availability error fails OPEN (proceed=true, err set) —
// mirroring apiguard's existing CITADEL governance check (apiguard/
// internal/api/handlers/scans.go's "CITADEL governance check": "proceeding
// with scan" on evalErr != nil) so an unreachable CITADEL does not itself
// become a GDPR-deadline-missing outage. Callers must log err even though
// they proceed.
func (g *GovernanceClient) EvaluateDeletion(ctx context.Context, k sdkcitadel.Kerkese) (proceed bool, reasons []string, err error) {
	decision, evalErr := g.sdk.Evaluate(ctx, k)
	if evalErr != nil {
		// sdk/go/citadel.Client.Evaluate treats any CITADEL response with
		// HTTP status >= 400 as a transport error and discards the parsed
		// Decision — but MARSHAL returns HTTP 403 for BOTH REFUSE and
		// HARD_STOP outcomes (see citadel/internal/api/handlers/marshal.go),
		// not just for genuine failures. Blindly failing open on every
		// evalErr != nil would therefore silently let a REFUSE/HARD_STOP
		// through — exactly the GDPR violation risk this gate exists to
		// prevent. So a 403 carrying a real decision is recovered here by
		// parsing it back out of the SDK error's embedded response body
		// (client.go: `fmt.Errorf("citadel: Evaluate: HTTP %d: %s", ...)`)
		// before falling through to fail-open for genuine transport errors.
		// This is a workaround for a gap in the shared SDK client — sdk/
		// go/citadel is off-limits for this task, so it cannot be fixed at
		// the source — not a design choice made freely.
		if dec, ok := decisionFromEvaluateError(evalErr); ok {
			if dec.Outcome == sdkcitadel.OutcomeRefuse || dec.Outcome == sdkcitadel.OutcomeHardStop {
				blockReasons := dec.Reasons
				if len(blockReasons) == 0 {
					blockReasons = []string{"CITADEL governance check rejected this deletion"}
				}
				return false, blockReasons, nil
			}
			return true, nil, nil
		}
		return true, nil, fmt.Errorf("citadel marshal evaluate: %w", evalErr)
	}
	if decision.Outcome == sdkcitadel.OutcomeRefuse || decision.Outcome == sdkcitadel.OutcomeHardStop {
		blockReasons := decision.Reasons
		if len(blockReasons) == 0 {
			blockReasons = []string{"CITADEL governance check rejected this deletion"}
		}
		return false, blockReasons, nil
	}
	return true, nil, nil
}

// decisionFromEvaluateError attempts to recover the Decision JSON embedded
// in an error returned by sdk/go/citadel.Client.Evaluate for an HTTP >= 400
// response. Returns ok=false if err does not match that shape (e.g. a
// genuine connection failure, which never reaches HTTP status parsing).
func decisionFromEvaluateError(err error) (dec sdkcitadel.Decision, ok bool) {
	msg := err.Error()
	_, afterStatus, found := strings.Cut(msg, ": HTTP ")
	if !found {
		return sdkcitadel.Decision{}, false
	}
	_, body, found := strings.Cut(afterStatus, ": ")
	if !found {
		return sdkcitadel.Decision{}, false
	}
	if jsonErr := json.Unmarshal([]byte(body), &dec); jsonErr != nil || dec.Outcome == "" {
		return sdkcitadel.Decision{}, false
	}
	return dec, true
}
