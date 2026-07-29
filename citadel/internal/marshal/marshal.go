package marshal

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// WORMEntry is a minimal result from a WORM append operation.
// Mirrors db.WORMEntry without importing the db package (avoids import cycle).
type WORMEntry struct {
	ID          uuid.UUID
	SequenceNum int64
	ChainHash   string
	SigOperator string
	SigVerifier string
}

// Store is the database interface required by the MARSHAL engine.
// Using an interface enables mock injection in tests and breaks the db↔marshal cycle.
type Store interface {
	// ActionCount returns how many actions actor made in the last windowDur.
	ActionCount(ctx context.Context, userID string, windowDur time.Duration) (int, error)
	// AppendWORM writes an append-only WORM entry (including the Operator/Verifier
	// signatures, if any) and returns minimal result.
	AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte, sigOperator, sigVerifier string) (*WORMEntry, error)
	// GetSigningKey returns the active Ed25519 public key registered for userID.
	// exists is false if the user has no registered key.
	GetSigningKey(ctx context.Context, userID string) (pubKey ed25519.PublicKey, exists bool, err error)
}

// TokenVerifier authenticates a sinauth-issued bearer token. Implemented by
// internal/auth.SinauthVerifier (wrapping sdk/go/sinauth.Client). Kept
// separate from Store because token verification is a crypto/HTTP concern
// against sinauth, not a database concern — see
// adrs/005-sinauth-identity-bridge.md.
type TokenVerifier interface {
	// Verify validates token and returns the authenticated user's sinauth
	// subject (UUID) and its issued role claim.
	Verify(ctx context.Context, token string) (userID, role string, err error)
}

// PermifySnapshot is the fast in-memory read interface into the
// Permify-derived Gate 2 policy snapshot. Implemented by
// internal/permifysync.Snapshot (a separate package: a time.Ticker-driven
// background sync from Permify into the local
// permify_role_action_snapshot table). Defined locally here — rather than
// importing permifysync directly — so gate2AuthZ compiles independently of
// exactly when that package lands; see
// adrs/007-permify-gate2-snapshot.md.
type PermifySnapshot interface {
	// Allowed reports whether Permify's synced policy permits role to
	// perform actionType. known is false when Permify has not asserted
	// anything about this role/action combination yet (e.g. not synced,
	// or synced but no matching tuple) — this is absence of data, not a
	// denial, and must never itself cause a REFUSE.
	Allowed(role, actionType string) (allowed bool, known bool)
}

// Engine is the MARSHAL 5-gate authorization engine.
//
// EnforceIdentity and EnforceSignatures are two INDEPENDENT rollout flags —
// see adrs/006-split-enforce-identity-and-signatures.md. They started as a
// single combined flag (ADR-004/005), but apiguard, irflow, and threatflow
// all reached real sinauth-token-backed identity (ActorToken/VerifierToken,
// real two-person approval) before any of them implemented per-user Ed25519
// key custody / signing. A single flag would have forced identity
// enforcement to wait on signing, or signing enforcement to be silently
// skipped — splitting lets identity enforcement turn on now while signature
// enforcement stays off until real signing exists.
type Engine struct {
	store    Store
	verifier TokenVerifier
	// enforceIdentity, when true, requires Gate 1/Gate 3 to REFUSE when
	// ActorToken/VerifierToken are missing, invalid, or don't match the
	// claimed user_id, instead of only warning.
	enforceIdentity bool
	// enforceSignatures, when true, requires Gate 1 and Gate 3 to verify
	// SigOperator/SigVerifier against a registered key; when false, the
	// signature check runs (and is recorded) but never fails the gate.
	// Stays false until at least one producer implements real per-user
	// Ed25519 signing — see adrs/004-operator-verifier-ed25519-signatures.md.
	enforceSignatures bool
	// permifySnapshot is the (optional) Permify-derived Gate 2 policy
	// snapshot. Nil is a valid state (no snapshot loaded yet, or
	// PermifyURL unset) — gate2AuthZ treats a nil snapshot the same as an
	// "unknown" result for every role/action: PASS for that sub-check,
	// never a REFUSE contributor. See adrs/007-permify-gate2-snapshot.md.
	permifySnapshot PermifySnapshot
	// enforcePermifyAuthz, when true, requires Gate 2 to REFUSE when the
	// Permify snapshot explicitly denies (known=true, allowed=false) the
	// actor's role/action. When false, a Permify-known deny only WARNs.
	// The rbacMap check in gate2AuthZ is NEVER gated by this flag — it is
	// the permanent, unconditional safety net regardless of this setting.
	enforcePermifyAuthz bool
}

// New creates a MARSHAL engine backed by the given Store and TokenVerifier,
// with both identity and signature enforcement disabled (soft mode — see
// EnforceIdentity, EnforceSignatures).
func New(store Store, verifier TokenVerifier) *Engine {
	return &Engine{store: store, verifier: verifier}
}

// EnforceIdentity returns a copy of the engine with identity enforcement
// enabled: Gate 1/Gate 3 REFUSE when ActorToken/VerifierToken are missing,
// invalid, or don't match the claimed user_id, instead of only warning.
func (e *Engine) EnforceIdentity(enforce bool) *Engine {
	cp := *e
	cp.enforceIdentity = enforce
	return &cp
}

// EnforceSignatures returns a copy of the engine with signature enforcement
// enabled: Gate 1/Gate 3 REFUSE when SigOperator/SigVerifier are missing or
// invalid, instead of only warning.
func (e *Engine) EnforceSignatures(enforce bool) *Engine {
	cp := *e
	cp.enforceSignatures = enforce
	return &cp
}

// EnforcePermifyAuthz returns a copy of the engine with Permify-snapshot
// enforcement enabled: Gate 2 (AuthZ) REFUSEs when the Permify-derived
// local snapshot explicitly denies (known=true, allowed=false) the actor's
// role/action, instead of only warning. The rbacMap check remains enforced
// unconditionally regardless of this flag — see
// adrs/007-permify-gate2-snapshot.md.
func (e *Engine) EnforcePermifyAuthz(enforce bool) *Engine {
	cp := *e
	cp.enforcePermifyAuthz = enforce
	return &cp
}

// PermifySnapshot returns a copy of the engine wired to read the given
// Permify-derived Gate 2 snapshot (typically internal/permifysync.Snapshot).
// A nil snapshot (the default) makes the Permify sub-check a no-op PASS for
// every role/action — see adrs/007-permify-gate2-snapshot.md.
func (e *Engine) PermifySnapshot(snapshot PermifySnapshot) *Engine {
	cp := *e
	cp.permifySnapshot = snapshot
	return &cp
}

// Evaluate runs the Kerkese through all 5 gates and returns a Decision.
// Gate 5 (WORM commit) always runs regardless of prior gate outcomes.
func (e *Engine) Evaluate(ctx context.Context, k *Kerkese) (*Decision, error) {
	start := time.Now()

	decision := &Decision{
		ExecutionID: k.ExecutionID,
		TsUTC:       time.Now().UTC(),
		DryRun:      k.DryRun,
		Gates:       make([]GateResult, 0, 5),
		Reasons:     make([]string, 0),
	}

	outcome := OutcomeExecute

	// ── Gate 1 — AuthN ───────────────────────────────────────────────────────
	g1 := e.gate1AuthN(ctx, k)
	decision.Gates = append(decision.Gates, g1)
	if g1.Status == GateFail {
		outcome = OutcomeRefuse
		decision.Reasons = append(decision.Reasons, g1.Reason)
	}

	// ── Gate 2 — AuthZ ───────────────────────────────────────────────────────
	g2 := e.gate2AuthZ(k)
	decision.Gates = append(decision.Gates, g2)
	if outcome == OutcomeExecute && g2.Status == GateFail {
		outcome = OutcomeRefuse
		decision.Reasons = append(decision.Reasons, g2.Reason)
	}

	// ── Gate 3 — NDS ─────────────────────────────────────────────────────────
	g3 := e.gate3NDS(ctx, k)
	decision.Gates = append(decision.Gates, g3)
	if outcome == OutcomeExecute && (g3.Status == GateFail || g3.Status == GateHardStop) {
		if g3.Status == GateHardStop {
			outcome = OutcomeHardStop
		} else {
			outcome = OutcomeRefuse
		}
		decision.Reasons = append(decision.Reasons, g3.Reason)
	}

	// ── Gate 4 — AUGUR ───────────────────────────────────────────────────────
	g4 := e.gate4AUGUR(ctx, k)
	decision.Gates = append(decision.Gates, g4)
	if outcome == OutcomeExecute && g4.Status == GateHardStop {
		outcome = OutcomeHardStop
		decision.Reasons = append(decision.Reasons, g4.Reason)
	}

	// ── Gate 5 — WORM (unconditional) ────────────────────────────────────────
	g5Start := time.Now()
	decision.Outcome = outcome

	wormEntry, err := e.gate5WORM(ctx, k, decision)
	g5 := GateResult{
		Gate:      5,
		Name:      "WORM",
		LatencyMs: float64(time.Since(g5Start).Microseconds()) / 1000.0,
	}
	if err != nil {
		g5.Status = GateWarn
		g5.Reason = fmt.Sprintf("WORM append warning: %v", err)
	} else {
		g5.Status = GatePass
		if wormEntry != nil {
			wid := wormEntry.ID
			decision.WORMEntryID = &wid
		}
	}
	decision.Gates = append(decision.Gates, g5)

	_ = start // total latency available for metrics if needed
	return decision, nil
}

// enforcedCheck is one sub-check (identity or signature) feeding into a
// gate's combined result — see combineChecks.
type enforcedCheck struct {
	status  string
	reason  string
	enforce bool
}

// combineChecks merges independently-enforced sub-checks into one gate
// status/reason: REFUSE if any failed check is enforced, WARN if any failed
// check is only soft-gated (and none are enforced), PASS otherwise. This is
// what lets EnforceIdentity and EnforceSignatures roll out independently —
// see adrs/006-split-enforce-identity-and-signatures.md.
func combineChecks(checks ...enforcedCheck) (status, reason string) {
	failed, warned := false, false
	var reasons []string
	for _, c := range checks {
		if c.status == GatePass {
			continue
		}
		reasons = append(reasons, c.reason)
		if c.enforce {
			failed = true
		} else {
			warned = true
		}
	}
	switch {
	case failed:
		return GateFail, strings.Join(reasons, "; ")
	case warned:
		return GateWarn, strings.Join(reasons, "; ")
	default:
		return GatePass, ""
	}
}

// gate1AuthN verifies the Actor holds a valid, currently-signed sinauth
// bearer token (ActorToken) whose subject matches k.Actor.UserID, and that
// the Operator's Ed25519 signature is valid. Replaces the earlier
// local-session-table check — see adrs/005-sinauth-identity-bridge.md for
// why: nothing ever populated that table, so it could never pass for a real
// request.
//
// The token check is gated by EnforceIdentity, the signature check by
// EnforceSignatures — independently, since producers reached real
// token-backed identity before any implemented Ed25519 signing — see
// adrs/006-split-enforce-identity-and-signatures.md.
func (e *Engine) gate1AuthN(ctx context.Context, k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 1, Name: "AuthN"}

	tokenStatus, tokenReason := e.verifyActorToken(ctx, k)
	sigStatus, sigReason := e.verifyOperatorSignature(ctx, k)

	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	g.Status, g.Reason = combineChecks(
		enforcedCheck{tokenStatus, tokenReason, e.enforceIdentity},
		enforcedCheck{sigStatus, sigReason, e.enforceSignatures},
	)
	return g
}

// verifyActorToken checks k.ActorToken authenticates k.Actor.UserID.
// Returns (GateFail, reason) on any failure, (GatePass, "") otherwise.
func (e *Engine) verifyActorToken(ctx context.Context, k *Kerkese) (string, string) {
	if k.ActorToken == "" {
		return GateFail, fmt.Sprintf("AUTH_FAIL: no actor_token provided for user_id=%s", k.Actor.UserID)
	}
	sub, _, err := e.verifier.Verify(ctx, k.ActorToken)
	if err != nil {
		return GateFail, fmt.Sprintf("AUTH_FAIL: actor_token invalid or expired: %v", err)
	}
	if sub != k.Actor.UserID {
		return GateFail, fmt.Sprintf("AUTH_FAIL: actor_token subject %q does not match actor.user_id %q", sub, k.Actor.UserID)
	}
	return GatePass, ""
}

// verifyOperatorSignature checks k.SigOperator against the Operator's
// registered signing key. Returns (GateFail, reason) if no key is
// registered or the signature is missing/invalid, (GatePass, "") otherwise.
func (e *Engine) verifyOperatorSignature(ctx context.Context, k *Kerkese) (string, string) {
	pub, exists, err := e.store.GetSigningKey(ctx, k.Actor.UserID)
	if err != nil {
		return GateFail, fmt.Sprintf("AUTH_FAIL: signing key lookup failed for user_id=%s", k.Actor.UserID)
	}
	if !exists {
		return GateFail, fmt.Sprintf("AUTH_FAIL: no signing key registered for operator user_id=%s", k.Actor.UserID)
	}
	if k.SigOperator == "" {
		return GateFail, "AUTH_FAIL: operator signature missing"
	}
	if !VerifySignature(pub, CanonicalPayload(*k), k.SigOperator) {
		return GateFail, "AUTH_FAIL: operator signature invalid"
	}
	return GatePass, ""
}

// gate2AuthZ checks the actor's role against two independently-enforced
// sub-checks folded via combineChecks (the same mechanism Gate 1/Gate 3 use
// — see adrs/006-split-enforce-identity-and-signatures.md):
//
//   - the rbacMap check (roleAllowed): the permanent safety net, always
//     enforced (enforce: true, unconditionally) — this is never weakened by
//     EnforcePermifyAuthz or anything else.
//   - the Permify-snapshot check (permifyCheck): enforced only when
//     EnforcePermifyAuthz is true, so a Permify-known deny only WARNs until
//     a deployment explicitly opts in. See adrs/007-permify-gate2-snapshot.md.
func (e *Engine) gate2AuthZ(k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 2, Name: "AuthZ"}

	rbacStatus, rbacReason := GatePass, ""
	if !roleAllowed(k.Actor.Role, k.Action.Type) {
		rbacStatus = GateFail
		rbacReason = fmt.Sprintf("AUTHZ_FAIL: role %q is not permitted to perform %q", k.Actor.Role, k.Action.Type)
	}

	permifyStatus, permifyReason := e.permifyCheck(k.Actor.Role, k.Action.Type)

	g.Status, g.Reason = combineChecks(
		enforcedCheck{rbacStatus, rbacReason, true},
		enforcedCheck{permifyStatus, permifyReason, e.enforcePermifyAuthz},
	)
	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	return g
}

// permifyCheck evaluates the Permify-derived snapshot for role/actionType.
// Returns (GatePass, "") when the snapshot is nil (not wired) or the
// snapshot has no opinion for this role/action (known=false) — absence of
// Permify data must never itself cause a REFUSE, only an explicit
// known=true,allowed=false denial is a fail candidate for this sub-check.
func (e *Engine) permifyCheck(role, actionType string) (status, reason string) {
	if e.permifySnapshot == nil {
		return GatePass, ""
	}
	allowed, known := e.permifySnapshot.Allowed(role, actionType)
	if !known {
		return GatePass, ""
	}
	if !allowed {
		return GateFail, fmt.Sprintf("AUTHZ_PERMIFY_DENY: Permify-synced policy denies role %q for %q", role, actionType)
	}
	return GatePass, ""
}

// gate3NDS enforces Separation of Duties:
// operator != verifier AND different role groups.
func (e *Engine) gate3NDS(ctx context.Context, k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 3, Name: "NDS"}

	// Same identity check
	if k.SoD.OperatorUserID == k.SoD.VerifierUserID {
		g.Status = GateHardStop
		g.Reason = "NDS_SAME_IDENTITY: operator and verifier are the same user"
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	// Role group check — role groups are derived from the producer-asserted
	// Actor.Role / Verifier.Role (unchanged from before; sinauth's role claim
	// is scoped per sinauth client, not to CITADEL's role taxonomy, so it
	// cannot substitute here — see adrs/005-sinauth-identity-bridge.md).
	opGroup := roleGroup(k.Actor.Role)
	vfGroup := roleGroup(k.Verifier.Role)

	if opGroup == vfGroup && opGroup != "unknown" {
		g.Status = GateHardStop
		g.Reason = fmt.Sprintf("NDS_SAME_GROUP: operator and verifier are both in role group %q", opGroup)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	// Identity + non-repudiation checks: both Operator and Verifier must
	// present a valid sinauth bearer token for their claimed user_id, and
	// the Verifier's Ed25519 signature must be valid — the second half of
	// Definition 2's non-repudiation pair (Gate 1 checks the Operator's).
	// Token checks are gated by EnforceIdentity, the signature check by
	// EnforceSignatures — independently, see
	// adrs/006-split-enforce-identity-and-signatures.md.
	opTokenStatus, opTokenReason := e.verifyToken(ctx, k.ActorToken, k.SoD.OperatorUserID, "operator")
	vfTokenStatus, vfTokenReason := e.verifyToken(ctx, k.VerifierToken, k.SoD.VerifierUserID, "verifier")
	sigStatus, sigReason := e.verifyVerifierSignature(ctx, k)

	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	g.Status, g.Reason = combineChecks(
		enforcedCheck{opTokenStatus, opTokenReason, e.enforceIdentity},
		enforcedCheck{vfTokenStatus, vfTokenReason, e.enforceIdentity},
		enforcedCheck{sigStatus, sigReason, e.enforceSignatures},
	)
	return g
}

// verifyToken checks token authenticates userID (used for both the Operator
// and the Verifier in Gate 3 — role is "operator"/"verifier", for error
// messages only).
func (e *Engine) verifyToken(ctx context.Context, token, userID, role string) (string, string) {
	if token == "" {
		return GateFail, fmt.Sprintf("NDS_FAIL: no %s_token provided for %s user_id=%s", role, role, userID)
	}
	sub, _, err := e.verifier.Verify(ctx, token)
	if err != nil || sub != userID {
		return GateFail, fmt.Sprintf("NDS_FAIL: %s user_id=%s has no valid %s_token", role, userID, role)
	}
	return GatePass, ""
}

// verifyVerifierSignature checks k.SigVerifier against the Verifier's
// registered signing key. Returns (GateFail, reason) if no key is
// registered or the signature is missing/invalid, (GatePass, "") otherwise.
func (e *Engine) verifyVerifierSignature(ctx context.Context, k *Kerkese) (string, string) {
	pub, exists, err := e.store.GetSigningKey(ctx, k.Verifier.UserID)
	if err != nil {
		return GateFail, fmt.Sprintf("NDS_FAIL: signing key lookup failed for verifier user_id=%s", k.Verifier.UserID)
	}
	if !exists {
		return GateFail, fmt.Sprintf("NDS_FAIL: no signing key registered for verifier user_id=%s", k.Verifier.UserID)
	}
	if k.SigVerifier == "" {
		return GateFail, "NDS_FAIL: verifier signature missing"
	}
	if !VerifySignature(pub, CanonicalPayload(*k), k.SigVerifier) {
		return GateFail, "NDS_FAIL: verifier signature invalid"
	}
	return GatePass, ""
}

// gate4AUGUR evaluates 3 behavioral heuristic rules.
func (e *Engine) gate4AUGUR(ctx context.Context, k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 4, Name: "AUGUR"}

	// rule_01: off-hours action (outside 07:00–19:00 UTC) → WARN
	hour := k.TsUTC.UTC().Hour()
	if hour < 7 || hour >= 19 {
		g.Status = GateWarn
		g.Reason = fmt.Sprintf("AUGUR_rule_01: action initiated outside business hours (hour=%d UTC)", hour)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		// WARN does not block — continue to check rule_03
	}

	// rule_02: same actor >10 actions in last 5 minutes → WARN
	count, err := e.store.ActionCount(ctx, k.Actor.UserID, 5*time.Minute)
	if err == nil && count > 10 {
		if g.Status == "" {
			g.Status = GateWarn
		}
		g.Reason += fmt.Sprintf(" AUGUR_rule_02: high frequency (%d actions in 5min)", count)
	}

	// rule_03: DATA_EXPORT without incident_id → HARD_STOP (overrides WARN)
	if k.Action.Type == "DATA_EXPORT" && k.Action.IncidentID == "" {
		g.Status = GateHardStop
		g.Reason = "AUGUR_rule_03: DATA_EXPORT attempted without incident_id — HARD_STOP"
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	if g.Status == "" {
		g.Status = GatePass
	}
	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	return g
}

// gate5WORM unconditionally appends the decision to the WORM chain.
func (e *Engine) gate5WORM(ctx context.Context, k *Kerkese, d *Decision) (*WORMEntry, error) {
	// Redact bearer tokens before archiving: SigOperator/SigVerifier are
	// long-term non-repudiation evidence and belong in the WORM record;
	// ActorToken/VerifierToken are short-lived secrets and must never be
	// written to storage, even inside the "kerkese" audit payload.
	redacted := *k
	redacted.ActorToken = ""
	redacted.VerifierToken = ""

	payload, err := json.Marshal(map[string]any{
		"kerkese":      redacted,
		"outcome":      d.Outcome,
		"gates":        d.Gates,
		"reasons":      d.Reasons,
		"execution_id": d.ExecutionID.String(),
		"ts_utc":       d.TsUTC.Format(time.RFC3339),
	})
	if err != nil {
		return nil, fmt.Errorf("gate5: marshal payload: %w", err)
	}

	projectID := k.ProjectID
	if projectID == "" {
		projectID = "citadel"
	}

	entry, err := e.store.AppendWORM(ctx, "citadel.marshal", "marshal.decision", projectID, payload, k.SigOperator, k.SigVerifier)
	if err != nil {
		return nil, fmt.Errorf("gate5: append worm: %w", err)
	}
	return entry, nil
}

// NewExecutionID generates a fresh UUID for a Kerkese that lacks one.
func NewExecutionID() uuid.UUID {
	return uuid.New()
}
