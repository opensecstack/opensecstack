package marshal

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// WORMEntry is a minimal result from a WORM append operation.
// Mirrors db.WORMEntry without importing the db package (avoids import cycle).
type WORMEntry struct {
	ID          uuid.UUID
	SequenceNum int64
	ChainHash   string
}

// Store is the database interface required by the MARSHAL engine.
// Using an interface enables mock injection in tests and breaks the db↔marshal cycle.
type Store interface {
	// SessionExists returns (role, roleGroup, exists) for a given user_id.
	SessionExists(ctx context.Context, userID int64) (role, roleGroup string, exists bool, err error)
	// ActionCount returns how many actions actor made in the last windowDur.
	ActionCount(ctx context.Context, userID int64, windowDur time.Duration) (int, error)
	// AppendWORM writes an append-only WORM entry and returns minimal result.
	AppendWORM(ctx context.Context, source, eventType, projectID string, payload []byte) (*WORMEntry, error)
}

// Engine is the MARSHAL 5-gate authorization engine.
type Engine struct {
	store Store
}

// New creates a MARSHAL engine backed by the given Store.
func New(store Store) *Engine {
	return &Engine{store: store}
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

// gate1AuthN verifies the actor has a valid, non-expired, non-revoked session.
func (e *Engine) gate1AuthN(ctx context.Context, k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 1, Name: "AuthN"}

	role, _, exists, err := e.store.SessionExists(ctx, k.Actor.UserID)
	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0

	if err != nil {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("AUTH_ERROR: session lookup failed for user_id=%d", k.Actor.UserID)
		return g
	}
	if !exists {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("AUTH_FAIL: no valid session for user_id=%d", k.Actor.UserID)
		return g
	}
	// Optionally validate role consistency
	if role != k.Actor.Role && k.Actor.Role != "" {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("AUTH_FAIL: claimed role %q does not match session role %q", k.Actor.Role, role)
		return g
	}

	g.Status = GatePass
	return g
}

// gate2AuthZ checks the actor's role against the RBAC map.
func (e *Engine) gate2AuthZ(k *Kerkese) GateResult {
	t := time.Now()
	g := GateResult{Gate: 2, Name: "AuthZ"}

	if !roleAllowed(k.Actor.Role, k.Action.Type) {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("AUTHZ_FAIL: role %q is not permitted to perform %q", k.Actor.Role, k.Action.Type)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	g.Status = GatePass
	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	return g
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

	// Role group check via session store
	_, opGroup, opExists, err := e.store.SessionExists(ctx, k.SoD.OperatorUserID)
	if err != nil || !opExists {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("NDS_FAIL: operator user_id=%d has no valid session", k.SoD.OperatorUserID)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	_, vfGroup, vfExists, err := e.store.SessionExists(ctx, k.SoD.VerifierUserID)
	if err != nil || !vfExists {
		g.Status = GateFail
		g.Reason = fmt.Sprintf("NDS_FAIL: verifier user_id=%d has no valid session", k.SoD.VerifierUserID)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	if opGroup == vfGroup && opGroup != "unknown" {
		g.Status = GateHardStop
		g.Reason = fmt.Sprintf("NDS_SAME_GROUP: operator and verifier are both in role group %q", opGroup)
		g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
		return g
	}

	g.Status = GatePass
	g.LatencyMs = float64(time.Since(t).Microseconds()) / 1000.0
	return g
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
	payload, err := json.Marshal(map[string]any{
		"kerkese":      k,
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

	entry, err := e.store.AppendWORM(ctx, "citadel.marshal", "marshal.decision", projectID, payload)
	if err != nil {
		return nil, fmt.Errorf("gate5: append worm: %w", err)
	}
	return entry, nil
}

// NewExecutionID generates a fresh UUID for a Kerkese that lacks one.
func NewExecutionID() uuid.UUID {
	return uuid.New()
}
