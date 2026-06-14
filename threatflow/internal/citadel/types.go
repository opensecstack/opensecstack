// Package citadel is ThreatFlow's client for the CITADEL governance engine.
// It performs two tasks:
//
//  1. MARSHAL gating — Evaluate() sends a Kerkese request to CITADEL which
//     replies with EXECUTE / REFUSE / HARD_STOP. IOC ingest, feed create,
//     and STIX bundle import all call through Evaluate before mutating state.
//  2. WORM emission — Emit() fires an audit event to CITADEL's immutable log.
//     Emissions are best-effort and asynchronous; the caller never blocks.
//
// When BaseURL is empty the client is a no-op: every method returns nil /
// empty without touching the network. This keeps ThreatFlow usable in
// standalone dev environments that have no CITADEL deployed.
package citadel

import (
	"time"

	"github.com/google/uuid"
)

// Kerkese is the governance payload sent to MARSHAL. Field names match
// CITADEL's `internal/marshal/types.go` exactly so the same JSON wire is
// shared across all opensecstack services.
type Kerkese struct {
	KerkeseVersion string          `json:"kerkese_version"`
	TsUTC          time.Time       `json:"ts_utc"`
	ProjectID      string          `json:"project_id"`
	ExecutionID    uuid.UUID       `json:"execution_id"`
	Action         KerkeseAction   `json:"action"`
	Actor          KerkeseActor    `json:"actor"`
	Verifier       KerkeseVerifier `json:"verifier"`
	Evidence       KerkeseEvidence `json:"evidence"`
	SoD            KerkeseSoD      `json:"sod"`
	DryRun         bool            `json:"dry_run,omitempty"`
	Emergency      bool            `json:"emergency,omitempty"`
	EmergencyJust  string          `json:"emergency_justification,omitempty"`
}

type KerkeseAction struct {
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	ChangeID      string `json:"change_id,omitempty"`
	IncidentID    string `json:"incident_id,omitempty"`
	RootCause     string `json:"root_cause,omitempty"`
	CorrectiveAct string `json:"corrective_action,omitempty"`
}

type KerkeseActor struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

type KerkeseVerifier struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

type KerkeseEvidence struct {
	ChangeID  string             `json:"change_id,omitempty"`
	Artifacts []EvidenceArtifact `json:"artifacts,omitempty"`
	DrillRef  string             `json:"drill_reference,omitempty"`
	Extra     map[string]any     `json:"extra,omitempty"`
}

type EvidenceArtifact struct {
	Hash  string `json:"hash"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

type KerkeseSoD struct {
	OperatorUserID int64 `json:"operator_user_id"`
	VerifierUserID int64 `json:"verifier_user_id"`
}

// Decision is the outcome from MARSHAL.
type Decision struct {
	Outcome     string       `json:"outcome"`
	ExecutionID uuid.UUID    `json:"execution_id"`
	WORMEntryID *uuid.UUID   `json:"worm_entry_id,omitempty"`
	Gates       []GateResult `json:"gates"`
	Reasons     []string     `json:"reasons"`
	TsUTC       time.Time    `json:"ts_utc"`
	DryRun      bool         `json:"dry_run,omitempty"`
}

type GateResult struct {
	Gate      int     `json:"gate"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
}

// Outcome constants mirror citadel/internal/marshal/types.go.
const (
	OutcomeExecute  = "EXECUTE"
	OutcomeRefuse   = "REFUSE"
	OutcomeHardStop = "HARD_STOP"
)

// Allowed returns true when the decision permits the action to proceed.
func (d *Decision) Allowed() bool {
	return d != nil && d.Outcome == OutcomeExecute
}

// Action types emitted by ThreatFlow. Keep these in sync with CITADEL's RBAC
// map if new ones are introduced.
const (
	ActionIOCIngest       = "IOC_INGEST"
	ActionIOCRevoke       = "IOC_REVOKE"
	ActionBundleImport    = "STIX_BUNDLE_IMPORT"
	ActionFeedCreate      = "FEED_CREATE"
	ActionFeedDelete      = "FEED_DELETE"
	ActionFeedToggle      = "FEED_TOGGLE"
)
