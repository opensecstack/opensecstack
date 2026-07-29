// Package citadel is the canonical Go contract for submitting governance
// requests ("Kerkese") to CITADEL's MARSHAL engine and signing them as the
// Operator and/or Verifier.
//
// This package exists because, before it was introduced, every producer
// platform (apiguard, irflow, threatflow) hand-duplicated its own copy of
// the Kerkese shape, and the copies had drifted (different field types,
// different KerkeseVersion strings, lossy ID transforms). Field names and
// JSON tags here MUST match citadel/internal/marshal/types.go exactly —
// that is the server-side source of truth this package mirrors.
package citadel

import (
	"time"

	"github.com/google/uuid"
)

// Kerkese is the governance payload submitted to MARSHAL for evaluation.
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

	// SigOperator and SigVerifier are hex-encoded Ed25519 signatures (64
	// bytes -> 128 hex chars) over CanonicalPayload(k), produced by Sign.
	// Both are required once the target CITADEL instance enforces signature
	// verification (see citadel ADR-004).
	SigOperator string `json:"sig_operator,omitempty"`
	SigVerifier string `json:"sig_verifier,omitempty"`

	// ActorToken and VerifierToken are sinauth-issued RS256 bearer tokens
	// proving the Operator's and Verifier's authenticated identity — see
	// citadel ADR-005 (sinauth identity bridge). Forward the exact bearer
	// token the caller presented; CITADEL verifies it directly against
	// sinauth's JWKS and discards it (never persisted).
	ActorToken    string `json:"actor_token,omitempty"`
	VerifierToken string `json:"verifier_token,omitempty"`
}

// KerkeseAction describes the privileged action being requested.
type KerkeseAction struct {
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	ChangeID      string `json:"change_id,omitempty"`
	IncidentID    string `json:"incident_id,omitempty"`
	RootCause     string `json:"root_cause,omitempty"`
	CorrectiveAct string `json:"corrective_action,omitempty"`
}

// KerkeseActor is the principal initiating the action (the Operator).
// UserID is the sinauth subject (UUID string).
type KerkeseActor struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

// KerkeseVerifier is the distinct principal approving the action.
// UserID is the sinauth subject (UUID string).
type KerkeseVerifier struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

// KerkeseEvidence holds supporting artefacts for the request.
// Deliberately excluded from the signed canonical payload (see sign.go) —
// WORM's TripleHash/chain_hash already covers full-payload integrity;
// signatures exist to prove who authorized the action, not to bind
// free-form evidence content.
type KerkeseEvidence struct {
	ChangeID  string             `json:"change_id,omitempty"`
	Artifacts []EvidenceArtifact `json:"artifacts,omitempty"`
	DrillRef  string             `json:"drill_reference,omitempty"`
	Extra     map[string]any     `json:"extra,omitempty"`
}

// EvidenceArtifact is a single evidence item (hash + type + label).
type EvidenceArtifact struct {
	Hash  string `json:"hash"`
	Type  string `json:"type"`
	Label string `json:"label"`
}

// KerkeseSoD carries the Separation of Duties identifiers (sinauth UUIDs).
type KerkeseSoD struct {
	OperatorUserID string `json:"operator_user_id"`
	VerifierUserID string `json:"verifier_user_id"`
}

// Decision is the outcome returned by MARSHAL.
type Decision struct {
	Outcome     string       `json:"outcome"`
	ExecutionID uuid.UUID    `json:"execution_id"`
	WORMEntryID *uuid.UUID   `json:"worm_entry_id,omitempty"`
	Gates       []GateResult `json:"gates"`
	Reasons     []string     `json:"reasons"`
	TsUTC       time.Time    `json:"ts_utc"`
	DryRun      bool         `json:"dry_run,omitempty"`
}

// GateResult is a single gate evaluation within a Decision.
type GateResult struct {
	Gate      int     `json:"gate"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	Reason    string  `json:"reason,omitempty"`
	LatencyMs float64 `json:"latency_ms"`
}

// Outcome constants, mirroring citadel/internal/marshal.
const (
	OutcomeExecute  = "EXECUTE"
	OutcomeRefuse   = "REFUSE"
	OutcomeHardStop = "HARD_STOP"
)
