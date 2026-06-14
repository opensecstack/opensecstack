package marshal

import (
	"time"

	"github.com/google/uuid"
)

// Kerkese is the governance payload sent to MARSHAL for evaluation.
// Field names mirror apiguard/internal/citadel/types.go exactly.
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

// KerkeseAction describes the privileged action being requested.
type KerkeseAction struct {
	Type          string `json:"type"`
	Description   string `json:"description,omitempty"`
	ChangeID      string `json:"change_id,omitempty"`
	IncidentID    string `json:"incident_id,omitempty"`
	RootCause     string `json:"root_cause,omitempty"`
	CorrectiveAct string `json:"corrective_action,omitempty"`
}

// KerkeseActor is the principal initiating the action.
type KerkeseActor struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

// KerkeseVerifier is the distinct principal approving the action.
type KerkeseVerifier struct {
	UserID int64  `json:"user_id"`
	Role   string `json:"role"`
	Email  string `json:"email,omitempty"`
}

// KerkeseEvidence holds supporting artefacts for the request.
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

// KerkeseSoD carries the Separation of Duties identifiers.
type KerkeseSoD struct {
	OperatorUserID int64 `json:"operator_user_id"`
	VerifierUserID int64 `json:"verifier_user_id"`
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

// Outcome constants.
const (
	OutcomeExecute  = "EXECUTE"
	OutcomeRefuse   = "REFUSE"
	OutcomeHardStop = "HARD_STOP"
)

// Gate status constants.
const (
	GatePass     = "PASS"
	GateFail     = "FAIL"
	GateWarn     = "WARN"
	GateHardStop = "HARD_STOP"
)

// RBAC — role → allowed action types.
// Extend this map as new action types are added to the ecosystem.
var rbacMap = map[string][]string{
	"admin": {
		"API_SCAN_INITIATE", "API_SCAN_DELETE",
		"INCIDENT_CREATE", "INCIDENT_CLOSE",
		"DATA_EXPORT", "CONFIG_CHANGE",
		"USER_CREATE", "USER_DELETE",
		"PLAYBOOK_EXECUTE", "IOC_INGEST",
	},
	"operator": {
		"API_SCAN_INITIATE",
		"INCIDENT_CREATE",
		"PLAYBOOK_EXECUTE", "IOC_INGEST",
		"DATA_EXPORT",
	},
	"analyst": {
		"API_SCAN_INITIATE",
		"INCIDENT_CREATE",
		"IOC_INGEST",
	},
	"viewer": {},
	"auditor": {
		"DATA_EXPORT",
	},
}

// roleGroupMap maps roles to their privilege group.
// Gate 3 NDS: operator and verifier must be in different groups.
var roleGroupMap = map[string]string{
	"admin":    "privileged",
	"operator": "privileged",
	"analyst":  "standard",
	"viewer":   "standard",
	"auditor":  "oversight",
}

// roleAllowed returns true if the given role can perform actionType.
func roleAllowed(role, actionType string) bool {
	allowed, ok := rbacMap[role]
	if !ok {
		return false
	}
	for _, a := range allowed {
		if a == actionType {
			return true
		}
	}
	return false
}

// roleGroup returns the privilege group for a role.
func roleGroup(role string) string {
	if g, ok := roleGroupMap[role]; ok {
		return g
	}
	return "unknown"
}
