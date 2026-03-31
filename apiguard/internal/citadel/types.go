package citadel

import (
	"time"

	"github.com/google/uuid"
)

// Kerkese is the governance payload sent to CITADEL MARSHAL.
// Field names mirror the CITADEL server's db.Kerkese struct exactly.
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

// Decision is the outcome returned by CITADEL MARSHAL.
type Decision struct {
	Outcome     string       `json:"outcome"`
	ExecutionID uuid.UUID    `json:"execution_id"`
	WORMEntryID *uuid.UUID   `json:"worm_entry_id"`
	Gates       []GateResult `json:"gates"`
	Reasons     []string     `json:"reasons"`
	TsUTC       time.Time    `json:"ts_utc"`
	DryRun      bool         `json:"dry_run,omitempty"`
}

// GateResult is a single gate evaluation within a Decision.
type GateResult struct {
	Gate   int    `json:"gate"`
	Name   string `json:"name"`
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

// Outcome constants — mirror CITADEL server values.
const (
	OutcomeExecute  = "EXECUTE"
	OutcomeRefuse   = "REFUSE"
	OutcomeHardStop = "HARD_STOP"
)

// VerifyResult is the response from CITADEL's chain verification endpoint.
type VerifyResult struct {
	Valid           bool   `json:"valid"`
	EntriesVerified int    `json:"entries_verified"`
	BreakAt         string `json:"break_at,omitempty"`
	AnchorVerified  bool   `json:"anchor_verified"`
}

// NIS2Measure maps an OWASP API Security Top 10 ID (OWASP 2023 format,
// e.g. "API1:2023") to the corresponding NIS2 Article 21(2) measure code (a–j).
// Reference: OWASP API Top 10 2023 × NIS2 Article 21(2) mapping.
var NIS2Measure = map[string]string{
	"API1:2023":  "e", // Broken Object Level Authorization        → Access control measures
	"API2:2023":  "e", // Broken Authentication                    → Access control / authentication
	"API3:2023":  "e", // Broken Object Property Level Auth        → Access control measures
	"API4:2023":  "d", // Unrestricted Resource Consumption        → Business continuity / DoS resilience
	"API5:2023":  "e", // Broken Function Level Authorization      → Access control measures
	"API6:2023":  "g", // Unrestricted Access to Sensitive Flows   → Security in network/systems acquisition
	"API7:2023":  "h", // Server Side Request Forgery              → Incident handling / vulnerability policy
	"API8:2023":  "h", // Security Misconfiguration                → Incident handling / vulnerability policy
	"API9:2023":  "h", // Improper Inventory Management            → Vulnerability handling / asset management
	"API10:2023": "g", // Unsafe Consumption of APIs               → Supply chain / third-party security
}
