// Package incident defines the core domain types for IRFlow incident management.
package incident

import (
	"encoding/json"
	"time"
)

// Severity represents the incident priority level.
type Severity string

const (
	SeverityP1 Severity = "P1" // Critical — 15 min response / 4 h resolution SLA
	SeverityP2 Severity = "P2" // High     — 1 h response   / 24 h resolution SLA
	SeverityP3 Severity = "P3" // Medium   — 4 h response   / 72 h resolution SLA
	SeverityP4 Severity = "P4" // Low      — 24 h response  / sprint resolution SLA
)

// Status represents the lifecycle state of an incident.
type Status string

const (
	StatusOpen          Status = "open"
	StatusInvestigating Status = "investigating"
	StatusContained     Status = "contained"
	StatusEradicating   Status = "eradicating"
	StatusRecovering    Status = "recovering"
	StatusClosed        Status = "closed"
)

// Source identifies the origin system that raised the incident.
type Source string

const (
	SourceAPIGuard   Source = "apiguard"
	SourceCitadel    Source = "citadel"
	SourceThreatFlow Source = "threatflow"
	SourceCyberPath  Source = "cyberpath"
	SourceManual     Source = "manual"
)

// Incident is the primary domain entity for an incident record.
type Incident struct {
	ID                 string     `json:"id"`
	Title              string     `json:"title"`
	Description        string     `json:"description"`
	Severity           Severity   `json:"severity"`
	Status             Status     `json:"status"`
	Source             Source     `json:"source"`
	SourceRef          string     `json:"source_ref"`
	ProjectID          string     `json:"project_id"`
	CommanderID        string     `json:"commander_id"`
	LeadID             string     `json:"lead_id"`
	RootCause          string     `json:"root_cause"`
	CorrectiveAction   string     `json:"corrective_action"`
	WORMEntryID        string     `json:"worm_entry_id"`
	NIS2NotifyRequired bool       `json:"nis2_notify_required"`
	NIS2NotifiedAt     *time.Time `json:"nis2_notified_at,omitempty"`
	ContainedAt        *time.Time `json:"contained_at,omitempty"`
	ClosedAt           *time.Time `json:"closed_at,omitempty"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}

// IncidentAction records a governed action taken during incident response.
type IncidentAction struct {
	ID              string          `json:"id"`
	IncidentID      string          `json:"incident_id"`
	ActionType      string          `json:"action_type"` // escalate, contain, eradicate, recover, close
	OperatorID      string          `json:"operator_id"`
	VerifierID      string          `json:"verifier_id"`
	Description     string          `json:"description"`
	Evidence        json.RawMessage `json:"evidence,omitempty"`
	MarshalDecision string          `json:"marshal_decision"`
	WORMEntryID     string          `json:"worm_entry_id"`
	CreatedAt       time.Time       `json:"created_at"`
}

// IOCEnrichment holds an indicator of compromise associated with an incident.
type IOCEnrichment struct {
	ID         string          `json:"id"`
	IncidentID string          `json:"incident_id"`
	IOCType    string          `json:"ioc_type"` // ip, domain, hash, url
	IOCValue   string          `json:"ioc_value"`
	Confidence float64         `json:"confidence"`
	Source     string          `json:"source"`
	STIXBundle json.RawMessage `json:"stix_bundle,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// TimelineEntry is a chronological event in the incident timeline.
type TimelineEntry struct {
	ID         string          `json:"id"`
	IncidentID string          `json:"incident_id"`
	EntryType  string          `json:"entry_type"`
	ActorID    string          `json:"actor_id"`
	Summary    string          `json:"summary"`
	Details    json.RawMessage `json:"details,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// Stats is the aggregated incident dashboard summary returned by GET /stats.
type Stats struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"`
	ByStatus   map[string]int `json:"by_status"`
	BySource   map[string]int `json:"by_source"`
}

// ---------- Request / Response DTOs ----------

// CreateIncidentRequest is the payload for creating a new incident.
type CreateIncidentRequest struct {
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	Source      Source   `json:"source"`
	SourceRef   string   `json:"source_ref"`
	ProjectID   string   `json:"project_id"`
	CommanderID string   `json:"commander_id"`
	LeadID      string   `json:"lead_id"`
}

// PatchIncidentRequest is the payload for partially updating an incident.
type PatchIncidentRequest struct {
	Title            *string   `json:"title,omitempty"`
	Description      *string   `json:"description,omitempty"`
	Severity         *Severity `json:"severity,omitempty"`
	Status           *Status   `json:"status,omitempty"`
	CommanderID      *string   `json:"commander_id,omitempty"`
	LeadID           *string   `json:"lead_id,omitempty"`
	RootCause        *string   `json:"root_cause,omitempty"`
	CorrectiveAction *string   `json:"corrective_action,omitempty"`
}

// ---------- Two-person-rule (SoD) pending actions ----------

// PendingActionStatus is the lifecycle state of a proposed governed action
// awaiting a second, distinct authenticated Verifier's decision.
type PendingActionStatus string

const (
	// PendingActionStatusPending awaits a Verifier's approve/reject decision.
	PendingActionStatusPending PendingActionStatus = "pending"
	// PendingActionStatusApproved was approved by a Verifier and (if MARSHAL
	// is configured) received an EXECUTE outcome; a real IncidentAction now
	// exists (see PendingAction.ActionID).
	PendingActionStatusApproved PendingActionStatus = "approved"
	// PendingActionStatusRejected was explicitly rejected by a Verifier
	// without ever being submitted to CITADEL.
	PendingActionStatusRejected PendingActionStatus = "rejected"
	// PendingActionStatusRefused was submitted to CITADEL MARSHAL on
	// approval but received a REFUSE outcome.
	PendingActionStatusRefused PendingActionStatus = "refused"
	// PendingActionStatusBlocked was submitted to CITADEL MARSHAL on
	// approval but received a HARD_STOP outcome.
	PendingActionStatusBlocked PendingActionStatus = "blocked"
)

// PendingAction is a governed incident-response action proposed by an
// authenticated Operator and awaiting approval from a SECOND, distinct
// authenticated Verifier before it is evaluated by CITADEL MARSHAL and
// persisted as a real IncidentAction.
//
// This is IRFlow's two-person-rule (Separation of Duties) workflow: the
// Operator's identity (OperatorUserID/OperatorRole) is captured at proposal
// time directly from their own authenticated session (see
// auth.ClaimsFromContext), never from client-supplied request fields. The
// Verifier's identity (VerifierUserID/VerifierRole) is captured the same way,
// but from a SEPARATE HTTP request the Verifier must make with their own
// bearer token — a single caller can never supply both identities.
type PendingAction struct {
	ID              string              `json:"id"`
	IncidentID      string              `json:"incident_id"`
	ActionType      string              `json:"action_type"`
	Description     string              `json:"description"`
	Evidence        json.RawMessage     `json:"evidence,omitempty"`
	OperatorUserID  string              `json:"operator_user_id"`
	OperatorRole    string              `json:"operator_role"`
	VerifierUserID  string              `json:"verifier_user_id,omitempty"`
	VerifierRole    string              `json:"verifier_role,omitempty"`
	Status          PendingActionStatus `json:"status"`
	MarshalDecision string              `json:"marshal_decision,omitempty"`
	WORMEntryID     string              `json:"worm_entry_id,omitempty"`
	ActionID        string              `json:"action_id,omitempty"`
	Reasons         []string            `json:"reasons,omitempty"`
	CreatedAt       time.Time           `json:"created_at"`
	DecidedAt       *time.Time          `json:"decided_at,omitempty"`
}

// ProposeActionRequest is the payload an authenticated Operator submits to
// propose a governed action. Deliberately carries no operator/verifier
// identity fields — the Operator is the authenticated caller, and the
// Verifier does not exist yet (they are chosen implicitly by whichever
// distinct authenticated user later calls the approve endpoint).
type ProposeActionRequest struct {
	ActionType  string          `json:"action_type"`
	Description string          `json:"description"`
	Evidence    json.RawMessage `json:"evidence,omitempty"`
}

// ApproveActionRequest is the payload an authenticated Verifier submits to
// approve a pending action. Reserved for future fields (e.g. a free-text
// approval note) — empty today because the Verifier's identity comes from
// their own authenticated bearer token (see auth.ClaimsFromContext /
// auth.BearerToken), never from this request body.
type ApproveActionRequest struct {
	Note string `json:"note,omitempty"`
}

// ---------- NIS2 Notification Thresholds ----------

// NIS2Thresholds maps severity to the initial notification deadline (Art. 23).
// A zero duration means no mandatory notification.
var NIS2Thresholds = map[Severity]time.Duration{
	SeverityP1: 24 * time.Hour, // significant incident — 24 h initial notification
	SeverityP2: 24 * time.Hour, // significant incident — 24 h initial notification
	SeverityP3: 72 * time.Hour, // notable incident    — 72 h initial notification
	SeverityP4: 0,              // low — no mandatory notification
}

// ---------- Status Transition Rules ----------

// ValidTransitions defines the allowed status transitions.
var ValidTransitions = map[Status][]Status{
	StatusOpen:          {StatusInvestigating, StatusClosed},
	StatusInvestigating: {StatusContained, StatusClosed},
	StatusContained:     {StatusEradicating, StatusClosed},
	StatusEradicating:   {StatusRecovering, StatusClosed},
	StatusRecovering:    {StatusClosed},
	StatusClosed:        {}, // terminal state
}
