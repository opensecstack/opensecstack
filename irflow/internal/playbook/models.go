package playbook

import (
	"errors"
	"time"
)

// Sentinel errors for the playbook domain.
var (
	ErrNotFound = errors.New("playbook not found")
	ErrInvalid  = errors.New("invalid playbook")
)

type StepType string

const (
	StepTypeAction      StepType = "action"      // Execute a CITADEL Kerkese
	StepTypeNotify      StepType = "notify"      // Send notification (email, webhook, Slack)
	StepTypeWait        StepType = "wait"        // Wait for condition or timeout
	StepTypeConditional StepType = "conditional" // Branch based on condition
	StepTypeEnrich      StepType = "enrich"      // Pull IOCs from ThreatFlow
	StepTypeScan        StepType = "scan"        // Trigger APIGuard re-scan
)

type PlaybookStatus string

const (
	PlaybookStatusDraft    PlaybookStatus = "draft"
	PlaybookStatusActive   PlaybookStatus = "active"
	PlaybookStatusArchived PlaybookStatus = "archived"
)

type ExecutionStatus string

const (
	ExecStatusPending   ExecutionStatus = "pending"
	ExecStatusRunning   ExecutionStatus = "running"
	ExecStatusCompleted ExecutionStatus = "completed"
	ExecStatusFailed    ExecutionStatus = "failed"
	ExecStatusCancelled ExecutionStatus = "cancelled"
)

// Playbook defines an automated incident response workflow.
type Playbook struct {
	ID          string         `json:"id" db:"id"`
	Name        string         `json:"name" db:"name"`
	Description string         `json:"description" db:"description"`
	Version     string         `json:"version" db:"version"`
	Status      PlaybookStatus `json:"status" db:"status"`
	Trigger     Trigger        `json:"trigger"`
	Steps       []Step         `json:"steps"`
	CreatedBy   string         `json:"created_by" db:"created_by"`
	CreatedAt   time.Time      `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" db:"updated_at"`
}

// Trigger defines when a playbook should be auto-executed.
type Trigger struct {
	EventType string `json:"event_type"`          // e.g. "apiguard.finding.critical"
	Severity  string `json:"severity,omitempty"`  // filter by incident severity
	Source    string `json:"source,omitempty"`    // filter by incident source
	Condition string `json:"condition,omitempty"` // CEL expression for advanced matching
}

// Step defines a single action in a playbook.
type Step struct {
	ID        string                 `json:"id"`
	Name      string                 `json:"name"`
	Type      StepType               `json:"type"`
	Config    map[string]interface{} `json:"config"`
	OnSuccess string                 `json:"on_success,omitempty"` // next step ID
	OnFailure string                 `json:"on_failure,omitempty"` // fallback step ID
	Timeout   string                 `json:"timeout,omitempty"`    // e.g. "5m", "1h"
}

// Execution tracks a running playbook instance.
type Execution struct {
	ID          string          `json:"id" db:"id"`
	PlaybookID  string          `json:"playbook_id" db:"playbook_id"`
	IncidentID  string          `json:"incident_id" db:"incident_id"`
	Status      ExecutionStatus `json:"status" db:"status"`
	CurrentStep string          `json:"current_step" db:"current_step"`
	StepResults []StepResult    `json:"step_results"`
	Error       string          `json:"error,omitempty" db:"error"`
	StartedAt   time.Time       `json:"started_at" db:"started_at"`
	CompletedAt *time.Time      `json:"completed_at" db:"completed_at"`
}

// StepResult captures the outcome of a single step execution.
type StepResult struct {
	StepID    string    `json:"step_id"`
	Status    string    `json:"status"` // "success", "failed", "skipped"
	Output    string    `json:"output"`
	Error     string    `json:"error,omitempty"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
}

// ---------- Request / Response DTOs ----------

// CreatePlaybookRequest is the payload for creating a new playbook.
type CreatePlaybookRequest struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Version     string         `json:"version"`
	Status      PlaybookStatus `json:"status"`
	Trigger     Trigger        `json:"trigger"`
	Steps       []Step         `json:"steps"`
	CreatedBy   string         `json:"created_by"`
}

// PatchPlaybookRequest is the payload for partially updating a playbook.
type PatchPlaybookRequest struct {
	Name        *string         `json:"name,omitempty"`
	Description *string         `json:"description,omitempty"`
	Version     *string         `json:"version,omitempty"`
	Status      *PlaybookStatus `json:"status,omitempty"`
	Trigger     *Trigger        `json:"trigger,omitempty"`
	Steps       *[]Step         `json:"steps,omitempty"`
}

// ExecutePlaybookRequest is the payload for running a playbook against an incident.
type ExecutePlaybookRequest struct {
	IncidentID string `json:"incident_id"`
}

// ListOptions controls pagination and filtering for playbook listing.
type ListOptions struct {
	Page    int
	PerPage int
	Status  string
}
