// Package opensecstack provides Go client types and HTTP clients for the
// opensecstack platform APIs (APIGuard, NIS2 Compass).
package opensecstack

import "time"

// ScanStatus enumerates the lifecycle states of an APIGuard scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// FindingSeverity enumerates CVSS-aligned severity bands.
type FindingSeverity string

const (
	FindingSeverityCritical FindingSeverity = "critical"
	FindingSeverityHigh     FindingSeverity = "high"
	FindingSeverityMedium   FindingSeverity = "medium"
	FindingSeverityLow      FindingSeverity = "low"
	FindingSeverityInfo     FindingSeverity = "info"
)

// FindingStatus enumerates the triage states of a finding.
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusConfirmed     FindingStatus = "confirmed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAccepted      FindingStatus = "accepted"
	FindingStatusFixed         FindingStatus = "fixed"
)

// Scan is the JSON representation of an APIGuard scan record.
type Scan struct {
	ID            string     `json:"id"`
	SpecURL       string     `json:"spec_url"`
	SpecHash      string     `json:"spec_hash"`
	TargetURL     string     `json:"target_url"`
	Status        ScanStatus `json:"status"`
	Modules       []string   `json:"modules"`
	TotalFindings int        `json:"total_findings"`
	CriticalCount int        `json:"critical_count"`
	HighCount     int        `json:"high_count"`
	MediumCount   int        `json:"medium_count"`
	LowCount      int        `json:"low_count"`
	InfoCount     int        `json:"info_count"`
	ErrorMessage  string     `json:"error_message"`
	StartedAt     *time.Time `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

// Finding is the JSON representation of a single APIGuard finding.
type Finding struct {
	ID             string          `json:"id"`
	ScanID         string          `json:"scan_id"`
	OwaspID        string          `json:"owasp_id"`
	ModuleID       string          `json:"module_id"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Severity       FindingSeverity `json:"severity"`
	CVSSScore      float64         `json:"cvss_score"`
	CVSSVector     string          `json:"cvss_vector"`
	EndpointPath   string          `json:"endpoint_path"`
	EndpointMethod string          `json:"endpoint_method"`
	Remediation    string          `json:"remediation"`
	Status         FindingStatus   `json:"status"`
	TriagedBy      string          `json:"triaged_by"`
	TriageNote     string          `json:"triage_note"`
	TriagedAt      *time.Time      `json:"triaged_at"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// AuditEntry is the JSON representation of a single APIGuard audit log entry.
// The chain_hash and prev_hash fields are used by CITADEL for WORM log validation.
type AuditEntry struct {
	ID           string          `json:"id"`
	ActorID      string          `json:"actor_id"`
	ActorType    string          `json:"actor_type"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	IPAddress    string          `json:"ip_address"`
	UserAgent    string          `json:"user_agent"`
	Metadata     interface{}     `json:"metadata"`
	PrevHash     *string         `json:"prev_hash"`
	ChainHash    string          `json:"chain_hash"`
	CreatedAt    time.Time       `json:"created_at"`
}

// findingsResponse is the paginated envelope returned by
// GET /api/v1/scans/{id}/findings and GET /api/v1/findings.
type findingsResponse struct {
	Data    []Finding `json:"data"`
	Total   int       `json:"total"`
	Page    int       `json:"page"`
	PerPage int       `json:"per_page"`
}

// createScanRequest is the JSON body sent to POST /api/v1/scans.
type createScanRequest struct {
	SpecURL    string   `json:"spec_url,omitempty"`
	SpecPath   string   `json:"spec_path,omitempty"`
	Target     string   `json:"target"`
	Modules    []string `json:"modules,omitempty"`
	AuthType   string   `json:"auth_type,omitempty"`
	AuthToken  string   `json:"auth_token,omitempty"`
	AuthHeader string   `json:"auth_header,omitempty"`
}

// apiError is the JSON error body returned by APIGuard on 4xx/5xx responses.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}
