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

// apiError is the JSON error body returned by APIGuard and NIS2 Compass on
// 4xx/5xx responses.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// ----------------------------------------------------------------------------
// NIS2 Compass types
// ----------------------------------------------------------------------------

// Organisation represents a registered NIS2-subject organisation.
type Organisation struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Industry           string    `json:"industry"`
	Country            string    `json:"country"`
	Size               string    `json:"size"`
	EntityType         string    `json:"entity_type"`
	RegistrationNumber string    `json:"registration_number,omitempty"`
	ContactEmail       string    `json:"contact_email,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// AssessmentStats is the aggregated control summary included in single-record
// GET and PATCH responses for an Assessment (when the server sets include_stats=true).
type AssessmentStats struct {
	Total        int            `json:"total"`
	ByStatus     map[string]int `json:"by_status"`
	AvgRiskScore *float64       `json:"avg_risk_score"`
}

// Assessment represents a NIS2 compliance assessment for an organisation.
// The server may include a summary block (aggregated control counts and overall
// risk score) on single-record GET and PATCH responses.
type Assessment struct {
	ID               string           `json:"id"`
	OrgID            string           `json:"org_id"`
	Title            string           `json:"title"`
	Status           string           `json:"status"`
	FrameworkVersion string           `json:"framework_version"`
	Scope            string           `json:"scope,omitempty"`
	Assessor         string           `json:"assessor,omitempty"`
	DueDate          string           `json:"due_date,omitempty"`
	CompletedAt      *time.Time       `json:"completed_at,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	Stats            *AssessmentStats `json:"stats,omitempty"`
}

// Control represents one of the 10 NIS2 Article 21(2) measure entries within
// an assessment (measures a through j).
type Control struct {
	ID                 string                 `json:"id"`
	AssessmentID       string                 `json:"assessment_id"`
	MeasureRef         string                 `json:"measure_ref"`
	ArticleRef         string                 `json:"article_ref"`
	Title              string                 `json:"title"`
	Description        string                 `json:"description,omitempty"`
	NistCategory       string                 `json:"nist_category"`
	Status             string                 `json:"status"`
	Evidence           map[string]interface{} `json:"evidence,omitempty"`
	RiskScore          *float64               `json:"risk_score,omitempty"`
	Notes              string                 `json:"notes,omitempty"`
	GapDescription     string                 `json:"gap_description,omitempty"`
	RemediationPlan    string                 `json:"remediation_plan,omitempty"`
	RemediationDue     string                 `json:"remediation_due,omitempty"`
	RemediationOwner   string                 `json:"remediation_owner,omitempty"`
	RemediationStatus  string                 `json:"remediation_status,omitempty"`
	ExternalTicketURL  string                 `json:"external_ticket_url,omitempty"`
	RemediationNotes   string                 `json:"remediation_notes,omitempty"`
	AssessedBy         string                 `json:"assessed_by,omitempty"`
	AssessedAt         *time.Time             `json:"assessed_at,omitempty"`
	CreatedAt          time.Time              `json:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at"`
}

// CreateOrganisationRequest is the body sent to POST /api/v1/organisations.
type CreateOrganisationRequest struct {
	Name               string `json:"name"`
	Industry           string `json:"industry"`
	Country            string `json:"country"`
	Size               string `json:"size,omitempty"`
	EntityType         string `json:"entity_type,omitempty"`
	RegistrationNumber string `json:"registration_number,omitempty"`
	ContactEmail       string `json:"contact_email,omitempty"`
}

// CreateAssessmentRequest is the body sent to
// POST /api/v1/organisations/{org_id}/assessments.
type CreateAssessmentRequest struct {
	Title            string `json:"title"`
	FrameworkVersion string `json:"framework_version,omitempty"`
	Scope            string `json:"scope,omitempty"`
	Assessor         string `json:"assessor,omitempty"`
	DueDate          string `json:"due_date,omitempty"`
}

// PatchAssessmentRequest is the body sent to PATCH /api/v1/assessments/{id}.
// All fields are optional; only non-zero fields are sent.
type PatchAssessmentRequest struct {
	Status   string `json:"status,omitempty"`
	Title    string `json:"title,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Assessor string `json:"assessor,omitempty"`
	DueDate  string `json:"due_date,omitempty"`
}

// PatchControlRequest is the body sent to
// PATCH /api/v1/assessments/{id}/controls/{measure_ref}.
// All fields are optional; only non-zero fields are sent.
type PatchControlRequest struct {
	Status            string                 `json:"status,omitempty"`
	Notes             string                 `json:"notes,omitempty"`
	GapDescription    string                 `json:"gap_description,omitempty"`
	RemediationPlan   string                 `json:"remediation_plan,omitempty"`
	RemediationDue    string                 `json:"remediation_due,omitempty"`
	RemediationOwner  string                 `json:"remediation_owner,omitempty"`
	RemediationStatus string                 `json:"remediation_status,omitempty"`
	ExternalTicketURL string                 `json:"external_ticket_url,omitempty"`
	RemediationNotes  string                 `json:"remediation_notes,omitempty"`
	Evidence          map[string]interface{} `json:"evidence,omitempty"`
	RiskScore         *float64               `json:"risk_score,omitempty"`
}

// PatchOrganisationRequest is the body sent to PATCH /api/v1/organisations/{id}.
// All fields are optional; only non-zero fields are sent.
type PatchOrganisationRequest struct {
	Name               string `json:"name,omitempty"`
	Industry           string `json:"industry,omitempty"`
	Country            string `json:"country,omitempty"`
	Size               string `json:"size,omitempty"`
	EntityType         string `json:"entity_type,omitempty"`
	RegistrationNumber string `json:"registration_number,omitempty"`
	ContactEmail       string `json:"contact_email,omitempty"`
}

// PatchFindingRequest is the body sent to PATCH /api/v1/findings/{id}.
// Status is required; Note is optional triage commentary.
type PatchFindingRequest struct {
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// NIS2AuditEntry is a single entry in the NIS2 Compass immutable audit log.
// The chain_hash and prev_hash fields provide a WORM integrity chain.
type NIS2AuditEntry struct {
	ID           string    `json:"id"`
	Action       string    `json:"action"`
	Actor        string    `json:"actor"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id,omitempty"`
	RiskClass    string    `json:"risk_class"`
	ChainHash    string    `json:"chain_hash"`
	PrevHash     string    `json:"prev_hash,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}
