package db

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ScanStatus represents the status of a scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
	// ScanStatusPendingApproval means the scan has been requested but is
	// waiting on a genuine, distinct second authenticated user to approve it
	// (see ScanApproval / POST /api/v1/scans/{id}/approve) before it runs.
	// Only reachable when config Citadel.RequireApproval is true.
	ScanStatusPendingApproval ScanStatus = "pending_approval"
)

// FindingSeverity represents the severity level of a finding.
type FindingSeverity string

const (
	FindingSeverityCritical FindingSeverity = "critical"
	FindingSeverityHigh     FindingSeverity = "high"
	FindingSeverityMedium   FindingSeverity = "medium"
	FindingSeverityLow      FindingSeverity = "low"
	FindingSeverityInfo     FindingSeverity = "info"
)

// FindingStatus represents the triage status of a finding.
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusConfirmed     FindingStatus = "confirmed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAccepted      FindingStatus = "accepted"
	FindingStatusFixed         FindingStatus = "fixed"
)

// Scan represents a row in the scans table.
type Scan struct {
	ID          uuid.UUID       `json:"id"`
	SpecURL     sql.NullString  `json:"spec_url"`
	SpecHash    sql.NullString  `json:"spec_hash"`
	TargetURL   string          `json:"target_url"`
	Status      ScanStatus      `json:"status"`
	Modules     []string        `json:"modules"`
	StartedAt   sql.NullTime    `json:"started_at"`
	CompletedAt sql.NullTime    `json:"completed_at"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	ConfigJSON  json.RawMessage `json:"config_json"`

	// Summary counts
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	InfoCount     int `json:"info_count"`

	AuthType     sql.NullString `json:"auth_type"`
	ErrorMessage sql.NullString `json:"error_message"`
}

// ScanSummary holds the aggregated finding counts for a completed scan.
type ScanSummary struct {
	TotalFindings int `json:"total_findings"`
	CriticalCount int `json:"critical_count"`
	HighCount     int `json:"high_count"`
	MediumCount   int `json:"medium_count"`
	LowCount      int `json:"low_count"`
	InfoCount     int `json:"info_count"`
}

// Finding represents a row in the findings table.
type Finding struct {
	ID       uuid.UUID `json:"id"`
	ScanID   uuid.UUID `json:"scan_id"`
	OwaspID  string    `json:"owasp_id"`
	ModuleID string    `json:"module_id"`

	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    FindingSeverity `json:"severity"`

	CVSSScore  float64        `json:"cvss_score"`
	CVSSVector sql.NullString `json:"cvss_vector"`

	EndpointPath   string `json:"endpoint_path"`
	EndpointMethod string `json:"endpoint_method"`

	EvidenceRequest  sql.NullString  `json:"evidence_request"`
	EvidenceResponse sql.NullString  `json:"evidence_response"`
	EvidenceJSON     json.RawMessage `json:"evidence_json"`

	Remediation sql.NullString `json:"remediation"`

	Status     FindingStatus  `json:"status"`
	TriagedBy  sql.NullString `json:"triaged_by"`
	TriagedAt  sql.NullTime   `json:"triaged_at"`
	TriageNote sql.NullString `json:"triage_note"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FindingFilters holds optional filters for querying findings.
type FindingFilters struct {
	ScanID   *uuid.UUID
	Severity *FindingSeverity
	Status   *FindingStatus
	OwaspID  *string
	ModuleID *string
}

// AuditAction enumerates the event types recorded in the audit log.
type AuditAction string

const (
	AuditActionScanCreated          AuditAction = "scan_created"
	AuditActionScanStarted          AuditAction = "scan_started"
	AuditActionScanCompleted        AuditAction = "scan_completed"
	AuditActionScanFailed           AuditAction = "scan_failed"
	AuditActionScanDeleted          AuditAction = "scan_deleted"
	AuditActionFindingTriaged       AuditAction = "finding_triaged"
	AuditActionFindingStatusChanged AuditAction = "finding_status_changed"
	AuditActionSpecUploaded         AuditAction = "spec_uploaded"
	AuditActionSpecParsed           AuditAction = "spec_parsed"
	AuditActionReportGenerated      AuditAction = "report_generated"
	AuditActionReportExported       AuditAction = "report_exported"
	AuditActionAPIKeyCreated        AuditAction = "api_key_created"
	AuditActionAPIKeyRevoked        AuditAction = "api_key_revoked"
	AuditActionAPIKeyUsed           AuditAction = "api_key_used"
	AuditActionUserLogin            AuditAction = "user_login"
	AuditActionUserLogout           AuditAction = "user_logout"
	AuditActionJWTSecretRotated     AuditAction = "jwt_secret_rotated"
	AuditActionScanApprovalRequested AuditAction = "scan_approval_requested"
	AuditActionScanApprovalApproved  AuditAction = "scan_approval_approved"
	AuditActionScanApprovalRejected  AuditAction = "scan_approval_rejected"
)

// AuditLog represents a row in the audit_log table.
type AuditLog struct {
	ID           uuid.UUID       `json:"id"`
	ActorID      string          `json:"actor_id"`
	ActorType    string          `json:"actor_type"`
	Action       AuditAction     `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *uuid.UUID      `json:"resource_id"`
	IPAddress    sql.NullString  `json:"ip_address"`
	UserAgent    sql.NullString  `json:"user_agent"`
	BeforeState  json.RawMessage `json:"before_state"`
	AfterState   json.RawMessage `json:"after_state"`
	Metadata     json.RawMessage `json:"metadata"`
	PrevHash     *string         `json:"prev_hash"`
	ChainHash    string          `json:"chain_hash"`
	CreatedAt    time.Time       `json:"created_at"`
}

// APISpec represents a row in the api_specs table.
type APISpec struct {
	ID            uuid.UUID       `json:"id"`
	SpecHash      string          `json:"spec_hash"`
	SpecURL       sql.NullString  `json:"spec_url"`
	SpecFormat    string          `json:"spec_format"`
	Title         sql.NullString  `json:"title"`
	Version       sql.NullString  `json:"version"`
	BaseURL       sql.NullString  `json:"base_url"`
	EndpointCount int             `json:"endpoint_count"`
	AuthSchemes   json.RawMessage `json:"auth_schemes"`
	RawSpec       sql.NullString  `json:"raw_spec"`
	ParsedIR      json.RawMessage `json:"parsed_ir"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// APIInventory represents a row in the api_inventory table.
type APIInventory struct {
	ID            uuid.UUID      `json:"id"`
	TargetURL     string         `json:"target_url"`
	SpecHash      sql.NullString `json:"spec_hash"`
	APIVersion    sql.NullString `json:"api_version"`
	FirstSeenAt   time.Time      `json:"first_seen_at"`
	LastScannedAt sql.NullTime   `json:"last_scanned_at"`
	ScanCount     int            `json:"scan_count"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
}
