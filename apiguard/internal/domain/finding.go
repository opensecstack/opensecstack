package domain

// Severity represents the impact level of a finding.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// FindingStatus tracks the triage state of a finding.
type FindingStatus string

const (
	FindingStatusOpen          FindingStatus = "open"
	FindingStatusConfirmed     FindingStatus = "confirmed"
	FindingStatusFalsePositive FindingStatus = "false_positive"
	FindingStatusAccepted      FindingStatus = "accepted"
	FindingStatusFixed         FindingStatus = "fixed"
)

// Finding represents a single security issue discovered during a scan.
type Finding struct {
	ID             string
	ScanID         string
	OWASPId        string // e.g. API1:2023, API2:2023
	ModuleID       string // e.g. a1_bola, a2_auth
	Title          string
	Description    string
	Severity       Severity
	CVSSScore      float64
	CVSSVector     string
	EndpointPath   string
	EndpointMethod string
	Evidence       Evidence
	Remediation    string
	Status         FindingStatus
}

// Evidence captures the HTTP request/response pair that proves a finding.
type Evidence struct {
	Request  string                 // Raw HTTP request
	Response string                 // Raw HTTP response
	Detail   map[string]interface{} // Structured evidence data
}
