package domain

import "time"

// ScanStatus represents the current state of a scan.
type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

// ScanRequest holds the parameters for initiating a new scan.
type ScanRequest struct {
	SpecPath    string
	SpecURL     string
	Target      string
	Modules     []string
	AuthToken   string
	AuthType    string
	AuthHeader  string
	Format      string
	Output      string
	FailOn      Severity
	Timeout     time.Duration
	Concurrency int
}

// ScanResult holds the outcome of a completed (or failed) scan.
type ScanResult struct {
	ID          string
	Status      ScanStatus
	Target      string
	SpecHash    string
	Findings    []Finding
	Summary     ScanSummary
	StartedAt   time.Time
	CompletedAt time.Time
	Error       string
}

// ScanSummary provides aggregate counts of findings by severity.
type ScanSummary struct {
	TotalFindings int
	Critical      int
	High          int
	Medium        int
	Low           int
	Info          int
}
