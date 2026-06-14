package webhook

import (
	"encoding/json"
	"time"
)

// APIGuardEvent is the payload delivered to POST /api/v1/webhooks/apiguard.
// A scan typically produces multiple findings; APIGuard sends one webhook per
// finding it wants IRFlow to act on.
type APIGuardEvent struct {
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"` // "finding" | "scan_result"
	ScanID     string          `json:"scan_id"`
	Target     string          `json:"target"` // e.g. https://api.example.com/users
	Finding    APIGuardFinding `json:"finding"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// APIGuardFinding matches APIGuard's SARIF-derived finding model. Severity
// values are the APIGuard canonical strings: critical, high, medium, low,
// informational.
type APIGuardFinding struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	RuleID      string  `json:"rule_id"`
	CVSS        float64 `json:"cvss,omitempty"`
}

// CITADELEvent is the payload delivered to POST /api/v1/webhooks/citadel.
// HARD_STOP events must be acted on immediately (P1 incident); other event
// types are logged but do not auto-create an incident.
type CITADELEvent struct {
	EventID     string    `json:"event_id"`
	EventType   string    `json:"event_type"` // "hard_stop" | "marshal_denied" | "worm_tamper"
	Trigger     string    `json:"trigger"`
	ProjectID   string    `json:"project_id"`
	ExecutionID string    `json:"execution_id"`
	Description string    `json:"description"`
	OccurredAt  time.Time `json:"occurred_at"`
}

// ThreatFlowEvent is the payload delivered to POST /api/v1/webhooks/threatflow.
// When IncidentID is set, the IOCs are attached directly to that incident.
// When empty, the event is accepted (202) and logged for later correlation —
// a future automated matching engine can pair bundles with open incidents by
// source_ref or IOC value overlap.
type ThreatFlowEvent struct {
	EventID    string          `json:"event_id"`
	EventType  string          `json:"event_type"` // "ioc_bundle"
	IncidentID string          `json:"incident_id,omitempty"`
	IOCs       []ThreatFlowIOC `json:"iocs"`
	OccurredAt time.Time       `json:"occurred_at"`
}

// ThreatFlowIOC mirrors the incident.IOCEnrichment fields but exists as a
// separate DTO so webhook callers are insulated from internal type changes.
type ThreatFlowIOC struct {
	Type       string          `json:"type"` // ip | domain | hash | url
	Value      string          `json:"value"`
	Confidence float64         `json:"confidence"`
	Source     string          `json:"source"`
	STIXBundle json.RawMessage `json:"stix_bundle,omitempty"`
}
