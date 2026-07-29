package incident

import (
	"context"
	"encoding/json"
	"errors"
)

// MARSHAL decision outcomes as defined by CITADEL's governance engine.
const (
	MarshalOutcomeExecute  = "EXECUTE"
	MarshalOutcomeRefuse   = "REFUSE"
	MarshalOutcomeHardStop = "HARD_STOP"
)

// ErrMarshalRefused is returned by ApproveAction when CITADEL's MARSHAL engine
// rejects the action (outcome = REFUSE). The HTTP layer maps this to 403.
var ErrMarshalRefused = errors.New("action refused by MARSHAL")

// ErrMarshalHardStop is returned by ApproveAction when CITADEL issues a
// HARD_STOP — an immediate halt signal that overrides any dual-control grant.
// The HTTP layer maps this to 403 and typically triggers a P1 auto-incident.
var ErrMarshalHardStop = errors.New("action blocked by MARSHAL HARD_STOP")

// MarshalClient evaluates a proposed incident action through CITADEL's
// five-gate governance engine. Implementations must be safe for concurrent
// use and must enforce a timeout so a slow CITADEL does not wedge IRFlow.
type MarshalClient interface {
	Evaluate(ctx context.Context, req MarshalRequest) (*MarshalResult, error)
}

// MarshalRequest is the IRFlow-level view of a Kerkese payload. The client
// implementation translates this into CITADEL's richer wire format.
//
// OperatorID/VerifierID are sinauth UUIDs derived from two SEPARATE
// authenticated sessions (see incident.Service.ApproveAction) — never
// client-supplied strings. ActorToken/VerifierToken are the raw sinauth
// bearer tokens proving those identities (citadel ADR-005); CITADEL verifies
// them directly against sinauth's JWKS and discards them.
type MarshalRequest struct {
	IncidentID    string
	ActionType    string
	Description   string
	OperatorID    string
	OperatorRole  string
	VerifierID    string
	VerifierRole  string
	ProjectID     string
	Evidence      json.RawMessage
	ActorToken    string
	VerifierToken string
}

// MarshalResult is the abbreviated decision returned by MARSHAL.
type MarshalResult struct {
	Outcome     string // one of MarshalOutcomeExecute / Refuse / HardStop
	WORMEntryID string // populated when CITADEL anchored the decision in WORM
	Reasons     []string
}

// WORMClient appends an event to CITADEL's write-once read-many audit chain.
// IRFlow uses this to record incident-lifecycle events (created, closed,
// IOC attached) that do not go through MARSHAL.
type WORMClient interface {
	Emit(ctx context.Context, event WORMEvent) (*WORMReceipt, error)
}

// WORMEvent is the minimum envelope required by CITADEL's /worm/emit.
type WORMEvent struct {
	Source    string
	EventType string
	ProjectID string
	Payload   json.RawMessage
}

// WORMReceipt carries the anchor metadata returned by CITADEL.
type WORMReceipt struct {
	WORMEntryID string
	ChainHash   string
	SequenceNum int64
}

// NIS2Client notifies NIS2 Compass that a regulatory-significant incident
// has been opened. Implementations should update the "Incident Handling"
// control on a designated assessment so the national competent authority
// has a tamper-evident record for Article 23 reporting.
type NIS2Client interface {
	NotifyIncident(ctx context.Context, inc *Incident) error
}
