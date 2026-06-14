package citadel

import (
	"time"

	"github.com/google/uuid"
)

// EventEnvelope fields shared by every openscrub.* event.
type EventEnvelope struct {
	Type    string    `json:"type"`
	Version string    `json:"version"`
	ID      string    `json:"id"`
	TS      time.Time `json:"ts"`
	Source  string    `json:"source"`
	Node    string    `json:"node"`
}

// RuleSummary is the embedded rule view used by both event types.
type RuleSummary struct {
	ID         string `json:"id"`
	CIDR       string `json:"cidr"`
	Type       string `json:"type"`
	PPS        *int   `json:"pps,omitempty"`
	Port       *int   `json:"port,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Source     string `json:"source"`
}

// MitigationEvent — emitted once per (rule, src_ip, window) tuple.
type MitigationEvent struct {
	EventEnvelope
	Rule          RuleSummary `json:"rule"`
	SrcIP         string      `json:"src_ip,omitempty"`
	Action        string      `json:"action"`
	Packets       int64       `json:"packets"`
	Bytes         int64       `json:"bytes"`
	WindowSeconds int         `json:"window_seconds"`
}

// RuleChangeOperation values per docs/citadel-integration.md.
const (
	OpInsert        = "insert"
	OpWithdraw      = "withdraw"
	OpExpire        = "expire"
	OpIOCPullApply  = "ioc_pull_apply"
)

// RuleChangeEvent — emitted on every rule lifecycle transition.
type RuleChangeEvent struct {
	EventEnvelope
	Operation string      `json:"operation"`
	Rule      RuleSummary `json:"rule"`
	Principal string      `json:"principal,omitempty"`
	Reason    string      `json:"reason,omitempty"`
}

// NewEnvelope returns a populated EventEnvelope.
func NewEnvelope(eventType, node string) EventEnvelope {
	return EventEnvelope{
		Type:    eventType,
		Version: "1",
		ID:      uuid.NewString(),
		TS:      time.Now().UTC(),
		Source:  "openscrub",
		Node:    node,
	}
}
